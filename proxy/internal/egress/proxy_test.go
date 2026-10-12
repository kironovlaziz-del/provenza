// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	proxyKey = "pvz_proxy_test"
	agentKey = "pvz_agent_test"
	secret   = "Bearer sk_live_server"
)

func hexsum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// fakeProvenza: the server side, as far as the proxy can see it.
type fakeProvenza struct {
	mu        sync.Mutex
	deny      string                    // reason to deny every check, if set
	checked   map[string]map[string]any // check id -> the descriptor checked
	redeemed  []map[string]any
	completed []map[string]any
	checks    int
	routes    []Route
}

func (f *fakeProvenza) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	byProxy := r.Header.Get("X-Proxy-Key") == proxyKey
	byAgent := r.Header.Get("X-Agent-Key") == agentKey
	switch r.URL.Path {
	case "/api/v1/egress-proxy/config":
		if !byProxy {
			reply(401, map[string]any{"detail": "egress.bad_proxy_key"})
			return
		}
		reply(200, map[string]any{"routes": f.routes, "refresh_seconds": 60})
	case "/api/v1/agent-identity/me":
		if !byAgent {
			reply(401, map[string]any{"detail": "bad key"})
			return
		}
		reply(200, map[string]any{"agent_id": 7})
	case "/api/v1/agents/actions/check":
		if !byAgent || body["agent_id"] != float64(7) || body["action_type"] != "proxy" {
			reply(401, map[string]any{"detail": "bad check"})
			return
		}
		f.checks++
		id := "chk_" + strings.Repeat("a", 12) + string(rune('a'+f.checks))
		f.checked[id] = body["input"].(map[string]any)
		if body["tool_name"] != "proxy."+f.checked[id]["route"].(string) {
			reply(400, map[string]any{"detail": "tool"})
			return
		}
		decision := "allowed"
		if f.deny != "" {
			decision = "denied"
		}
		reply(200, map[string]any{"decision": decision, "reason": f.deny, "check_id": id})
	case "/api/v1/egress-proxy/redeem":
		if !byProxy {
			reply(401, nil)
			return
		}
		f.redeemed = append(f.redeemed, body)
		id := body["check_id"].(string)
		want, ok := f.checked[id]
		if !ok {
			reply(404, map[string]any{"detail": "egress.unknown_check"})
			return
		}
		delete(body, "check_id")
		a, _ := json.Marshal(want)
		b, _ := json.Marshal(body)
		if string(a) != string(b) { // the real server compares content hashes
			reply(400, map[string]any{"detail": "egress.request_mismatch"})
			return
		}
		if f.deny != "" {
			reply(200, map[string]any{"allowed": false, "decision": "denied", "reason": f.deny, "action_id": 1})
			return
		}
		reply(200, map[string]any{"allowed": true, "redemption_id": 1})
	case "/api/v1/egress-proxy/complete":
		f.completed = append(f.completed, body)
		reply(200, map[string]any{"action_id": 2})
	default:
		reply(404, nil)
	}
}

type upstream struct {
	mu   sync.Mutex
	got  []*http.Request
	body []string
	srv  *httptest.Server
}

func newUpstream(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *upstream {
	u := &upstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.got, u.body = append(u.got, r), append(u.body, string(raw))
		u.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func setup(t *testing.T, up *upstream, mutate func(*Route, *Config), extra ...Route) (*fakeProvenza, *httptest.Server, *httptest.Server) {
	t.Helper()
	route := Route{Slug: "stripe", UpstreamURL: up.srv.URL, Methods: []string{"GET", "POST"},
		PathPrefixes: []string{"/v1/charges"}, CredentialSource: "server", AuthHeader: "Authorization",
		Secret: secret, MaxBodyBytes: 100}
	fake := &fakeProvenza{checked: map[string]map[string]any{}}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	cfg := &Config{ServerURL: srv.URL}
	if mutate != nil {
		mutate(&route, cfg)
	}
	fake.routes = append([]Route{route}, extra...)
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	p := New(cfg, proxyKey, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := p.Start(ctx); err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(p)
	t.Cleanup(front.Close)
	return fake, srv, front
}

func send(t *testing.T, front *httptest.Server, method, path, body string, headers map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, front.URL+path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func ok(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Set-Cookie", "upstream=1")
	w.WriteHeader(201)
	_, _ = io.WriteString(w, `{"id":"ch_1"}`)
}

func TestMediatedRequestIsCheckedForwardedAndRecorded(t *testing.T) {
	up := newUpstream(t, ok)
	fake, _, front := setup(t, up, nil)
	body := `{"amount":1000}`
	resp := send(t, front, "POST", "/stripe/v1/charges?expand=x", body, map[string]string{
		"X-Agent-Key": agentKey, "Authorization": "Bearer agent-own", "Cookie": "s=1",
		"X-Provenza-Anything": "1", "Content-Type": "application/json", "Idempotency-Key": "k1"})
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 201 || string(got) != `{"id":"ch_1"}` {
		t.Fatalf("got %d %s", resp.StatusCode, got)
	}
	r := up.got[0]
	if r.URL.Path != "/v1/charges" || r.URL.RawQuery != "expand=x" || up.body[0] != body {
		t.Fatalf("upstream saw %s?%s %q", r.URL.Path, r.URL.RawQuery, up.body[0])
	}
	if r.Header.Get("Authorization") != secret || r.Header.Get("Cookie") != "" || r.Header.Get("X-Agent-Key") != "" ||
		r.Header.Get("X-Provenza-Anything") != "" || r.Header.Get("Idempotency-Key") != "k1" {
		t.Fatalf("upstream headers: %v", r.Header)
	}
	want := map[string]any{"route": "stripe", "method": "POST", "path": "/v1/charges",
		"query_sha256": hexsum([]byte("expand=x")), "body_sha256": hexsum([]byte(body)), "body_bytes": float64(len(body))}
	for k, v := range want {
		if fake.redeemed[0][k] != v {
			t.Fatalf("descriptor %s: %v, want %v", k, fake.redeemed[0][k], v)
		}
	}
	c := fake.completed[0]
	if c["status"] != float64(201) || c["response_sha256"] != hexsum(got) || c["response_bytes"] != float64(len(got)) {
		t.Fatalf("complete: %v", c)
	}
}

func TestARefusedRequestNeverLeaves(t *testing.T) {
	up := newUpstream(t, ok)
	fake, _, front := setup(t, up, nil)
	fake.deny = "not in this agent's rights"
	resp := send(t, front, "GET", "/stripe/v1/charges", "", map[string]string{"X-Agent-Key": agentKey})
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 403 || resp.Header.Get("X-Provenza-Refused") == "" || !strings.Contains(string(raw), "rights") {
		t.Fatalf("got %d %s", resp.StatusCode, raw)
	}
	if len(up.got) != 0 || len(fake.redeemed) != 1 || len(fake.completed) != 0 {
		t.Fatal("a refused request reached the upstream, or was not redeemed (recorded)")
	}
}

func TestSDKModeRedeemsTheAgentsCheck(t *testing.T) {
	up := newUpstream(t, ok)
	fake, _, front := setup(t, up, nil)
	id := "chk_sdk_0123456789"
	fake.checked[id] = map[string]any{"route": "stripe", "method": "GET", "path": "/v1/charges/ch_1",
		"query_sha256": nil, "body_sha256": nil, "body_bytes": float64(0)}
	resp := send(t, front, "GET", "/stripe/v1/charges/ch_1", "", map[string]string{"X-Provenza-Check-Id": id})
	if resp.StatusCode != 201 || fake.checks != 0 || len(up.got) != 1 {
		t.Fatalf("got %d, checks %d", resp.StatusCode, fake.checks)
	}
	if up.got[0].Header.Get("X-Provenza-Check-Id") != "" {
		t.Fatal("the check id was forwarded")
	}
	// a request other than the checked one: the server refuses, nothing is sent
	resp = send(t, front, "GET", "/stripe/v1/charges/ch_2", "", map[string]string{"X-Provenza-Check-Id": id})
	if resp.StatusCode != 403 || len(up.got) != 1 {
		t.Fatalf("mismatch: got %d", resp.StatusCode)
	}
}

func TestLocalCredential(t *testing.T) {
	up := newUpstream(t, ok)
	file := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(file, []byte("local-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, front := setup(t, up, func(r *Route, c *Config) {
		r.CredentialSource, r.Secret = "local", ""
		c.LocalSecrets = map[string]LocalSecret{"stripe": {Header: "X-Api-Key", ValueFile: file}}
	})
	send(t, front, "GET", "/stripe/v1/charges", "", map[string]string{"X-Agent-Key": agentKey})
	if h := up.got[0].Header; h.Get("X-Api-Key") != "local-key" || h.Get("Authorization") != "" {
		t.Fatalf("upstream headers: %v", h)
	}
}

func TestTheRouteTableIsEnforcedLocally(t *testing.T) {
	up := newUpstream(t, ok)
	fake, _, front := setup(t, up, nil)
	agent := map[string]string{"X-Agent-Key": agentKey}
	for _, c := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/nope/v1/charges", "", 404},
		{"DELETE", "/stripe/v1/charges", "", 405},
		{"GET", "/stripe/v1/refunds", "", 403},
		{"GET", "/stripe/v1/charges/%2e%2e/%2e%2e/admin", "", 403},
		{"GET", "/stripe/v1/charges/a%2Fb", "", 403},
		{"POST", "/stripe/v1/charges", strings.Repeat("x", 101), 413},
	} {
		if resp := send(t, front, c.method, c.path, c.body, agent); resp.StatusCode != c.status {
			t.Errorf("%s %s: %d, want %d", c.method, c.path, resp.StatusCode, c.status)
		}
	}
	if len(up.got) != 0 || fake.checks != 0 {
		t.Fatal("a request outside the route reached the server or the upstream")
	}
	if resp := send(t, front, "GET", "/stripe/v1/charges", "", nil); resp.StatusCode != 401 {
		t.Fatalf("no key: %d", resp.StatusCode)
	}
}

func TestFailClosedAndUpstreamFailures(t *testing.T) {
	up := newUpstream(t, ok)
	fake, srv, front := setup(t, up, nil)
	agent := map[string]string{"X-Agent-Key": agentKey}

	up.srv.Close() // upstream gone: 502, recorded with status 0
	if resp := send(t, front, "GET", "/stripe/v1/charges", "", agent); resp.StatusCode != 502 {
		t.Fatalf("upstream down: %d", resp.StatusCode)
	}
	if c := fake.completed[0]; c["status"] != float64(0) || c["error"] != "upstream.unreachable" {
		t.Fatalf("complete: %v", c)
	}
	srv.Close() // Provenza gone: nothing is sent
	if resp := send(t, front, "GET", "/stripe/v1/charges", "", map[string]string{"X-Provenza-Check-Id": "chk_x_0123456789"}); resp.StatusCode != 503 {
		t.Fatalf("server down: %d", resp.StatusCode)
	}
}

func TestRedirectsGoBackToTheAgent(t *testing.T) {
	elsewhere := newUpstream(t, ok)
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.srv.URL+"/steal", http.StatusFound)
	})
	_, _, front := setup(t, up, nil)
	resp := send(t, front, "GET", "/stripe/v1/charges", "", map[string]string{"X-Agent-Key": agentKey})
	if resp.StatusCode != 302 || len(elsewhere.got) != 0 {
		t.Fatalf("redirect followed with the credential: %d", resp.StatusCode)
	}
}

func TestConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "c.json")
		_ = os.WriteFile(p, []byte(s), 0o600)
		return p
	}
	c, err := LoadConfig(write(`{"server_url":"https://provenza.example.com/"}`))
	if err != nil || c.Listen != "127.0.0.1:8443" || c.ServerURL != "https://provenza.example.com" ||
		c.UpstreamTimeout.Duration != time.Minute {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	for _, bad := range []string{
		`{"server_url":"https://p","listen":"0.0.0.0:8443"}`,
		`{"server_url":"https://p","alow_non_loopback":true}`,
		`{"server_url":"ftp://p"}`,
	} {
		if _, err := LoadConfig(write(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if _, err := LoadConfig(write(`{"server_url":"https://p","listen":"0.0.0.0:8443","allow_non_loopback":true}`)); err != nil {
		t.Fatal(err)
	}
}

// The descriptor the proxy redeems must be exactly the one an SDK checks
// (sdk/testdata/proxy-descriptor-vectors.json), through the real handler.
func TestDescriptorVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "sdk", "testdata", "proxy-descriptor-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Route, Method, Path, Query, Body string
			Descriptor                       map[string]any
		}
	}
	if err := json.Unmarshal(raw, &file); err != nil || len(file.Vectors) == 0 {
		t.Fatal("no vectors", err)
	}
	up := newUpstream(t, ok)
	var routes []Route
	for _, v := range file.Vectors {
		if v.Route != "stripe" {
			routes = append(routes, Route{Slug: v.Route, UpstreamURL: up.srv.URL, Methods: []string{"GET", "POST"},
				PathPrefixes: []string{"/"}, CredentialSource: "none", MaxBodyBytes: 1 << 20})
		}
	}
	fake, _, front := setup(t, up, func(r *Route, _ *Config) { r.PathPrefixes, r.MaxBodyBytes = []string{"/"}, 1<<20 },
		routes...)
	for _, v := range file.Vectors {
		p := v.Path
		if v.Query != "" {
			p += "?" + v.Query
		}
		resp := send(t, front, v.Method, "/"+v.Route+p, v.Body, map[string]string{"X-Agent-Key": agentKey})
		if resp.StatusCode != 201 {
			t.Fatalf("%s %s: %d", v.Method, p, resp.StatusCode)
		}
		got := fake.redeemed[len(fake.redeemed)-1]
		delete(got, "check_id")
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(v.Descriptor)
		if string(a) != string(b) {
			t.Errorf("%s %s:\n got  %s\n want %s", v.Method, p, a, b)
		}
	}
}
