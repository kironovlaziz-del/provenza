// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
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
	publicKey string                                              // the proxy key registered (/egress-proxy/key)
	encKey    string                                              // its encryption key, signed by publicKey
	sealTo    map[string]any                                      // context override for the envelopes served (a server that cheats)
	sealed    []sealedObject                                      // other objects' credentials it serves sealed
	plans     map[string]func(body map[string]any) map[string]any // /egress-proxy/<kind>/plan
	planned   []map[string]any                                    // what the proxy sent to plan endpoints (with the agent key)
	mcpSyncs  []map[string]any                                    // what the proxy reported of the MCP servers it syncs
	releases  []map[string]any                                    // what /egress-proxy/policy-release serves (all of them)
	approval  map[string]any                                      // returned with checks, when set
	agentID   any                                                 // the agent checks are issued for (default 5)
	// offline operation and the kill switch (offline.go, killswitch.go)
	down       bool             // answer every call with 503
	offline    []map[string]any // the offline actions handed over
	reconState map[string]any   // GET /egress-proxy/reconciliation
	ksPosts    []map[string]any // POST /egress-proxy/kill-switch
	liftSigs   []any            // what GET /egress-proxy/kill-switch/lift serves
	liftSHA    string
	liftedSHA  string
	headers    map[string]http.Header // the last request's headers, by path
	creds      []map[string]any       // what /egress-proxy/credentials serves instead, when set
}

func (f *fakeProvenza) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	if f.headers == nil {
		f.headers = map[string]http.Header{}
	}
	f.headers[r.URL.Path] = r.Header.Clone()
	if f.down {
		reply(503, nil)
		return
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	byProxy := r.Header.Get("X-Proxy-Key") == proxyKey
	byAgent := r.Header.Get("X-Agent-Key") == agentKey
	switch r.URL.Path {
	case "/api/v1/egress-proxy/key":
		if !byProxy {
			reply(401, nil)
			return
		}
		if f.publicKey != "" && f.publicKey != body["public_key"] {
			reply(409, map[string]any{"detail": "egress.proxy_key_changed"})
			return
		}
		f.publicKey, _ = body["public_key"].(string)
		enc, _ := body["encryption_key"].(string)
		sig, _ := base64.StdEncoding.DecodeString(fmt.Sprint(body["encryption_key_signature"]))
		pub, _ := base64.StdEncoding.DecodeString(f.publicKey)
		stmt, _ := keyStatement(enc)
		if enc == "" || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, stmt, sig) {
			reply(422, map[string]any{"detail": "egress.bad_proxy_encryption_key"})
			return
		}
		f.encKey = enc
		reply(200, map[string]any{"proxy_id": 1, "org_id": 3})
	case "/api/v1/egress-proxy/credentials":
		if !byProxy {
			reply(401, nil)
			return
		}
		if f.creds != nil {
			reply(200, map[string]any{"credentials": f.creds})
			return
		}
		out := []map[string]any{}
		for _, rt := range f.routes {
			if !sealedSource(rt.CredentialSource) || f.encKey == "" {
				continue
			}
			id, _ := rt.ID.Int64()
			ctx := map[string]any{"org_id": 3, "object": "route", "object_id": id, "proxy_id": 1,
				"upstream": origin(rt.UpstreamURL)}
			if f.sealTo != nil {
				ctx = f.sealTo
			}
			out = append(out, map[string]any{"object": "route", "object_id": id,
				"envelope": sealForTest(f.encKey, ctx, secret)})
		}
		for _, o := range f.sealed {
			if f.encKey == "" {
				continue
			}
			ctx := map[string]any{"org_id": 3, "object": o.object, "object_id": o.id, "proxy_id": 1,
				"upstream": o.upstream}
			out = append(out, map[string]any{"object": o.object, "object_id": o.id,
				"envelope": sealForTest(f.encKey, ctx, o.value)})
		}
		reply(200, map[string]any{"credentials": out})
	case "/api/v1/egress-proxy/check-info":
		want, ok := f.checked[body["check_id"].(string)]
		if !byProxy || !ok {
			reply(404, map[string]any{"detail": "egress.unknown_check"})
			return
		}
		parsed, _ := canon.Of(want)
		sha, _ := canon.SHA256(parsed)
		reply(200, map[string]any{"agent_id": f.agent(), "chain_id": nil, "action_type": "proxy",
			"tool_name": "proxy." + want["route"].(string), "input_sha256": sha, "decision": "allowed",
			"approval": f.approval})
	case "/api/v1/egress-proxy/policy-release":
		after, _ := strconv.Atoi(r.URL.Query().Get("after"))
		chain := []map[string]any{}
		for _, doc := range f.releases {
			n, _ := strconv.Atoi(fmt.Sprint(doc["release"].(map[string]any)["number"]))
			if n > after {
				chain = append(chain, doc)
			}
		}
		var current any
		if len(f.releases) > 0 {
			current = f.releases[len(f.releases)-1]["release"].(map[string]any)["number"]
		}
		reply(200, map[string]any{"current": current, "chain": chain})
	case "/api/v1/egress-proxy/config":
		if !byProxy {
			reply(401, map[string]any{"detail": "egress.bad_proxy_key"})
			return
		}
		reply(200, map[string]any{"routes": f.routes, "refresh_seconds": 60})
	case "/api/v1/egress-proxy/check":
		if !byProxy || !byAgent {
			reply(401, map[string]any{"detail": "egress.agent_key_invalid"})
			return
		}
		f.checks++
		id := "chk_" + strings.Repeat("a", 12) + string(rune('a'+f.checks))
		f.checked[id] = body
		decision := "allowed"
		if f.deny != "" {
			decision = "denied"
		}
		reply(200, map[string]any{"decision": decision, "reason": f.deny, "check_id": id, "agent_id": f.agent(),
			"chain_id": nil, "approval": f.approval})
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
	case "/api/v1/relay-echo":
		// what the relay delivered: the agent's own credentials, never the proxy's
		w.Header().Set("Retry-After", "7")
		w.Header().Set("Set-Cookie", "server=1")
		reply(418, map[string]any{"method": r.Method, "query": r.URL.RawQuery, "body": body,
			"agent_key": r.Header.Get("X-Agent-Key"), "proxy_key": r.Header.Get("X-Proxy-Key"),
			"cookie": r.Header.Get("Cookie")})
	case "/api/v1/egress-proxy/http-tools/plan", "/api/v1/egress-proxy/llm/plan", "/api/v1/egress-proxy/mcp/plan",
		"/api/v1/egress-proxy/a2a/plan":
		kind := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/egress-proxy/"), "/plan")
		if !byProxy || !byAgent {
			reply(401, map[string]any{"detail": "egress.agent_key_invalid"})
			return
		}
		f.planned = append(f.planned, body)
		h := f.plans[kind]
		if h == nil {
			reply(404, nil)
			return
		}
		reply(200, h(body))
	case "/api/v1/egress-proxy/mcp/sync":
		if !byProxy {
			reply(401, nil)
			return
		}
		f.mcpSyncs = append(f.mcpSyncs, body)
		reply(200, map[string]any{"synced": true})
	case "/api/v1/egress-proxy/complete":
		f.completed = append(f.completed, body)
		reply(200, map[string]any{"action_id": 2})
	case "/api/v1/egress-proxy/offline-actions":
		results := []map[string]any{}
		for _, a := range body["actions"].([]any) {
			f.offline = append(f.offline, a.(map[string]any))
			results = append(results, map[string]any{"status": "recorded"})
		}
		reply(200, map[string]any{"results": results})
	case "/api/v1/egress-proxy/reconciliation":
		reply(200, f.reconState)
	case "/api/v1/egress-proxy/kill-switch":
		f.ksPosts = append(f.ksPosts, body)
		reply(200, map[string]any{"id": 1})
	case "/api/v1/egress-proxy/kill-switch/lift":
		reply(200, map[string]any{"report_sha256": f.liftSHA, "signatures": f.liftSigs})
	case "/api/v1/egress-proxy/kill-switch/lifted":
		f.liftedSHA, _ = body["report_sha256"].(string)
		reply(200, map[string]any{"ok": true})
	default:
		reply(404, nil)
	}
}

// sealedObject: a credential the fake server serves sealed to the proxy.
type sealedObject struct {
	object, upstream, value string
	id                      int64
}

func (f *fakeProvenza) agent() any {
	if f.agentID != nil {
		return f.agentID
	}
	return 5
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
	route := Route{ID: "7", Slug: "stripe", UpstreamURL: up.srv.URL, Methods: []string{"GET", "POST"},
		PathPrefixes: []string{"/v1/charges"}, CredentialSource: "sealed", AuthHeader: "Authorization",
		MaxBodyBytes: 100}
	fake := &fakeProvenza{checked: map[string]map[string]any{}}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	cfg := &Config{ServerURL: srv.URL, StateDir: t.TempDir()}
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
		r.CredentialSource = "local"
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

func TestRelayToProvenza(t *testing.T) {
	up := newUpstream(t, ok)
	_, _, front := setup(t, up, func(_ *Route, c *Config) { c.RelayProvenza = true })
	resp := send(t, front, "POST", "/_provenza/api/v1/relay-echo?x=1", `{"a":1}`,
		map[string]string{"X-Agent-Key": agentKey, "Content-Type": "application/json", "Cookie": "c=1",
			"X-Proxy-Key": "pvz_proxy_forged"})
	var got map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if resp.StatusCode != 418 || got["method"] != "POST" || got["query"] != "x=1" || got["agent_key"] != agentKey {
		t.Fatalf("relayed %d %v", resp.StatusCode, got)
	}
	if got["proxy_key"] != "" || got["cookie"] != "" {
		t.Fatalf("the relay must not pass the proxy key or cookies: %v", got)
	}
	if resp.Header.Get("Retry-After") != "7" || resp.Header.Get("Set-Cookie") != "" {
		t.Fatalf("response headers %v", resp.Header)
	}
	if b, _ := json.Marshal(got["body"]); string(b) != `{"a":1}` {
		t.Fatalf("body %s", b)
	}
	for _, path := range []string{"/_provenza/egress-beacon/x", "/_provenza/api/v1/../../egress-beacon/x",
		"/_provenza/api/v1/%2e%2e/x", "/_provenza"} {
		if resp := send(t, front, "GET", path, "", nil); resp.StatusCode != 403 {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
	}
	if len(up.got) != 0 {
		t.Fatal("nothing goes to the routes' upstreams")
	}
}

func TestRelayIsOffByDefault(t *testing.T) {
	up := newUpstream(t, ok)
	_, _, front := setup(t, up, nil)
	if resp := send(t, front, "GET", "/_provenza/api/v1/relay-echo", "", nil); resp.StatusCode != 404 {
		t.Fatalf("relay off: %d", resp.StatusCode)
	}
}

// On a proxy host the sensor holds the proxy for a moment (docs/pvp/edge.md,
// section 5): a server not reachable yet at start is tried again.
func TestStartWaitsForTheServerBriefly(t *testing.T) {
	up := newUpstream(t, ok)
	fake := &fakeProvenza{checked: map[string]map[string]any{},
		routes: []Route{{ID: "7", Slug: "stripe", UpstreamURL: up.srv.URL, Methods: []string{"GET"},
			PathPrefixes: []string{"/v1"}, CredentialSource: "none", AuthHeader: "Authorization", MaxBodyBytes: 100}}}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close() // nothing listens yet
	cfg := &Config{ServerURL: "http://" + addr, StateDir: t.TempDir()}
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	p := New(cfg, proxyKey, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- p.Start(ctx) }()
	time.Sleep(400 * time.Millisecond)
	l, err = net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("the port was taken meanwhile: %v", err)
	}
	srv := &http.Server{Handler: fake}
	go srv.Serve(l)
	defer srv.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not finish")
	}
	if time.Since(start) < 400*time.Millisecond || p.reg.ProxyID.String() == "" {
		t.Fatalf("started without the server (%v, %+v)", time.Since(start), p.reg)
	}
}
