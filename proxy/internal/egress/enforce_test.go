// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

// sdk/testdata/trust-vectors.json: releases signed by software passkeys the
// way the server and a browser sign them (backend/scripts/trust_vectors.py).
func trustVectors(t *testing.T) map[string]any {
	raw, err := os.ReadFile("../../../sdk/testdata/trust-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := canon.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func docs(v map[string]any) []map[string]any {
	var out []map[string]any
	for _, d := range v["releases"].([]any) {
		out = append(out, d.(map[string]any))
	}
	return out
}

// verifyReceipt: the receipt is signed by the key the proxy registered.
func verifyReceipt(t *testing.T, publicKey string, receipt map[string]any) map[string]any {
	t.Helper()
	pub, _ := base64.StdEncoding.DecodeString(publicKey)
	sig, _ := base64.StdEncoding.DecodeString(receipt["signature"].(string))
	st, err := canon.Of(receipt["statement"])
	if err != nil {
		t.Fatal(err)
	}
	text, _ := canon.Text(st)
	if !ed25519.Verify(pub, []byte(text), sig) {
		t.Fatal("the receipt's signature does not verify with the registered key")
	}
	return receipt["statement"].(map[string]any)
}

func TestReceiptsAreSignedAndChained(t *testing.T) {
	up := newUpstream(t, ok)
	var dir string
	fake, _, front := setup(t, up, func(_ *Route, c *Config) { dir = c.StateDir })
	for i := 0; i < 2; i++ {
		resp := send(t, front, "POST", "/stripe/v1/charges", `{"amount":1}`, map[string]string{"X-Agent-Key": agentKey})
		if resp.StatusCode != 201 {
			t.Fatalf("got %d", resp.StatusCode)
		}
	}
	if fake.publicKey == "" {
		t.Fatal("the proxy did not register its key")
	}
	var lines [][]byte
	f, err := os.Open(filepath.Join(dir, logFile))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, append([]byte{}, sc.Bytes()...))
	}
	for i, c := range fake.completed {
		receipt, _ := c["receipt"].(map[string]any)
		if receipt == nil {
			t.Fatalf("request %d: no receipt", i)
		}
		st := verifyReceipt(t, fake.publicKey, receipt)
		out, _ := canon.Of(map[string]any{"status": c["status"], "response_sha256": c["response_sha256"],
			"response_bytes": c["response_bytes"]})
		outSHA, _ := canon.SHA256(out)
		if st["output_sha256"] != outSHA || st["decision"] != "allowed" || st["agent_signature"] != "not_presented" ||
			st["policy"] != nil || st["tool_name"] != "proxy.stripe" || st["check_id"] != c["check_id"] {
			t.Fatalf("receipt %d: %v", i, st)
		}
		log := st["log"].(map[string]any)
		prev := ""
		if i > 0 {
			sum := sha256.Sum256(lines[i-1])
			prev = hex.EncodeToString(sum[:])
		}
		if log["prev"] != prev || len(lines) != 2 {
			t.Fatalf("receipt %d: log %v, %d lines", i, log, len(lines))
		}
	}
}

func TestTheKeyIsTheProxysOwn(t *testing.T) {
	up := newUpstream(t, ok)
	var dir string
	fake, srv, _ := setup(t, up, func(_ *Route, c *Config) { dir = c.StateDir })
	first := fake.publicKey
	// the same state dir: the same key
	p := New(&Config{ServerURL: srv.URL, StateDir: dir, Listen: "127.0.0.1:0"}, proxyKey, nil)
	_ = p.cfg.normalize()
	if err := p.Start(context.Background()); err != nil || fake.publicKey != first {
		t.Fatalf("restart: %v, key %s -> %s", err, first, fake.publicKey)
	}
	// another key for the same proxy: refused by the server, the proxy does not start
	p = New(&Config{ServerURL: srv.URL, StateDir: t.TempDir(), Listen: "127.0.0.1:0"}, proxyKey, nil)
	_ = p.cfg.normalize()
	if err := p.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "registering") {
		t.Fatalf("a second key: %v", err)
	}
}

// enforcing: a proxy with policy.mode "enforce", pinned to the first release's manifest.
func enforcing(t *testing.T, mutate func(*Config), releases func(v map[string]any) []map[string]any) (*fakeProvenza, *httptest.Server, map[string]any) {
	t.Helper()
	fake, front, v, _ := enforcingProxy(t, mutate, releases)
	return fake, front, v
}

func enforcingProxy(t *testing.T, mutate func(*Config), releases func(v map[string]any) []map[string]any,
	server ...func(*fakeProvenza)) (*fakeProvenza, *httptest.Server, map[string]any, *Proxy) {
	t.Helper()
	v := trustVectors(t)
	up := newUpstream(t, ok)
	fake := &fakeProvenza{checked: map[string]map[string]any{}}
	for _, f := range server {
		f(fake) // before the proxy starts: nothing reads it yet
	}
	if releases != nil {
		fake.releases = releases(v)
	}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	fake.routes = []Route{{Slug: "stripe", UpstreamURL: up.srv.URL, Methods: []string{"POST"},
		PathPrefixes: []string{"/v1/charges"}, CredentialSource: "none", AuthHeader: "Authorization", MaxBodyBytes: 100}}
	cfg := &Config{ServerURL: srv.URL, StateDir: t.TempDir(),
		Policy: PolicyConfig{Mode: "enforce", Pin: v["pin"].(string)}}
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	p := New(cfg, proxyKey, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// the signed releases name https://api.stripe.com: a test never reaches the internet
	p.upstream.Transport = loopbackOnly{}
	now, _ := v["now"].(json.Number).Int64()
	p.now = func() time.Time { return time.Unix(now, 0) }
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := p.Start(ctx); err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(p)
	t.Cleanup(front.Close)
	// the agent's own check, as the SDK makes it
	fake.checked["chk_sdk_signed_0001"] = map[string]any{"route": "stripe", "method": "POST", "path": "/v1/charges",
		"query_sha256": nil, "body_sha256": nil, "body_bytes": float64(0)}
	return fake, front, v, p
}

func TestEnforceTheSignedPolicy(t *testing.T) {
	fake, front, v := enforcing(t, nil, docs)
	signed := map[string]string{"X-Provenza-Check-Id": "chk_sdk_signed_0001",
		"X-Provenza-Request": v["request_header"].(string)}
	resp := send(t, front, "POST", "/stripe/v1/charges", "", signed)
	// the signed route's upstream (api.stripe.com, unreachable here), not the server's table
	if resp.StatusCode != 502 || len(fake.redeemed) != 1 || fake.redeemed[0]["enforcement"] != nil {
		t.Fatalf("got %d, redeemed %v", resp.StatusCode, fake.redeemed)
	}
	c := fake.completed[0]
	if c["error"] != "upstream.unreachable" {
		t.Fatalf("complete: %v", c)
	}
	st := verifyReceipt(t, fake.publicKey, c["receipt"].(map[string]any))
	pol := st["policy"].(map[string]any)
	if st["agent_signature"] != "verified" || pol["release"] != float64(3) {
		t.Fatalf("receipt: %v", st)
	}
	// the same signed request again: its nonce is spent
	resp = send(t, front, "POST", "/stripe/v1/charges", "", signed)
	if resp.StatusCode != 401 {
		t.Fatalf("a replayed signed request: %d", resp.StatusCode)
	}
}

func TestEnforceRefusesWhatTheSignedPolicyDoesNotAllow(t *testing.T) {
	fake, front, _ := enforcing(t, nil, docs)
	fake.agentID = 6 // an agent the release does not know
	resp := send(t, front, "POST", "/stripe/v1/charges", "", map[string]string{"X-Agent-Key": agentKey})
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 403 || !strings.Contains(string(raw), "not in the signed policy") {
		t.Fatalf("got %d %s", resp.StatusCode, raw)
	}
	enf := fake.redeemed[0]["enforcement"].(map[string]any)
	if enf["decision"] != "denied" {
		t.Fatalf("enforcement: %v", enf)
	}
	st := verifyReceipt(t, fake.publicKey, enf["receipt"].(map[string]any))
	if st["decision"] != "denied" || st["agent_id"] != float64(6) {
		t.Fatalf("receipt: %v", st)
	}
	if len(fake.completed) != 0 {
		t.Fatal("a refused request was forwarded")
	}
}

func TestEnforceWithoutAVerifiedRelease(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"nothing served": nil,
		"another anchor": func(c *Config) { c.Policy.Pin = strings.Repeat("0", 64) },
	} {
		var serve func(map[string]any) []map[string]any
		if name != "nothing served" {
			serve = docs
		}
		fake, front, _ := enforcing(t, mutate, serve)
		resp := send(t, front, "POST", "/stripe/v1/charges", "", map[string]string{"X-Agent-Key": agentKey})
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 403 || !strings.Contains(string(raw), "has not verified a signed policy") {
			t.Fatalf("%s: got %d %s", name, resp.StatusCode, raw)
		}
		if len(fake.completed) != 0 {
			t.Fatalf("%s: forwarded", name)
		}
	}
}

func TestEnforceStaysOnTheLastGoodRelease(t *testing.T) {
	// release 3 altered on the server: the proxy keeps release 2, which has no route
	_, front, _ := enforcing(t, nil, func(v map[string]any) []map[string]any {
		all := docs(v)
		raw, _ := json.Marshal(all[2])
		tampered, _ := canon.Parse(raw)
		tm := tampered.(map[string]any)
		tm["bundle"].(map[string]any)["offline_seconds"] = json.Number("99999")
		return []map[string]any{all[0], all[1], tm}
	})
	resp := send(t, front, "POST", "/stripe/v1/charges", "", map[string]string{"X-Agent-Key": agentKey})
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 403 || !strings.Contains(string(raw), "egress route 'stripe' does not exist") {
		t.Fatalf("got %d %s", resp.StatusCode, raw)
	}
}

func TestRequireTheAgentsSignature(t *testing.T) {
	_, front, _ := enforcing(t, func(c *Config) { c.Policy.RequireAgentSignature = true }, docs)
	for _, h := range []map[string]string{{"X-Agent-Key": agentKey}, {"X-Provenza-Check-Id": "chk_sdk_signed_0001"}} {
		resp := send(t, front, "POST", "/stripe/v1/charges", "", h)
		if resp.StatusCode != 401 {
			t.Fatalf("%v: got %d", h, resp.StatusCode)
		}
	}
}

func TestPolicyConfig(t *testing.T) {
	for _, p := range []PolicyConfig{{Mode: "enforce"}, {Mode: "enforce", Pin: "abc"}, {Mode: "strict"}} {
		c := &Config{ServerURL: "https://p.example", Policy: p}
		if err := c.normalize(); err == nil {
			t.Errorf("%+v accepted", p)
		}
	}
	c := &Config{ServerURL: "https://p.example", Policy: PolicyConfig{Mode: "enforce", Pin: "tofu"}}
	if err := c.normalize(); err != nil || c.StateDir == "" {
		t.Fatal(err)
	}
}

func TestASigningKeyFromAFile(t *testing.T) {
	seed, fp, err := NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "proxy.key")
	if err := os.WriteFile(keyPath, []byte(seed+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	up := newUpstream(t, ok)
	fake, _, _ := setup(t, up, func(_ *Route, c *Config) { c.SigningKeyFile = keyPath })
	raw, _ := base64.StdEncoding.DecodeString(fake.publicKey)
	sum := sha256.Sum256(raw)
	if got := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]); got != fp {
		t.Fatalf("registered %s, the file's key is %s", got, fp)
	}
}

// loopbackOnly: the upstream transport of the tests - a request to anything but
// this host fails as an unreachable upstream does, wherever the tests run.
type loopbackOnly struct{}

func (loopbackOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	if ip := net.ParseIP(r.URL.Hostname()); ip == nil || !ip.IsLoopback() {
		return nil, errors.New("tests do not reach " + r.URL.Host)
	}
	return http.DefaultTransport.RoundTrip(r)
}
