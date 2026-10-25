// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

import (
	"context"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
	"github.com/kironovlaziz-del/provenza/proxy/internal/trust"
)

// sdk/testdata/enforce-vectors.json: a release in enforce mode and agent 5's
// key (backend/scripts/trust_vectors.py enforce).
func enforceVectors(t *testing.T) map[string]any {
	raw, err := os.ReadFile("../../../sdk/testdata/enforce-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := canon.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func identityFile(t *testing.T, fields map[string]any, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.json")
	raw, _ := json.Marshal(fields)
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func agentFields(ev map[string]any) map[string]any {
	a := ev["agent"].(map[string]any)
	return map[string]any{"agent_id": 5, "api_key": agentKey, "private_key": a["private_key"],
		"public_key": a["public_key"], "pq_private_key": nil, "server": "https://p.example"}
}

func TestTheAgentsIdentity(t *testing.T) {
	ev := enforceVectors(t)
	id, err := LoadAgentIdentity(identityFile(t, agentFields(ev), 0o600))
	if err != nil || id.AgentID != 5 || id.APIKey != agentKey {
		t.Fatalf("%v %+v", err, id)
	}
	for name, c := range map[string]struct {
		edit func(map[string]any)
		mode os.FileMode
	}{
		"readable by others": {nil, 0o644},
		"bad ML-DSA key":     {func(m map[string]any) { m["pq_private_key"] = "AAAA" }, 0o600},
		"ML-DSA public only": {func(m map[string]any) { m["pq_public_key"] = "AAAA" }, 0o600},
		"keychain":           {func(m map[string]any) { m["secrets"] = "keychain"; m["private_key"] = nil }, 0o600},
		"not enrolled":       {func(m map[string]any) { delete(m, "agent_id") }, 0o600},
		"another key":        {func(m map[string]any) { m["public_key"] = strings.Repeat("A", 43) + "=" }, 0o600},
	} {
		f := agentFields(ev)
		if c.edit != nil {
			c.edit(f)
		}
		if _, err := LoadAgentIdentity(identityFile(t, f, c.mode)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, addr := range []string{"0.0.0.0:8480", "10.0.0.5:8480", ":8480"} {
		if _, err := NewAgentMode(id, addr, "http://127.0.0.1:8443", nil); err == nil {
			t.Errorf("listen %s: accepted", addr)
		}
	}
	for _, up := range []string{"ftp://x:1", "http://proxy:8443/prefix", "http://proxy:8443/?a=1", "proxy:8443"} {
		if _, err := NewAgentMode(id, "127.0.0.1:8480", up, nil); err == nil {
			t.Errorf("upstream %s: accepted", up)
		}
	}
}

// inEnforceMode: a proxy whose verified release says "enforcement": "enforce",
// and agent mode in front of it, signing as agent 5 (named in that release).
func inEnforceMode(t *testing.T) (*fakeProvenza, *httptest.Server, *httptest.Server, *Proxy) {
	t.Helper()
	ev := enforceVectors(t)
	fake, front, _, p := enforcingProxy(t, func(c *Config) { c.Policy.Pin = ev["pin"].(string) },
		func(map[string]any) []map[string]any { return docs(ev) })
	if !p.enf.strict() {
		t.Fatal("the release in enforce mode does not make the proxy strict")
	}
	id, err := LoadAgentIdentity(identityFile(t, agentFields(ev), 0o600))
	if err != nil {
		t.Fatal(err)
	}
	h, err := newAgentMode(id, "127.0.0.1:8480", front.URL, nil, p.now)
	if err != nil {
		t.Fatal(err)
	}
	am := httptest.NewServer(h)
	t.Cleanup(am.Close)
	return fake, front, am, p
}

func TestAgentModeSignsForTheAgent(t *testing.T) {
	fake, front, am, p := inEnforceMode(t)
	// straight to the proxy with the agent's key only: refused in enforce mode
	resp := send(t, front, "POST", "/stripe/v1/charges", "", map[string]string{"X-Agent-Key": agentKey})
	if resp.StatusCode != 401 || fake.checks != 0 {
		t.Fatalf("unsigned: %d, %d checks", resp.StatusCode, fake.checks)
	}
	// through agent mode: signed, checked with the signed request, judged with the agent's key verified
	resp = send(t, am, "POST", "/stripe/v1/charges", "", map[string]string{"Authorization": "Bearer junk"})
	if resp.StatusCode != 502 || fake.checks != 1 || len(fake.completed) != 1 { // the signed upstream: unreachable here
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("signed: %d %s, %d checks", resp.StatusCode, raw, fake.checks)
	}
	h := fake.headers["/api/v1/egress-proxy/check"]
	if h.Get(proxyModeHeader) != "enforce" || h.Get("X-Agent-Key") != agentKey || h.Get(requestHeader) == "" {
		t.Fatalf("check headers: %v", h)
	}
	sr, err := trust.ParseSignedRequest(h.Get(requestHeader))
	if err != nil {
		t.Fatal(err)
	}
	dmap, _ := canon.Of(Descriptor{Route: "stripe", Method: "POST", Path: "/v1/charges"})
	sha, _ := canon.SHA256(dmap)
	if _, err := sr.Verify("proxy", "proxy.stripe", sha, trust.NewNonces(), p.now()); err != nil {
		t.Fatalf("what agent mode signed: %v", err)
	}
	st := verifyReceipt(t, fake.publicKey, fake.completed[0]["receipt"].(map[string]any))
	if st["agent_signature"] != "verified" || st["policy"].(map[string]any)["release"] != float64(1) {
		t.Fatalf("receipt: %v", st)
	}
}

func TestEnforceModeOnTheGatewayPaths(t *testing.T) {
	fake, front, am, _ := inEnforceMode(t)
	fake.plans = map[string]func(map[string]any) map[string]any{"llm": func(map[string]any) map[string]any {
		return map[string]any{"decision": "refused", "status": 403,
			"error": map[string]any{"code": "model_not_allowed", "message": "no"}}
	}}
	chat := `{"model":"gpt-x","messages":[{"role":"user","content":"hi"}]}`
	resp := send(t, front, "POST", "/_llm/v1/chat/completions", chat, map[string]string{"X-Agent-Key": agentKey})
	if resp.StatusCode != 401 || len(fake.planned) != 0 {
		t.Fatalf("unsigned: %d", resp.StatusCode)
	}
	resp = send(t, am, "POST", "/_llm/v1/chat/completions", chat, map[string]string{"Authorization": "Bearer junk"})
	if resp.StatusCode != 403 || len(fake.planned) != 1 {
		t.Fatalf("signed: %d, %d plans", resp.StatusCode, len(fake.planned))
	}
	// the plan carries the agent's signed request and what it signed, for the server to verify again
	h := fake.headers["/api/v1/egress-proxy/llm/plan"]
	raw, err := base64.RawURLEncoding.DecodeString(h.Get(descriptorHeader))
	if err != nil {
		t.Fatal(err)
	}
	desc, _ := canon.Parse(raw)
	sr, err := trust.ParseSignedRequest(h.Get(requestHeader))
	if err != nil {
		t.Fatal(err)
	}
	sha, _ := canon.SHA256(desc)
	d := desc.(map[string]any)
	if d["route"] != "_llm" || d["path"] != "/v1/chat/completions" || sr.Payload["input_sha256"] != sha ||
		sr.Payload["tool_name"] != "proxy._llm" || h.Get(proxyModeHeader) != "enforce" {
		t.Fatalf("plan headers: %v %v", desc, sr.Payload)
	}
	// the same signed request twice: refused here before the server sees it
	again := map[string]string{"X-Agent-Key": agentKey, requestHeader: h.Get(requestHeader)}
	resp = send(t, front, "POST", "/_llm/v1/chat/completions", chat, again)
	if resp.StatusCode != 401 || len(fake.planned) != 1 {
		t.Fatalf("replayed: %d", resp.StatusCode)
	}
	// a read is not an action: the model list needs no signature
	resp = send(t, front, "GET", "/_llm/v1/models", "", map[string]string{"X-Agent-Key": agentKey})
	if resp.StatusCode == 401 {
		t.Fatal("the model list asked for a signature")
	}
}

func TestStrictFollowsTheSignedPolicy(t *testing.T) {
	e := newEnforcer(PolicyConfig{Mode: "enforce"}, t.TempDir())
	if e.strict() {
		t.Fatal("strict without a release")
	}
	e.rel = &trust.Release{Bundle: map[string]any{"enforcement": map[string]any{"mode": "observe"}}}
	if e.strict() {
		t.Fatal("strict in observe mode")
	}
	e.rel = &trust.Release{Bundle: map[string]any{"enforcement": map[string]any{"mode": "enforce"}}}
	if !e.strict() {
		t.Fatal("not strict in enforce mode")
	}
	e.cfg.Mode = "off"
	if e.strict() {
		t.Fatal("a proxy that does not judge by the signed policy cannot be strict")
	}
}

// The signed Tool Registry pins a tool's digest: the judge gets the digest the
// proxy found (an HTTP tool's pinned definition, an MCP tool's live one).
func TestTheJudgeGetsTheToolsDigest(t *testing.T) {
	p := New(&Config{ServerURL: "https://p.example", StateDir: t.TempDir(), Policy: PolicyConfig{Mode: "enforce", Pin: "tofu"}},
		proxyKey, nil)
	digest := strings.Repeat("ab", 32)
	p.enf.rel = &trust.Release{Number: 4, Bundle: map[string]any{
		"not_after": json.Number(fmt.Sprint(time.Now().Unix() + 3600)),
		"agents": map[string]any{"5": map[string]any{"name": "a", "status": "active", "team_id": nil,
			"capabilities": []any{}, "allowed_tools": []any{"crm.set_tier"}, "allowed_models": []any{},
			"max_delegation_depth": json.Number("1")}},
		"tool_registry": map[string]any{"mode": "enforce", "entries": map[string]any{"crm.set_tier": map[string]any{
			"status": "approved", "pinned_version": nil, "pinned_digest": digest,
			"required_capabilities": []any{}}}}}}
	judge := func(d *string) (string, string) {
		chk := &checkResult{AgentID: json.Number("5"), Tool: "crm.set_tier", ToolDigest: d}
		v, why, _ := p.judge(chk, "tool_call", "crm.set_tier", map[string]any{"id": "1"}, "x", false, nil)
		return v, why
	}
	if v, why := judge(nil); v != "denied" || !strings.Contains(why, "must report its manifest digest") {
		t.Fatalf("no digest: %s %s", v, why)
	}
	other := strings.Repeat("cd", 32)
	if v, why := judge(&other); v != "denied" || !strings.Contains(why, "differs") {
		t.Fatalf("another digest: %s %s", v, why)
	}
	if v, why := judge(&digest); strings.Contains(why, "ASI04") {
		t.Fatalf("the pinned digest: %s %s", v, why)
	}
}

// Agent mode on a unix socket: only its owner reaches it.
func TestAgentModeOnAUnixSocket(t *testing.T) {
	fake, front, _, p := inEnforceMode(t)
	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")
	if err := os.WriteFile(sock, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AgentListener("unix:" + sock); err == nil {
		t.Fatal("a file that is not a socket was replaced")
	}
	_ = os.Remove(sock)
	for _, bad := range []string{"unix:", "unix:relative.sock", "0.0.0.0:8480"} {
		if _, err := AgentListener(bad); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
	ln, err := AgentListener("unix:" + sock)
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(sock); err != nil || st.Mode().Perm() != 0o600 || st.Mode()&os.ModeSocket == 0 {
		t.Fatalf("the socket: %v %v", st.Mode(), err)
	}
	ev := enforceVectors(t)
	id, _ := LoadAgentIdentity(identityFile(t, agentFields(ev), 0o600))
	h, err := newAgentMode(id, "unix:"+sock, front.URL, nil, p.now)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	resp, err := client.Post("http://agent/stripe/v1/charges", "application/json", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 502 || fake.checks != 1 { // signed, checked, sent to the signed upstream (unreachable here)
		t.Fatalf("through the socket: %d, %d checks", resp.StatusCode, fake.checks)
	}
	// a stale socket from an earlier run is replaced
	_ = srv.Close()
	if l2, err := AgentListener("unix:" + sock); err != nil {
		t.Fatalf("a stale socket: %v", err)
	} else {
		l2.Close()
	}
}

// An enforcing proxy hashes the A2A card it fetched itself, as the server does
// (sdk/testdata/enforce-vectors.json, a2a_cards).
func TestTheCardDigestIsTheServers(t *testing.T) {
	for i, c := range enforceVectors(t)["a2a_cards"].([]any) {
		v := c.(map[string]any)
		got, err := cardDigest(v["card"].(map[string]any))
		if err != nil || got != v["digest"] {
			t.Errorf("card %d: %s, want %s (%v)", i, got, v["digest"], err)
		}
	}
}

// An enforcing proxy opens only an envelope an administrator of its signed
// manifest vouched for (trust.VerifySealed): the server cannot slip one in.
func TestOnlyAVouchedCredentialOpens(t *testing.T) {
	ev := enforceVectors(t)
	s := ev["sealer"].(map[string]any)
	keyFile := filepath.Join(t.TempDir(), "proxy.key")
	if err := os.WriteFile(keyFile, []byte(s["proxy_seed"].(string)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var fake *fakeProvenza
	fake, _, _, p := enforcingProxy(t, func(c *Config) {
		c.Policy.Pin = ev["pin"].(string)
		c.SigningKeyFile = keyFile
	}, func(map[string]any) []map[string]any { return docs(ev) },
		func(f *fakeProvenza) { f.orgID = 1 }) // the organization the vectors' release is of
	cred := map[string]any{"object": "route", "object_id": 9, "envelope": s["envelope"], "sealer": s["proof"]}
	serve := func(c map[string]any) map[credKey]openedCredential {
		fake.mu.Lock()
		fake.creds = []map[string]any{c}
		fake.mu.Unlock()
		if err := p.refreshCredentials(context.Background()); err != nil {
			t.Fatal(err)
		}
		p.mu.RLock()
		defer p.mu.RUnlock()
		return p.creds
	}
	if got := serve(cred); got[credKey{"route", "9"}].Value != "Bearer sk_sealed_"+strings.Repeat("s", 24) ||
		!p.vouched["route:9"] {
		t.Fatalf("the vouched credential: %v", got)
	}
	unsigned := map[string]any{"object": "route", "object_id": 9, "envelope": s["envelope"]}
	if got := serve(unsigned); len(got) != 0 {
		t.Fatal("an envelope nobody vouched for was opened")
	}
	// the server's own envelope, under the administrator's signature for another one
	other := map[string]any{"object": "route", "object_id": 9, "sealer": s["proof"],
		"envelope": sealForTest(fake.encKey, map[string]any{"org_id": 1, "object": "route", "object_id": 9,
			"proxy_id": 1, "upstream": "https://api.stripe.com"}, "Bearer server_chose_this")}
	if got := serve(other); len(got) != 0 {
		t.Fatal("an envelope the signature does not name was opened")
	}
}

// After an outage, a credential sealed again counts as signed when an
// administrator of the signed policy vouched for its envelope.
func TestAVouchedEnvelopeIsASignedDifference(t *testing.T) {
	ev := enforceVectors(t)
	rel, _, err := trust.VerifyRelease(docs(ev)[0])
	if err != nil {
		t.Fatal(err)
	}
	st := &engagedState{EngagedAt: 1, Envelopes: map[string]string{"route:9": "aa", "route:7": "bb"}, before: rel}
	now := map[string]string{"route:9": "cc", "route:7": "dd"}
	server := map[string]any{"manifest": rel.Manifest} // the manifest unchanged meanwhile
	_, unsigned := buildReport(st, rel, server, now, map[string]string{"route:9": "cc"},
		json.Number("1"), json.Number("1"))
	if len(unsigned) != 1 || unsigned[0] != "credentials.sealed.route:7" {
		t.Fatalf("unsigned: %v", unsigned)
	}
}

// A hybrid identity (Ed25519 + ML-DSA-65): agent mode signs with both halves,
// over the same canonical payload, as the SDKs do.
func TestAgentModeSignsWithAHybridKey(t *testing.T) {
	ev := enforceVectors(t)
	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	f := agentFields(ev)
	f["pq_private_key"] = base64.StdEncoding.EncodeToString(sk.Bytes())
	f["pq_public_key"] = base64.StdEncoding.EncodeToString(sk.PublicKey().Bytes())
	id, err := LoadAgentIdentity(identityFile(t, f, 0o600))
	if err != nil || !id.Hybrid() {
		t.Fatalf("hybrid identity: %v", err)
	}
	other, _ := mldsa.GenerateKey(mldsa.MLDSA65())
	f["pq_public_key"] = base64.StdEncoding.EncodeToString(other.PublicKey().Bytes())
	if _, err := LoadAgentIdentity(identityFile(t, f, 0o600)); err == nil {
		t.Fatal("an ML-DSA public key that is not the private key's was accepted")
	}

	d := Descriptor{Route: "stripe", Method: "POST", Path: "/v1/charges", BodySHA256: sha256Hex([]byte("{}")), BodyBytes: 2}
	header, err := id.Sign(d, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		t.Fatal(err)
	}
	var signed struct {
		Payload     map[string]any `json:"payload"`
		PQSignature string         `json:"pq_signature"`
		PQPublicKey string         `json:"pq_public_key"`
	}
	if err := json.Unmarshal(raw, &signed); err != nil || signed.PQSignature == "" {
		t.Fatalf("no ML-DSA signature: %v %s", err, raw)
	}
	msg, _ := canon.Bytes(signed.Payload)
	pub, _ := base64.StdEncoding.DecodeString(signed.PQPublicKey)
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pub)
	ps, _ := base64.StdEncoding.DecodeString(signed.PQSignature)
	if err != nil || mldsa.Verify(pk, msg, ps, nil) != nil {
		t.Fatal("the ML-DSA signature does not verify over the canonical payload")
	}
	// what an enforcing proxy checks: the Ed25519 half, the key's fingerprint, fresh and once
	sr, err := trust.ParseSignedRequest(header)
	if err != nil {
		t.Fatal(err)
	}
	dmap, _ := canon.Of(d)
	sha, _ := canon.SHA256(dmap)
	fp, err := sr.Verify("proxy", "proxy.stripe", sha, trust.NewNonces(), time.Now())
	want, _ := trust.KeyFingerprint(id.PublicKey, id.PQPublic)
	if err != nil || fp != want {
		t.Fatalf("verify: %v (fingerprint %s, want %s)", err, fp, want)
	}
}
