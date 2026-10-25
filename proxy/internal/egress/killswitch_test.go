// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
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

// softPasskey: a passkey as tests/webauthn_helpers.py makes them (ES256).
type softPasskey struct {
	key  *ecdsa.PrivateKey
	cred string
	spki string
}

func newSoftPasskey(t *testing.T, name string) softPasskey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return softPasskey{key: k, cred: "cred-" + name, spki: base64.StdEncoding.EncodeToString(der)}
}

func (k softPasskey) entry() map[string]any {
	return map[string]any{"alg": -7, "public_key": k.spki, "fingerprint": trust.PasskeyFingerprint(k.spki)}
}

// assert: the WebAuthn assertion over a statement (user present and verified).
func (k softPasskey) assert(t *testing.T, statement any) map[string]any {
	t.Helper()
	text, err := canon.Text(statement)
	if err != nil {
		t.Fatal(err)
	}
	challenge := sha256.Sum256([]byte(text))
	client, _ := json.Marshal(map[string]any{"type": "webauthn.get",
		"challenge": base64.RawURLEncoding.EncodeToString(challenge[:]), "origin": "https://provenza.test"})
	auth := append(make([]byte, 32), 0x05, 0, 0, 0, 1)
	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, auth...), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	b := base64.RawURLEncoding.EncodeToString
	return map[string]any{"client_data_json": b(client), "authenticator_data": b(auth), "signature": b(sig)}
}

// parsed: v as a document parsed from JSON (numbers as json.Number).
func parsed(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	out, err := canon.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return out.(map[string]any)
}

// firstRelease: release 1, signed by the administrators' passkeys (its own manifest governs it).
func firstRelease(t *testing.T, admins map[string]softPasskey, quorum int) map[string]any {
	t.Helper()
	signers := map[string]any{}
	for uid, k := range admins {
		signers[uid] = map[string]any{"email": uid + "@example.com", "role": "admin",
			"passkeys": map[string]any{k.cred: k.entry()}}
	}
	notAfter := time.Now().Add(24 * time.Hour).Unix()
	bundle := parsed(t, map[string]any{"type": "provenza.policy.bundle", "v": 1, "org_id": 3, "version": 1,
		"previous": nil, "not_after": notAfter, "offline_seconds": 60, "agents": map[string]any{},
		"tool_registry": map[string]any{"entries": map[string]any{"1": map[string]any{"name": "db.read"}}}})
	manifest := parsed(t, map[string]any{"type": "provenza.key.manifest", "v": 1, "org_id": 3, "version": 1,
		"previous": nil, "quorum": quorum, "signers": signers, "agents": map[string]any{"5": "SHA256:agent5"},
		"egress_proxies": map[string]any{}, "egress_sensors": map[string]any{}, "sensor_command_key": nil})
	bsha, _ := canon.SHA256(bundle)
	msha, _ := canon.SHA256(manifest)
	rel := map[string]any{"number": 1, "bundle": map[string]any{"version": 1, "sha256": bsha},
		"manifest": map[string]any{"version": 1, "sha256": msha}}
	var sigs []any
	for uid, k := range admins {
		st := parsed(t, map[string]any{"type": "provenza.policy.release", "v": 1, "org_id": 3,
			"user_id": json.Number(uid), "release": 1, "bundle": rel["bundle"], "manifest": rel["manifest"],
			"not_after": notAfter, "issued_at": time.Now().Unix() - 10})
		sigs = append(sigs, map[string]any{"user_id": json.Number(uid), "credential_id": k.cred, "statement": st,
			"assertion": k.assert(t, st)})
	}
	doc := parsed(t, map[string]any{"release": rel, "bundle": bundle, "manifest": manifest, "signatures": sigs,
		"governed_by": nil})
	if _, _, err := trust.VerifyRelease(doc); err != nil {
		t.Fatalf("the test release does not verify: %v", err)
	}
	return doc
}

func liftSignature(t *testing.T, uid string, k softPasskey, sha string, accept []string) any {
	acc := []any{}
	for _, a := range accept {
		acc = append(acc, a)
	}
	st := parsed(t, map[string]any{"type": "provenza.kill_switch.lift", "v": 1, "org_id": 3,
		"user_id": json.Number(uid), "proxy_id": 1, "report_sha256": sha, "accept": acc,
		"issued_at": time.Now().Unix(), "expires_at": time.Now().Unix() + 12*3600})
	return map[string]any{"user_id": json.Number(uid), "credential_id": k.cred, "statement": st,
		"assertion": k.assert(t, st)}
}

func startProxy(t *testing.T, fake *fakeProvenza, srv *httptest.Server, dir, pin string) (*Proxy, *httptest.Server) {
	t.Helper()
	cfg := &Config{ServerURL: srv.URL, StateDir: dir, Policy: PolicyConfig{Mode: "enforce", Pin: pin}}
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
	return p, front
}

// cutOff: Provenza has not answered for d.
func cutOff(p *Proxy, d time.Duration) {
	p.srv.contact.mu.Lock()
	p.srv.contact.last, p.srv.contact.down = time.Now().Add(-d), true
	p.srv.contact.mu.Unlock()
}

func TestTheLocalKillSwitch(t *testing.T) {
	a, b, c := newSoftPasskey(t, "a"), newSoftPasskey(t, "b"), newSoftPasskey(t, "c")
	doc := firstRelease(t, map[string]softPasskey{"1": a, "2": b}, 2)
	up := newUpstream(t, ok)
	fake := &fakeProvenza{checked: map[string]map[string]any{}, releases: []map[string]any{doc}}
	fake.routes = []Route{{ID: "7", Slug: "stripe", UpstreamURL: up.srv.URL, Methods: []string{"POST"},
		PathPrefixes: []string{"/v1"}, CredentialSource: "none", AuthHeader: "Authorization", MaxBodyBytes: 100}}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	pin := doc["release"].(map[string]any)["manifest"].(map[string]any)["sha256"].(string)
	p, front := startProxy(t, fake, srv, dir, pin)
	if p.enf.current() == nil {
		t.Fatal("no verified release")
	}

	// a short outage: nothing yet
	cutOff(p, 30*time.Second)
	if p.ks.check(p, p.enf.current()) {
		t.Fatal("engaged within the release's offline time")
	}
	// longer than the release's offline_seconds (60): stopped
	cutOff(p, 61*time.Second)
	if !p.ks.check(p, p.enf.current()) {
		t.Fatal("not engaged")
	}
	resp := send(t, front, "POST", "/stripe/v1/x", "", map[string]string{"X-Agent-Key": agentKey})
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 503 || !strings.Contains(string(raw), "provenza_kill_switch") {
		t.Fatalf("got %d %s", resp.StatusCode, raw)
	}
	if _, err := os.Stat(filepath.Join(dir, killSwitchFile)); err != nil {
		t.Fatal(err)
	}

	// a restart does not lift it
	p2, front2 := startProxy(t, fake, srv, dir, pin)
	if engaged, _ := p2.ks.engagedNow(); !engaged {
		t.Fatal("a restart lifted the kill switch")
	}
	// the server states an agent key and an administrator that no release signed
	manifest := parsed(t, doc["manifest"])
	manifest["agents"].(map[string]any)["9"] = "SHA256:slipped-in"
	manifest["signers"].(map[string]any)["3"] = map[string]any{"email": "c@example.com", "role": "admin",
		"passkeys": map[string]any{c.cred: c.entry()}}
	fake.reconState = map[string]any{"manifest": manifest, "tool_registry": doc["bundle"].(map[string]any)["tool_registry"]}
	if err := p2.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fake.ksPosts) != 1 {
		t.Fatalf("reports %d", len(fake.ksPosts))
	}
	post := fake.ksPosts[0]
	report := post["report"].(map[string]any)
	diffs := report["differences"].([]any)
	ids := []string{}
	for _, d := range diffs {
		dm := d.(map[string]any)
		if dm["signed"] != false {
			t.Fatalf("signed: %v", dm)
		}
		ids = append(ids, dm["id"].(string))
	}
	if strings.Join(ids, ",") != "manifest.signers.3,manifest.agents.9" {
		t.Fatalf("differences %v", ids)
	}
	st := verifyReceipt(t, fake.publicKey, post["receipt"].(map[string]any))
	if st["type"] != reportType || st["report_sha256"] != p2.ks.posted {
		t.Fatalf("receipt %v", st)
	}
	// the same report is not sent again
	_ = p2.reconcile(context.Background())
	if len(fake.ksPosts) != 1 {
		t.Fatal("an unchanged report was sent again")
	}

	sha := p2.ks.posted
	fake.liftSHA = sha
	cases := []struct {
		name string
		sigs []any
	}{
		{"one of two", []any{liftSignature(t, "1", a, sha, ids)}},
		{"not accepting all", []any{liftSignature(t, "1", a, sha, ids[:1]), liftSignature(t, "2", b, sha, ids[:1])}},
		{"another report", []any{liftSignature(t, "1", a, "00", ids), liftSignature(t, "2", b, "00", ids)}},
		// the administrator the server slipped in does not count: only the manifest before the outage does
		{"a new administrator", []any{liftSignature(t, "1", a, sha, ids), liftSignature(t, "3", c, sha, ids)}},
	}
	for _, cs := range cases {
		fake.liftSigs = cs.sigs
		if err := p2.reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		if engaged, _ := p2.ks.engagedNow(); !engaged {
			t.Fatalf("%s: lifted", cs.name)
		}
	}
	fake.liftSigs = []any{liftSignature(t, "1", a, sha, ids), liftSignature(t, "2", b, sha, ids)}
	if err := p2.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if engaged, _ := p2.ks.engagedNow(); engaged || fake.liftedSHA != sha {
		t.Fatalf("not lifted (lifted %q)", fake.liftedSHA)
	}
	if _, err := os.Stat(filepath.Join(dir, killSwitchFile)); !os.IsNotExist(err) {
		t.Fatal("the kill switch file stayed")
	}
	resp = send(t, front2, "POST", "/stripe/v1/x", "", map[string]string{"X-Agent-Key": agentKey})
	if resp.StatusCode == 503 {
		t.Fatal("still stopped after the lift")
	}
	// the report and the lift are in the proxy's signed log
	f, _ := os.Open(filepath.Join(dir, logFile))
	defer f.Close()
	types := []string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var line struct {
			Statement struct {
				Type string `json:"type"`
			} `json:"statement"`
		}
		_ = json.Unmarshal(sc.Bytes(), &line)
		types = append(types, line.Statement.Type)
	}
	if !strings.Contains(strings.Join(types, " "), "provenza.reconciliation provenza.proxy.lifted") {
		t.Fatalf("log %v", types)
	}
}

func TestOfflineUnderTheSignedPolicy(t *testing.T) {
	fake, front, v, p := enforcingProxy(t, nil, docs)
	signedOnly := map[string]string{"X-Provenza-Request": v["request_header"].(string)}
	// Provenza answers: a request with no check is refused
	resp := send(t, front, "POST", "/stripe/v1/charges", "", signedOnly)
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 400 || !strings.Contains(string(raw), "Provenza is reachable") {
		t.Fatalf("online: %d %s", resp.StatusCode, raw)
	}
	fake.mu.Lock()
	fake.down = true
	fake.mu.Unlock()
	time.Sleep(probeEvery + 100*time.Millisecond) // the last probe found it up
	// cut off: the release judges it; the signed route (api.stripe.com) is unreachable here
	resp = send(t, front, "POST", "/stripe/v1/charges", "", signedOnly)
	if resp.StatusCode != 502 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("offline: %d %s", resp.StatusCode, raw)
	}
	// once
	resp = send(t, front, "POST", "/stripe/v1/charges", "", signedOnly)
	if resp.StatusCode != 401 {
		t.Fatalf("a replay offline: %d", resp.StatusCode)
	}
	// an agent key alone cannot be checked offline
	resp = send(t, front, "POST", "/stripe/v1/charges", "", map[string]string{"X-Agent-Key": agentKey})
	if resp.StatusCode != 503 {
		t.Fatalf("mediated offline: %d", resp.StatusCode)
	}
	p.uploadOffline(context.Background()) // still cut off: nothing
	fake.mu.Lock()
	fake.down = false
	n := len(fake.offline)
	fake.mu.Unlock()
	if n != 0 {
		t.Fatal("handed over while offline")
	}
	p.Refresh(context.Background()) // it answers again
	p.uploadOffline(context.Background())
	if len(fake.offline) != 1 {
		t.Fatalf("handed over %d", len(fake.offline))
	}
	e := fake.offline[0]
	if e["decision"] != "allowed" || e["outcome"].(map[string]any)["error"] != "upstream.unreachable" ||
		e["release"] != float64(3) || e["request"].(map[string]any)["payload"] == nil {
		t.Fatalf("entry %v", e)
	}
	st := verifyReceipt(t, fake.publicKey, e["receipt"].(map[string]any))
	if st["agent_signature"] != "verified" || !strings.HasPrefix(st["check_id"].(string), "offline-") {
		t.Fatalf("receipt %v", st)
	}
	for _, f := range []string{offlineFile, offlineUploading} {
		if _, err := os.Stat(filepath.Join(p.cfg.StateDir, f)); !os.IsNotExist(err) {
			t.Fatalf("%s stayed", f)
		}
	}
}

// A refused key is no contact: the offline time keeps running.
func TestARefusedKeyIsNoContact(t *testing.T) {
	status := http.StatusUnauthorized
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"detail":"x"}`))
	}))
	t.Cleanup(srv.Close)
	s := newServer(srv.URL, proxyKey, 5*time.Second)
	if _, err := s.callRaw(context.Background(), http.MethodGet, "/egress-proxy/config", nil, s.asProxy()); err == nil {
		t.Fatal("a refused key answered")
	}
	if _, since := s.contact.state(); since != 0 || !s.contact.last.IsZero() {
		t.Fatal("HTTP 401 counted as contact")
	}
	status = http.StatusNotFound // an answer, even a refusal of the request
	_, _ = s.callRaw(context.Background(), http.MethodGet, "/egress-proxy/config", nil, s.asProxy())
	if s.contact.last.IsZero() {
		t.Fatal("an answer did not count as contact")
	}
}
