// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

// sealForTest seals as the browser does (frontend/lib/sealing.ts, backend/app/pvp/sealed.py).
func sealForTest(proxyPub string, ctx map[string]any, credential string) map[string]any {
	pub, _ := base64.StdEncoding.DecodeString(proxyPub)
	peer, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		panic(err)
	}
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	shared, _ := eph.ECDH(peer)
	parsed, _ := canon.Of(ctx)
	aad, _ := canon.Bytes(parsed)
	epk := eph.PublicKey().Bytes()
	key := hkdfSHA256(shared, append(append([]byte{}, epk...), pub...), append([]byte(sealedInfo), aad...), 32)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	enc := base64.StdEncoding.EncodeToString
	return map[string]any{"v": 1, "alg": sealedAlg, "proxy_id": ctx["proxy_id"], "key_fingerprint": fingerprint(pub),
		"context": ctx, "epk": enc(epk), "nonce": enc(nonce), "ct": enc(gcm.Seal(nil, nonce, []byte(credential), aad))}
}

// asServed: the envelope as the proxy receives it (JSON, numbers as text).
func asServed(t *testing.T, env map[string]any) map[string]any {
	t.Helper()
	v, err := canon.Of(env)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func testOpener(t *testing.T) *opener {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	op, err := newOpener(priv)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func TestASealedCredentialOpensOnlyForItsContext(t *testing.T) {
	op := testOpener(t)
	want := map[string]any{"org_id": 3, "object": "route", "object_id": 7, "proxy_id": 1}
	ctx := map[string]any{"org_id": 3, "object": "route", "object_id": 7, "proxy_id": 1, "upstream": "https://api.stripe.com"}
	env := asServed(t, sealForTest(op.publicKey(), ctx, "Bearer sk_live"))
	got, up, err := op.open(env, want)
	if err != nil || got != "Bearer sk_live" || up != "https://api.stripe.com" {
		t.Fatalf("open: %q %q %v", got, up, err)
	}
	for name, other := range map[string]map[string]any{
		"another object": {"org_id": 3, "object": "route", "object_id": 8, "proxy_id": 1},
		"another kind":   {"org_id": 3, "object": "provider", "object_id": 7, "proxy_id": 1},
		"another proxy":  {"org_id": 3, "object": "route", "object_id": 7, "proxy_id": 2},
		"another org":    {"org_id": 4, "object": "route", "object_id": 7, "proxy_id": 1},
	} {
		if _, _, err := op.open(env, other); err == nil {
			t.Fatalf("%s: opened", name)
		}
	}
	// the context is authenticated: rewriting it in the envelope does not help
	moved := asServed(t, sealForTest(op.publicKey(), ctx, "x"))
	moved["context"] = map[string]any{"org_id": json.Number("3"), "object": "route", "object_id": json.Number("8"),
		"proxy_id": json.Number("1"), "upstream": "https://api.stripe.com"}
	if _, _, err := op.open(moved, map[string]any{"org_id": 3, "object": "route", "object_id": 8, "proxy_id": 1}); err == nil {
		t.Fatal("a rewritten context opened")
	}
	// nor does pointing it at another upstream
	evil := asServed(t, sealForTest(op.publicKey(), ctx, "x"))
	evil["context"].(map[string]any)["upstream"] = "https://evil.example"
	if _, _, err := op.open(evil, want); err == nil {
		t.Fatal("a rewritten upstream opened")
	}
	// sealed to another proxy's key
	other := testOpener(t)
	if _, _, err := op.open(asServed(t, sealForTest(other.publicKey(), ctx, "x")), want); err == nil {
		t.Fatal("another key's envelope opened")
	}
	// tampered ciphertext
	bad := asServed(t, sealForTest(op.publicKey(), ctx, "x"))
	ct, _ := base64.StdEncoding.DecodeString(bad["ct"].(string))
	ct[0] ^= 1
	bad["ct"] = base64.StdEncoding.EncodeToString(ct)
	if _, _, err := op.open(bad, want); err == nil {
		t.Fatal("a tampered envelope opened")
	}
}

// The vectors made by scripts/trust_vectors.py: Python seals, Go opens, and
// both derive the same encryption key from a proxy's signing seed.
func TestSealedVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "sdk", "testdata", "trust-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := canon.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := doc.(map[string]any)["sealed"].([]any)
	if len(list) == 0 {
		t.Fatal("no sealed vectors")
	}
	for _, v := range list {
		c := v.(map[string]any)
		seed, _ := base64.StdEncoding.DecodeString(c["proxy_seed"].(string))
		op, err := newOpener(ed25519.NewKeyFromSeed(seed))
		if err != nil {
			t.Fatal(err)
		}
		if op.publicKey() != c["encryption_key"] {
			t.Fatalf("%s: derived %s, want %s", c["name"], op.publicKey(), c["encryption_key"])
		}
		stmt, _ := keyStatement(op.publicKey())
		if string(stmt) != c["key_statement"] {
			t.Fatalf("%s: key statement %s", c["name"], stmt)
		}
		ctx := c["context"].(map[string]any)
		want := map[string]any{}
		for k, v := range ctx {
			if k != "upstream" {
				want[k] = v
			}
		}
		got, up, err := op.open(c["envelope"].(map[string]any), want)
		if err == nil && up != ctx["upstream"] {
			err = fmt.Errorf("opened for %s, the vector names %s", up, ctx["upstream"])
		}
		cred, _ := c["credential"].(string)
		if fails, _ := c["fails"].(bool); fails {
			if err == nil {
				t.Fatalf("%s: opened", c["name"])
			}
			continue
		}
		if err != nil || got != cred {
			t.Fatalf("%s: %q %v", c["name"], got, err)
		}
	}
}

func TestTheSealedCredentialGoesUpstreamAndOnlyForItsRoute(t *testing.T) {
	up := newUpstream(t, ok)
	fake, _, front := setup(t, up, nil)
	send(t, front, "GET", "/stripe/v1/charges", "", map[string]string{"X-Agent-Key": agentKey})
	if len(up.got) != 1 || up.got[0].Header.Get("Authorization") != secret {
		t.Fatalf("upstream: %v", up.got)
	}
	// a server that hands this route another route's envelope: nothing opens, nothing is sent
	fake.mu.Lock()
	fake.sealTo = map[string]any{"org_id": 3, "object": "route", "object_id": 99, "proxy_id": 1,
		"upstream": origin(up.srv.URL)}
	fake.mu.Unlock()
	p := front.Config.Handler.(*Proxy)
	if err := p.refreshCredentials(context.Background()); err != nil {
		t.Fatal(err)
	}
	resp := send(t, front, "GET", "/stripe/v1/charges", "", map[string]string{"X-Agent-Key": agentKey})
	if resp.StatusCode != http.StatusBadGateway || len(up.got) != 1 {
		t.Fatalf("status %d, upstream calls %d", resp.StatusCode, len(up.got))
	}
	fake.mu.Lock()
	last := fake.completed[len(fake.completed)-1]
	fake.mu.Unlock()
	if last["error"] != "proxy.sealed_credential_missing" {
		t.Fatalf("completed: %v", last)
	}
}

func TestTheOriginIsTheServers(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "sdk", "testdata", "trust-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Origins [][]any `json:"origins"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Origins) == 0 {
		t.Fatal("no origins", err)
	}
	for _, o := range doc.Origins {
		want, _ := o[1].(string)
		if got := origin(o[0].(string)); got != want {
			t.Fatalf("%v: %q, want %q", o[0], got, want)
		}
	}
}

func TestACredentialGoesOnlyToItsOrigin(t *testing.T) {
	up := newUpstream(t, ok)
	fake, _, front := setup(t, up, nil)
	// the server points the route at another upstream: the credential does not follow
	other := newUpstream(t, ok)
	fake.mu.Lock()
	fake.sealTo = map[string]any{"org_id": 3, "object": "route", "object_id": 7, "proxy_id": 1,
		"upstream": origin(up.srv.URL)}
	fake.routes[0].UpstreamURL = other.srv.URL
	fake.mu.Unlock()
	p := front.Config.Handler.(*Proxy)
	if _, err := p.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	resp := send(t, front, "GET", "/stripe/v1/charges", "", map[string]string{"X-Agent-Key": agentKey})
	if resp.StatusCode != http.StatusBadGateway || len(other.got) != 0 {
		t.Fatalf("status %d, calls to the other upstream %d", resp.StatusCode, len(other.got))
	}
}

func TestALocalCredentialBoundToAnOriginGoesNowhereElse(t *testing.T) {
	up := newUpstream(t, ok)
	file := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(file, []byte("local-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, front := setup(t, up, func(r *Route, c *Config) {
		r.CredentialSource = "local"
		c.LocalSecrets = map[string]LocalSecret{"stripe": {ValueFile: file, Upstream: "https://api.stripe.com"}}
	})
	resp := send(t, front, "GET", "/stripe/v1/charges", "", map[string]string{"X-Agent-Key": agentKey})
	if resp.StatusCode != http.StatusBadGateway || len(up.got) != 0 {
		t.Fatalf("status %d, upstream calls %d", resp.StatusCode, len(up.got))
	}
	if err := (&Config{ServerURL: "http://x", StateDir: t.TempDir(),
		LocalSecrets: map[string]LocalSecret{"a": {Upstream: "ftp://x"}}}).normalize(); err == nil {
		t.Fatal("a bad upstream was accepted")
	}
}
