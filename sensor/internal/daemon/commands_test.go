// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/kironovlaziz-del/provenza/sensor/internal/client"
)

// The bytes below were produced by the Python side
// (app.core.agent_signing.canonical_text). If this test fails, one of the
// two implementations changed its JSON writer and every command signature
// will no longer verify.
func TestCanonicalBytesMatchPython(t *testing.T) {
	p := client.CommandPayload{
		ID:        42,
		Kind:      "detach",
		OrgID:     7,
		SensorID:  3,
		IssuedAt:  "2026-10-16T09:00:00Z",
		ExpiresAt: "2026-10-16T09:05:00Z",
	}
	got, err := canonicalBytes(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"expires_at":"2026-10-16T09:05:00Z","id":42,` +
		`"issued_at":"2026-10-16T09:00:00Z","kind":"detach",` +
		`"org_id":7,"sensor_id":3}`
	if string(got) != want {
		t.Fatalf("canonical bytes differ:\n got %s\nwant %s", got, want)
	}
}

func TestVerifyCommandSignatureRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := client.CommandPayload{
		ID: 1, Kind: "dump-state", OrgID: 7, SensorID: 3,
		IssuedAt: "2026-10-16T09:00:00Z", ExpiresAt: "2026-10-16T09:05:00Z",
	}
	canonical, _ := canonicalBytes(p)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical))

	if !verifyCommandSignature(pub, p, sig) {
		t.Fatal("valid signature refused")
	}

	// Flip the kind: same key, same wire format, different bytes.
	bad := p
	bad.Kind = "restart"
	if verifyCommandSignature(pub, bad, sig) {
		t.Fatal("signature verified over a modified payload")
	}

	// Garbage base64 must not panic and must not verify.
	if verifyCommandSignature(pub, p, "not-base64!!!") {
		t.Fatal("garbage signature accepted")
	}

	// Wrong-sized key must be refused quietly.
	if verifyCommandSignature(ed25519.PublicKey([]byte("short")), p, sig) {
		t.Fatal("short key accepted")
	}
}
