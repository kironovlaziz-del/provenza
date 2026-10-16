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

func TestVerifyCommandSignatureFallback(t *testing.T) {
	// Two keypairs: old (previous) and new (current). A command signed
	// with the old one verifies when the old is in the list, even if the
	// current key comes first.
	oldPub, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	p := client.CommandPayload{
		ID: 1, Kind: "restart", OrgID: 7, SensorID: 3,
		IssuedAt: "2026-10-16T09:00:00Z", ExpiresAt: "2026-10-16T09:05:00Z",
	}
	canonical, _ := canonicalBytes(p)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(oldPriv, canonical))

	if verifyCommandSignatureAny([]ed25519.PublicKey{newPub, oldPub}, p, sig) != true {
		t.Fatal("fallback to previous key did not verify")
	}
	if verifyCommandSignatureAny([]ed25519.PublicKey{newPub}, p, sig) {
		t.Fatal("signature verified with the wrong key")
	}
}

func TestCanonicalBytesWithUpdateSigningKey(t *testing.T) {
	// The extra fields appear only when non-empty, and in alphabetical
	// order: expires_at, id, issued_at, kind, new_public_key, org_id,
	// previous_valid_until, sensor_id.
	p := client.CommandPayload{
		ID:                 7,
		Kind:               "update-signing-key",
		OrgID:              1,
		SensorID:           3,
		IssuedAt:           "2026-10-16T09:00:00Z",
		ExpiresAt:          "2026-10-16T09:05:00Z",
		NewPublicKey:       "AAAA",
		PreviousValidUntil: "2026-10-17T09:00:00Z",
	}
	got, err := canonicalBytes(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"expires_at":"2026-10-16T09:05:00Z","id":7,` +
		`"issued_at":"2026-10-16T09:00:00Z","kind":"update-signing-key",` +
		`"new_public_key":"AAAA","org_id":1,` +
		`"previous_valid_until":"2026-10-17T09:00:00Z","sensor_id":3}`
	if string(got) != want {
		t.Fatalf("canonical bytes differ:\n got %s\nwant %s", got, want)
	}
}
