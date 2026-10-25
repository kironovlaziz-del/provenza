// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package trust

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/canon"
)

// sdk/testdata/trust-vectors.json is made by the server's code
// (backend/scripts/trust_vectors.py) and checked by it
// (backend/tests/test_trust_vectors.py); the same documents must verify here.
func vectors(t *testing.T) map[string]any {
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

func releases(v map[string]any) []map[string]any {
	var out []map[string]any
	for _, r := range v["releases"].([]any) {
		out = append(out, r.(map[string]any))
	}
	return out
}

// deep copy through JSON, numbers kept
func clone(t *testing.T, m map[string]any) map[string]any {
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	v, err := canon.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func TestReleasesVerify(t *testing.T) {
	v := vectors(t)
	for i, doc := range releases(v) {
		r, fps, err := VerifyRelease(doc)
		if err != nil {
			t.Fatalf("release %d: %v", i+1, err)
		}
		if r.Number != i+1 || len(fps) == 0 {
			t.Fatalf("release %d: number %d, %d signers", i+1, r.Number, len(fps))
		}
	}
}

func TestAdvanceFromThePin(t *testing.T) {
	v := vectors(t)
	chain := releases(v)
	pin := v["pin"].(string)
	r, err := Advance(nil, pin, false, chain)
	if err != nil || r == nil || r.Number != 3 {
		t.Fatalf("got %v, %v", r, err)
	}
	// from release 2 on, only what follows it
	two, _, _ := VerifyRelease(chain[1])
	r, err = Advance(two, "", false, chain)
	if err != nil || r.Number != 3 {
		t.Fatalf("got %v, %v", r, err)
	}
	// another anchor: nothing is taken
	r, err = Advance(nil, "0000", false, chain)
	if err != nil || r != nil {
		t.Fatalf("an unknown anchor took %v (%v)", r, err)
	}
	// trust on first use takes the first release's own manifest
	r, err = Advance(nil, "", true, chain)
	if err != nil || r == nil || r.Number != 3 {
		t.Fatalf("tofu: %v, %v", r, err)
	}
}

func TestTamperedReleasesAreRefused(t *testing.T) {
	v := vectors(t)
	cases := map[string]func(d map[string]any){
		"bundle changed": func(d map[string]any) {
			d["bundle"].(map[string]any)["agents"].(map[string]any)["5"].(map[string]any)["allowed_tools"] = []any{"*"}
		},
		"a signature missing": func(d map[string]any) {
			s := d["signatures"].([]any)
			d["signatures"] = s[:1]
		},
		"statement for another release": func(d map[string]any) {
			d["signatures"].([]any)[1].(map[string]any)["statement"].(map[string]any)["release"] = json.Number("99")
		},
		"governing quorum lowered": func(d map[string]any) {
			d["governed_by"].(map[string]any)["manifest"].(map[string]any)["quorum"] = json.Number("1")
		},
	}
	for name, change := range cases {
		doc := clone(t, releases(v)[2])
		change(doc)
		if _, _, err := VerifyRelease(doc); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// a tampered step stops the advance where it is
	chain := releases(v)
	bad := clone(t, chain[2])
	bad["signatures"] = bad["signatures"].([]any)[:1]
	one, _, _ := VerifyRelease(chain[0])
	r, err := Advance(one, "", false, []map[string]any{chain[1], bad})
	if err == nil || r.Number != 2 {
		t.Fatalf("got %v, %v", r, err)
	}
}

func TestApproval(t *testing.T) {
	v := vectors(t)
	proof := v["approval"].(map[string]any)
	call := v["call"].(map[string]any)
	c := Call{AgentID: call["agent_id"], ChainID: call["chain_id"], ActionType: call["action_type"].(string),
		ToolName: call["tool_name"].(string), InputSHA256: call["input_sha256"].(string)}
	m3 := releases(v)[2]["manifest"].(map[string]any)
	if _, err := VerifyApproval(proof, m3, c); err != nil {
		t.Fatal(err)
	}
	m1 := releases(v)[0]["manifest"].(map[string]any)
	if _, err := VerifyApproval(proof, m1, c); err == nil {
		t.Fatal("an approver missing from the manifest approved")
	}
	other := c
	other.InputSHA256 = "00"
	if _, err := VerifyApproval(proof, m3, other); err == nil {
		t.Fatal("approved another call")
	}
	forged := clone(t, proof)
	forged["statement"].(map[string]any)["action_id"] = json.Number("78")
	if _, err := VerifyApproval(forged, m3, c); err == nil {
		t.Fatal("a changed statement verified")
	}
}

func TestSignedRequest(t *testing.T) {
	v := vectors(t)
	r, err := ParseSignedRequest(v["request_header"].(string))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	sha := v["call"].(map[string]any)["input_sha256"].(string)
	nonces := NewNonces()
	fp, err := r.Verify("proxy", "proxy.stripe", sha, nonces, now)
	if err != nil || fp != v["agent_fingerprint"] {
		t.Fatalf("%q %v", fp, err)
	}
	if _, err := r.Verify("proxy", "proxy.stripe", sha, nonces, now); err == nil {
		t.Fatal("a used nonce was accepted again")
	}
	if _, err := r.Verify("proxy", "proxy.stripe", "00", NewNonces(), now); err == nil {
		t.Fatal("verified for another input")
	}
	if _, err := r.Verify("proxy", "proxy.stripe", sha, NewNonces(), now.Add(time.Hour)); err == nil {
		t.Fatal("an old request was accepted")
	}
	r.Payload["nonce"] = "changed"
	if _, err := r.Verify("proxy", "proxy.stripe", sha, NewNonces(), now); err == nil {
		t.Fatal("a changed payload verified")
	}
}
