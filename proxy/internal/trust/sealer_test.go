// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package trust

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

// sdk/testdata/enforce-vectors.json, sealer: made by the server's code
// (backend/scripts/trust_vectors.py enforce).
func TestVerifySealed(t *testing.T) {
	raw, err := os.ReadFile("../../../sdk/testdata/enforce-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	pv, err := canon.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	v := pv.(map[string]any)
	manifest := obj(obj(v["releases"].([]any)[0])["manifest"])
	s := obj(v["sealer"])
	proof := obj(s["proof"])
	want := SealedWant{OrgID: s["org_id"], Object: str(s["object"]), ObjectID: s["object_id"], ProxyID: s["proxy_id"],
		Upstream: str(s["upstream"]), EnvelopeSHA256: str(s["envelope_sha256"])}
	if user, err := VerifySealed(proof, manifest, want); err != nil || user != "1" {
		t.Fatalf("%s %v", user, err)
	}
	refused := func(name string, p, m map[string]any, w SealedWant) {
		t.Helper()
		if _, err := VerifySealed(p, m, w); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	other := func(f func(*SealedWant)) SealedWant { w := want; f(&w); return w }
	refused("another object", proof, manifest, other(func(w *SealedWant) { w.ObjectID = json.Number("10") }))
	refused("another proxy", proof, manifest, other(func(w *SealedWant) { w.ProxyID = json.Number("2") }))
	refused("another envelope", proof, manifest, other(func(w *SealedWant) { w.EnvelopeSHA256 = "00" }))
	refused("another origin", proof, manifest, other(func(w *SealedWant) { w.Upstream = "https://evil.example" }))
	refused("another organization", proof, manifest, other(func(w *SealedWant) { w.OrgID = json.Number("3") }))
	refused("no proof", nil, manifest, want)
	approver := clone(t, manifest)
	obj(obj(approver["signers"])["1"])["role"] = "approver"
	refused("not an administrator", proof, approver, want)
	gone := clone(t, manifest)
	obj(obj(gone["signers"])["1"])["passkeys"] = map[string]any{}
	refused("a passkey the manifest does not name", proof, gone, want)
	forged := clone(t, proof)
	obj(forged["statement"])["envelopes"] = map[string]any{"1": "00"}
	refused("a changed statement", forged, manifest, other(func(w *SealedWant) { w.EnvelopeSHA256 = "00" }))
	late := clone(t, proof)
	obj(late["statement"])["issued_at"] = json.Number("1900000000")
	refused("signed outside the session", late, manifest, want)
}
