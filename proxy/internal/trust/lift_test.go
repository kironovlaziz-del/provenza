// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package trust

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

// sdk/testdata/lift-vectors.json: made by the server's code (backend/scripts/trust_vectors.py lift).
func TestVerifyLift(t *testing.T) {
	raw, err := os.ReadFile("../../../sdk/testdata/lift-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	pv, err := canon.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	v := pv.(map[string]any)
	manifest := obj(v["manifest"])
	var unsigned []string
	for _, u := range v["unsigned"].([]any) {
		unsigned = append(unsigned, str(u))
	}
	engaged, _ := num(v["engaged_at"])
	now, _ := num(v["now"])
	want := LiftWant{ProxyID: canonText(v["proxy_id"]), ReportSHA256: str(v["report_sha256"]), Unsigned: unsigned,
		NotBefore: engaged, Now: now}
	sigs := v["signatures"].([]any)
	users, problems := VerifyLift(sigs, manifest, want)
	if len(users) != 2 || len(problems) != 0 || Quorum(manifest) != 2 {
		t.Fatalf("%v %v", users, problems)
	}
	if users, _ := VerifyLift(sigs[:1], manifest, want); len(users) >= Quorum(manifest) {
		t.Fatal("one administrator reached a quorum of two")
	}
	if users, _ := VerifyLift([]any{sigs[0], sigs[0]}, manifest, want); len(users) != 1 {
		t.Fatal("the same administrator counted twice")
	}
	for _, name := range []string{"approver", "partial_accept", "before_engaged", "other_report"} {
		if users, problems := VerifyLift([]any{v[name]}, manifest, want); len(users) != 0 || len(problems) != 1 {
			t.Errorf("%s: %v %v", name, users, problems)
		}
	}
	late := want
	late.Now = now + 13*3600
	if users, _ := VerifyLift(sigs, manifest, late); len(users) != 0 {
		t.Fatal("an expired signature lifted")
	}
	long := clone(t, obj(sigs[0]))
	obj(long["statement"])["expires_at"] = json.Number(fmt.Sprint(now + 3*86400))
	if users, _ := VerifyLift([]any{long}, manifest, want); len(users) != 0 {
		t.Fatal("a signature valid for days lifted")
	}
	other := want
	other.ProxyID = "3"
	if users, _ := VerifyLift(sigs, manifest, other); len(users) != 0 {
		t.Fatal("lifted another proxy")
	}
	// a manifest without them (the server's new one, say) lifts nothing
	m := clone(t, manifest)
	delete(obj(m["signers"]), "1")
	if users, _ := VerifyLift(sigs, m, want); len(users) != 1 {
		t.Fatalf("%v", users)
	}
	forged := clone(t, obj(sigs[0]))
	obj(forged["statement"])["accept"] = []any{}
	if users, _ := VerifyLift([]any{forged}, manifest, LiftWant{ProxyID: want.ProxyID,
		ReportSHA256: want.ReportSHA256, NotBefore: engaged, Now: now}); len(users) != 0 {
		t.Fatal("a changed statement verified")
	}
}
