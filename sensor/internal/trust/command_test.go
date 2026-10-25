// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package trust

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/canon"
)

// sdk/testdata/sensor-command-vectors.json is made by the server's code
// (backend/scripts/trust_vectors.py sensor-commands) and checked by it
// (backend/tests/test_sensor_signed_commands.py).
func commandVectors(t *testing.T) map[string]any {
	raw, err := os.ReadFile("../../../sdk/testdata/sensor-command-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := canon.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func TestVerifyCommand(t *testing.T) {
	v := commandVectors(t)
	now := time.Unix(1_800_000_000, 0)
	manifest := obj(v["manifest"])
	admin := obj(v["admin"])

	cmd, err := VerifyCommand(admin, manifest, 4, now)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Kind != "restart" || cmd.UserID != "1" || len(cmd.Nonce) < 16 || !strings.HasPrefix(cmd.Passkey, "SHA256:") {
		t.Fatalf("%+v", cmd)
	}
	if got := ProxyBinaries(manifest); len(got) != 1 || !got[strings.Repeat("ab", 32)] {
		t.Fatalf("proxy binaries %v", got)
	}

	refused := func(name string, proof, m map[string]any, sensor int64, at time.Time) {
		t.Helper()
		if _, err := VerifyCommand(proof, m, sensor, at); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	refused("another sensor", admin, manifest, 5, now)
	refused("expired", admin, manifest, 4, now.Add(11*time.Minute))
	refused("issued in the future", admin, manifest, 4, now.Add(-5*time.Minute))
	refused("an approver", obj(v["approver"]), manifest, 4, now)

	edit := func(f func(p, m map[string]any)) (map[string]any, map[string]any) {
		p, m := clone(t, admin), clone(t, manifest)
		f(p, m)
		return p, m
	}
	for name, f := range map[string]func(p, m map[string]any){
		"kind changed":       func(p, m map[string]any) { obj(p["statement"])["kind"] = "detach" },
		"not a command kind": func(p, m map[string]any) { obj(p["statement"])["kind"] = "update-signing-key" },
		"long life": func(p, m map[string]any) {
			obj(p["statement"])["expires_at"] = json.Number("1800009999")
		},
		"another org":         func(p, m map[string]any) { m["org_id"] = json.Number("2") },
		"not in the manifest": func(p, m map[string]any) { delete(obj(m["signers"]), "1") },
		"demoted":             func(p, m map[string]any) { obj(obj(m["signers"])["1"])["role"] = "approver" },
		"another passkey":     func(p, m map[string]any) { obj(obj(m["signers"])["1"])["passkeys"] = map[string]any{} },
		"another session key": func(p, m map[string]any) { p["session_public_key"] = obj(v["approver"])["session_public_key"] },
		"another certificate": func(p, m map[string]any) { p["certificate"] = obj(v["approver"])["certificate"] },
		"signature":           func(p, m map[string]any) { p["signature"] = obj(v["approver"])["signature"] },
		"no nonce":            func(p, m map[string]any) { obj(p["statement"])["nonce"] = "x" },
		"statement type":      func(p, m map[string]any) { obj(p["statement"])["type"] = "provenza.approval" },
		"no statement":        func(p, m map[string]any) { delete(p, "statement") },
		"certificate assertion": func(p, m map[string]any) {
			obj(obj(p["certificate"])["assertion"])["signature"] = obj(obj(obj(v["approver"])["certificate"])["assertion"])["signature"]
		},
	} {
		p, m := edit(f)
		refused(name, p, m, 4, now)
	}
}
