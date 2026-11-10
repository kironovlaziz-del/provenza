// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

//go:build windows

package connect

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The identity file's access list on this system: after protectFile only this
// user (and what Windows keeps for the system) is on it, and a file that
// Everyone can read is refused by egress.LoadAgentIdentity's check (tested there).
func TestProtectFileRemovesInheritedAccess(t *testing.T) {
	p := filepath.Join(t.TempDir(), "id.json")
	if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", p, "/grant", "*S-1-1-0:R").CombinedOutput(); err != nil { // Everyone
		t.Fatalf("icacls: %v %s", err, out)
	}
	if err := protectFile(p); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("icacls", p).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"Everyone", "BUILTIN\\Users", "Authenticated Users"} {
		if contains(string(out), bad) {
			t.Fatalf("%s is still on the access list:\n%s", bad, out)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
