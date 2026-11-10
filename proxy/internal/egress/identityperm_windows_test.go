// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

//go:build windows

package egress

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// identityFileProblem on a real Windows access list: a file Everyone can read
// is refused, one reset the way the message says is accepted.
func TestIdentityFileProblemOnWindows(t *testing.T) {
	p := filepath.Join(t.TempDir(), "provenza-agent.json")
	if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
			t.Fatalf("icacls %v: %v %s", args, err, out)
		}
	}
	run(p, "/grant", "*S-1-1-0:R") // Everyone
	st, _ := os.Stat(p)
	if err := identityFileProblem(p, st); err == nil {
		t.Fatal("a file Everyone can read was accepted")
	}
	if err := exec.Command("cmd", "/c", strings.TrimSpace(fixCommand(p))).Run(); err != nil {
		t.Fatalf("the reset command in the message does not work: %v", err)
	}
	if err := identityFileProblem(p, st); err != nil {
		t.Fatalf("a file reset as the message says was refused: %v", err)
	}
}
