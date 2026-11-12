// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

//go:build windows

package connect

import (
	"io"
	"os/exec"
	"testing"
)

// The sign-in entry of an earlier agent serving the same port is removed from
// this user's real Run key; one of another agent on another port stays.
func TestEarlierSignInEntryIsRemoved(t *testing.T) {
	reg := func(args ...string) error { return exec.Command(sys32("reg.exe"), args...).Run() }
	o := Options{AgentID: 99102, Port: 48480, Proxy: "http://127.0.0.1:8443", Out: io.Discard, Run: RunCommand,
		Binary: `C:\p\provenza-proxy.exe`, Identity: `C:\p\agent-99102.json`}
	earlier, other := o, o
	earlier.AgentID, earlier.Identity = 99101, `C:\p\agent-99101.json` // the same port
	other.AgentID, other.Port, other.Identity = 99100, 48490, `C:\p\agent-99100.json`
	for _, x := range []Options{earlier, other} {
		if err := reg(x.runKeyAddArgs()...); err != nil {
			t.Fatal(err)
		}
		name := x.runValueName()
		t.Cleanup(func() { _ = reg("delete", runKey, "/v", name, "/f") })
	}
	gone := replaceEarlierServices(o)
	if len(gone) != 1 || gone[0] != earlier.AgentID {
		t.Fatalf("removed %v", gone)
	}
	if reg("query", runKey, "/v", earlier.runValueName()) == nil {
		t.Fatal("the earlier entry stays")
	}
	if reg("query", runKey, "/v", other.runValueName()) != nil {
		t.Fatal("the other agent's entry was removed")
	}
}
