// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package connect

import (
	"strings"
	"testing"
)

func TestWinQuote(t *testing.T) {
	for in, want := range map[string]string{
		`plain`:                      `plain`,
		``:                           `""`,
		`C:\Program Files\x\p.exe`:   `"C:\Program Files\x\p.exe"`,
		`C:\dir with space\`:         `"C:\dir with space\\"`,
		`a"b`:                        `"a\"b"`,
		`a\"b`:                       `"a\\\"b"`,
		"tab\there":                  "\"tab\there\"",
		`http://127.0.0.1:8443`:      `http://127.0.0.1:8443`,
		`C:\Users\Ann Lee\.config\p`: `"C:\Users\Ann Lee\.config\p"`,
	} {
		if got := winQuote(in); got != want {
			t.Errorf("winQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestAutostartCommandAndRunKey(t *testing.T) {
	o := Options{AgentID: 7, Port: 8480, Proxy: "http://127.0.0.1:8443",
		Binary:   `C:\Users\Ann Lee\AppData\Local\provenza\provenza-proxy.exe`,
		Identity: `C:\Users\Ann Lee\.config\provenza\provenza-agent.json`}
	want := `"C:\Users\Ann Lee\AppData\Local\provenza\provenza-proxy.exe" agent-start -agent-id 7 ` +
		`-identity "C:\Users\Ann Lee\.config\provenza\provenza-agent.json" -port 8480 -proxy http://127.0.0.1:8443`
	if got := o.AutostartCommand(); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	args := o.runKeyAddArgs()
	if strings.Join(args[:6], " ") != `add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v ProvenzaAgent7 /t REG_SZ` ||
		args[6] != "/d" || args[7] != want || args[8] != "/f" {
		t.Fatalf("reg arguments: %q", args)
	}
	// only this user's hive: no machine-wide key
	if strings.Contains(strings.Join(args, " "), "HKLM") {
		t.Fatal("must not write machine-wide")
	}
}
