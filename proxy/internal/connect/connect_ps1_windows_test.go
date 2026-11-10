// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

//go:build windows

package connect

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The one command of Agents -> Connect on Windows, end to end: the real
// connect.ps1 of the backend, in Windows PowerShell, against a stand-in for
// the server (the downloads, and the enrollment API of enroll_test.go), with
// the real provenza-proxy.exe it downloads. Needs the binary:
//
//	PROVENZA_E2E_PROXY_EXE=<built provenza-proxy.exe> go test -run ConnectPS1 ./internal/connect/
//
// It writes the sign-in entry (HKCU...\Run) of the machine it runs on and
// starts agent mode: meant for CI, and it takes both away at the end.

const ps1Source = "../../../backend/app/api/connect_script.py"

// renderPS1: SCRIPT_PS1 of the backend, with the server's address in it.
func renderPS1(t *testing.T, server string) string {
	t.Helper()
	raw, err := os.ReadFile(ps1Source)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	const open = `SCRIPT_PS1 = r"""`
	i := strings.Index(s, open)
	if i < 0 {
		t.Fatal("SCRIPT_PS1 not found in connect_script.py")
	}
	s = s[i+len(open):]
	s = s[:strings.Index(s, `"""`)]
	s = strings.ReplaceAll(s, "@SERVER@", server)
	return strings.ReplaceAll(s, "@CLIENTS_PS@", "'gemini-cli','claude-code','cursor','openai'")
}

func TestConnectPS1EndToEnd(t *testing.T) {
	exe := os.Getenv("PROVENZA_E2E_PROXY_EXE")
	if exe == "" {
		t.Skip("PROVENZA_E2E_PROXY_EXE (a built provenza-proxy.exe) is not set")
	}
	binary, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(binary)
	const name = "provenza-proxy-windows-amd64.exe"
	sums := hex.EncodeToString(sum[:]) + "  " + name + "\n"

	// the stand-in server: the downloads, and the enrollment API of the fake in enroll_test.go
	enroll, _ := fakeEnrollment(t, true, "new", "")
	target, _ := url.Parse(enroll.URL)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/egress-sensor/download/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sums)) })
	mux.HandleFunc("/api/v1/egress-sensor/download/"+name, func(w http.ResponseWriter, r *http.Request) { w.Write(binary) })
	mux.Handle("/", httputil.NewSingleHostReverseProxy(target))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	root := t.TempDir()
	home, local := filepath.Join(root, "home"), filepath.Join(root, "local")
	script := filepath.Join(root, "connect.ps1")
	if err := os.WriteFile(script, []byte(renderPS1(t, srv.URL)), 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "USERPROFILE="+home, "LOCALAPPDATA="+local)
	installed := filepath.Join(local, "provenza", "provenza-proxy.exe")
	identity := filepath.Join(home, ".config", "provenza", "provenza-agent.json")

	remove := func() ([]byte, error) {
		cmd := exec.Command(installed, "connect", "cursor", "--remove")
		cmd.Env = env
		return cmd.CombinedOutput()
	}
	t.Cleanup(func() {
		if _, err := os.Stat(installed); err == nil {
			remove()
		}
	})

	run := func() string {
		t.Helper()
		cmd := exec.Command(sys32(`WindowsPowerShell\v1.0\powershell.exe`), "-NoProfile", "-NonInteractive",
			"-ExecutionPolicy", "Bypass", "-File", script, "-Client", "cursor", "-Token", "pvz_enr_good")
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("connect.ps1: %v\n%s", err, out)
		}
		return string(out)
	}
	hasRunKey := func() bool {
		return exec.Command(sys32("reg.exe"), "query", runKey, "/v", "ProvenzaAgent31").Run() == nil
	}
	listening := func() bool {
		c, err := net.DialTimeout("tcp", "127.0.0.1:8480", time.Second)
		if err == nil {
			c.Close()
		}
		return err == nil
	}
	waitFor := func(what string, want bool, f func() bool) {
		t.Helper()
		for i := 0; i < 50; i++ {
			if f() == want {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatalf("%s: not %v after 10 s", what, want)
	}

	out := run()
	for _, step := range []string{"Downloading provenza-proxy", "Enrolling the agent", "Connecting cursor"} {
		if !strings.Contains(out, step) {
			t.Fatalf("no %q in the output:\n%s", step, out)
		}
	}
	if strings.Contains(out, "pvz_enr_good") {
		t.Fatalf("the token is in the output:\n%s", out)
	}
	// 1. the identity file is this user's alone
	if _, err := os.Stat(identity); err != nil {
		t.Fatalf("no identity file: %v\n%s", err, out)
	}
	acl, _ := exec.Command(sys32("icacls.exe"), identity).CombinedOutput()
	for _, bad := range []string{"Everyone", `BUILTIN\Users`, "Authenticated Users"} {
		if strings.Contains(string(acl), bad) {
			t.Fatalf("%s is on the identity file's access list:\n%s", bad, acl)
		}
	}
	// 2. the client is connected
	mcp, err := os.ReadFile(filepath.Join(home, ".cursor", "mcp.json"))
	if err != nil || !strings.Contains(string(mcp), EntryName) {
		t.Fatalf("no %q entry in the client's file: %v\n%s", EntryName, err, mcp)
	}
	// 3. agent mode runs, and starts at sign-in
	waitFor("agent mode listening", true, listening)
	if !hasRunKey() {
		t.Fatalf("no sign-in entry\n%s", out)
	}
	// 4. the same command again, while agent mode holds the installed file: it stops it, installs, starts it again
	out = run()
	if !strings.Contains(out, "ok ") {
		t.Fatalf("second run:\n%s", out)
	}
	waitFor("agent mode listening again", true, listening)

	// 5. taken out again
	if o, err := remove(); err != nil {
		t.Fatalf("connect --remove: %v\n%s", err, o)
	}
	waitFor("sign-in entry removed", false, hasRunKey)
	waitFor("agent mode stopped", false, listening)
	mcp, _ = os.ReadFile(filepath.Join(home, ".cursor", "mcp.json"))
	if strings.Contains(string(mcp), `"`+EntryName+`"`) {
		t.Fatalf("the client's entry is still there:\n%s", mcp)
	}
}
