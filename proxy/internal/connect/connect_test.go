// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package connect

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type runs struct{ calls []string }

func (r *runs) run(fail string) func(string, ...string) error {
	return func(name string, args ...string) error {
		line := strings.Join(append([]string{name}, args...), " ")
		r.calls = append(r.calls, line)
		if fail != "" && strings.HasPrefix(line, fail) {
			return errors.New("no user bus")
		}
		return nil
	}
}

func opts(t *testing.T, client string, r *runs, fail string) (Options, *bytes.Buffer) {
	t.Helper()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	out := &bytes.Buffer{}
	return Options{Client: Clients[client], Identity: "/home/a/.config/provenza/provenza-agent.json", AgentID: 7,
		Proxy: "http://127.0.0.1:8443", Port: port, Binary: "/usr/local/bin/provenza-proxy", Home: t.TempDir(),
		Service: true, Out: out, Run: r.run(fail)}, out
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestGeminiCLI(t *testing.T) {
	r := &runs{}
	o, out := opts(t, "gemini-cli", r, "")
	settings := filepath.Join(o.Home, ".gemini", "settings.json")
	os.MkdirAll(filepath.Dir(settings), 0o700)
	before := `{"theme": "Dracula", "mcpServers": {"other": {"command": "x"}}}`
	os.WriteFile(settings, []byte(before), 0o640)

	if err := Do(o); err != nil {
		t.Fatal(err)
	}
	m := readJSON(t, settings)
	servers := m["mcpServers"].(map[string]any)
	if m["theme"] != "Dracula" || servers["other"] == nil {
		t.Fatalf("the rest of the settings changed: %v", m)
	}
	if got := servers[EntryName].(map[string]any)["httpUrl"]; got != o.MCPURL() {
		t.Fatalf("entry: %v", got)
	}
	if st, _ := os.Stat(settings); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	if raw, _ := os.ReadFile(settings + ".provenza-backup"); string(raw) != before {
		t.Fatal("no backup of the original")
	}
	unit, err := os.ReadFile(filepath.Join(o.Home, ".config/systemd/user/provenza-agent-7.service"))
	if err != nil || !strings.Contains(string(unit), "ExecStart=/usr/local/bin/provenza-proxy -agent-identity "+
		"/home/a/.config/provenza/provenza-agent.json -listen "+o.listen()+" -upstream http://127.0.0.1:8443\n") {
		t.Fatalf("unit: %v\n%s", err, unit)
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "systemctl --user restart provenza-agent-7.service") {
		t.Fatalf("not started: %v", r.calls)
	}
	if strings.Contains(out.String(), "pvz_") || !strings.Contains(out.String(), o.LLMURL()) {
		t.Fatalf("output: %s", out)
	}

	// again: the same, nothing added twice; then removed, the other server stays
	if err := Do(o); err != nil {
		t.Fatal(err)
	}
	o.Remove = true
	if err := Do(o); err != nil {
		t.Fatal(err)
	}
	servers = readJSON(t, settings)["mcpServers"].(map[string]any)
	if servers[EntryName] != nil || servers["other"] == nil {
		t.Fatalf("after remove: %v", servers)
	}
	if _, err := os.Stat(filepath.Join(o.Home, ".config/systemd/user/provenza-agent-7.service")); err == nil {
		t.Fatal("the unit is still there")
	}
}

func TestNoConfigYetAndNoUserBus(t *testing.T) {
	r := &runs{}
	o, out := opts(t, "cursor", r, "systemctl --user enable")
	if err := Do(o); err != nil {
		t.Fatal(err)
	}
	m := readJSON(t, filepath.Join(o.Home, ".cursor", "mcp.json"))
	if m["mcpServers"].(map[string]any)[EntryName].(map[string]any)["url"] != o.MCPURL() {
		t.Fatalf("%v", m)
	}
	if !strings.Contains(out.String(), "-agent-identity") || !strings.Contains(out.String(), "systemd --user is not reachable") {
		t.Fatalf("no fallback command: %s", out)
	}
}

func TestAFileItCannotReadIsLeftAlone(t *testing.T) {
	r := &runs{}
	o, out := opts(t, "gemini-cli", r, "")
	o.Service = false
	settings := filepath.Join(o.Home, ".gemini", "settings.json")
	os.MkdirAll(filepath.Dir(settings), 0o700)
	commented := "{\n  // mine\n  \"theme\": \"x\"\n}\n"
	os.WriteFile(settings, []byte(commented), 0o600)
	if err := Do(o); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(settings); string(raw) != commented {
		t.Fatal("a file with comments was rewritten")
	}
	if !strings.Contains(out.String(), `"httpUrl"`) {
		t.Fatalf("no snippet to add by hand: %s", out)
	}
}

func TestClaudeCodeUsesItsOwnCommand(t *testing.T) {
	r := &runs{}
	o, _ := opts(t, "claude-code", r, "")
	o.Service = false
	if err := Do(o); err != nil {
		t.Fatal(err)
	}
	want := "claude mcp add --transport http --scope user provenza " + o.MCPURL()
	if r.calls[len(r.calls)-1] != want {
		t.Fatalf("%v", r.calls)
	}
}

func TestAPortTakenByAnotherProgram(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	r := &runs{}
	o, _ := opts(t, "gemini-cli", r, "")
	o.Port = ln.Addr().(*net.TCPAddr).Port
	if err := Do(o); err == nil || !strings.Contains(err.Error(), "--port") {
		t.Fatalf("%v", err)
	}
}
