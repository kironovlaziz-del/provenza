// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

//go:build !windows

package connect

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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
	o.Start = func(Options) (int, error) { return 4242, nil }
	if err := Do(o); err != nil {
		t.Fatal(err)
	}
	m := readJSON(t, filepath.Join(o.Home, ".cursor", "mcp.json"))
	if m["mcpServers"].(map[string]any)[EntryName].(map[string]any)["url"] != o.MCPURL() {
		t.Fatalf("%v", m)
	}
	if !strings.Contains(out.String(), "started in the background (pid 4242") {
		t.Fatalf("not started without systemd: %s", out)
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

// A client's command that does not finish (waiting for a prompt, or another
// program of that name) is stopped: connect goes on and says what to run.
func TestRunCommandStopsAHangingClient(t *testing.T) {
	old := commandTimeout
	commandTimeout = 300 * time.Millisecond
	defer func() { commandTimeout = old }()
	started := time.Now()
	err := RunCommand("sleep", "30")
	if err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("err = %v", err)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatalf("waited %s", time.Since(started))
	}
	if err := RunCommand("true"); err != nil {
		t.Fatal(err)
	}
}

// A new enrollment on a machine with an earlier agent of this user: the
// earlier agent mode (its unit, its process) serving the same port or identity
// file is replaced; an agent mode of another agent on another port, with
// another identity file, is left alone.
func TestAnEarlierAgentIsReplaced(t *testing.T) {
	r := &runs{}
	o, out := opts(t, "gemini-cli", r, "")
	unitDir := filepath.Dir(o.unitPath())
	os.MkdirAll(unitDir, 0o755)
	earlier, other := o, o
	earlier.AgentID = 6
	other.AgentID, other.Port, other.Identity = 5, o.Port+1, "/home/a/other/agent.json"
	os.WriteFile(earlier.unitPath(), []byte(earlier.Unit()), 0o644)
	os.WriteFile(other.unitPath(), []byte(other.Unit()), 0o644)

	// agent modes as processes: the earlier one (pid file) and the other one
	start := func(x Options) *exec.Cmd {
		c := exec.Command("sh", "-c", "sleep 30", "sh", "-agent-identity", x.Identity, "-listen", x.listen())
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Process.Kill(); c.Wait() })
		return c
	}
	pe, po := start(earlier), start(other)
	os.MkdirAll(o.stateDir(), 0o700)
	os.WriteFile(earlier.pidPath(), []byte(strconv.Itoa(pe.Process.Pid)+"\n"), 0o600)
	waited := make(chan error, 1)
	go func() { waited <- pe.Wait() }()

	if err := Do(o); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(earlier.unitPath()); !os.IsNotExist(err) {
		t.Fatalf("the earlier unit stays: %v", err)
	}
	if _, err := os.Stat(other.unitPath()); err != nil {
		t.Fatalf("the other agent's unit was removed: %v", err)
	}
	calls := strings.Join(r.calls, "\n")
	if !strings.Contains(calls, "systemctl --user disable --now provenza-agent-6.service") ||
		strings.Contains(calls, "provenza-agent-5.service") {
		t.Fatalf("calls:\n%s", calls)
	}
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("the earlier agent mode still runs")
	}
	if _, err := os.Stat(earlier.pidPath()); !os.IsNotExist(err) {
		t.Fatal("the earlier pid file stays")
	}
	if !procIsAgent(po.Process.Pid) {
		t.Fatal("the other agent's agent mode was stopped")
	}
	if !strings.Contains(out.String(), "the earlier agent #6 no longer starts here (this machine's agent is now #7)") ||
		!strings.Contains(out.String(), "stopped the agent mode of the earlier agent #6") {
		t.Fatalf("output:\n%s", out.String())
	}
}
