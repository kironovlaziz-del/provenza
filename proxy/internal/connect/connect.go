// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

// Package connect: `provenza-proxy connect <client>` - an AI client (Gemini
// CLI, Claude Code, Cursor, any OpenAI client) connected to Provenza in one
// command, as the agent whose identity file it is given:
//
//   - agent mode runs as a service of this user (systemd --user): it signs
//     every request with the agent's key (Ed25519, or Ed25519 + ML-DSA-65)
//     and passes it to the egress proxy;
//   - the client's own configuration gets Provenza's MCP endpoint through
//     agent mode; no key goes into it.
//
// `--remove` takes both out again.
package connect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// EntryName: the MCP server's name in a client's configuration.
const EntryName = "provenza"

// Client: where an AI client keeps its MCP servers, and how Provenza's entry looks there.
type Client struct {
	Name  string
	Title string
	// File: the configuration file under the user's home ("" - nothing is written, see Note)
	File string
	// Entry: the MCP server entry for an endpoint URL
	Entry func(mcpURL string) map[string]any
	// Command: what to run instead of editing a file (Claude Code keeps its own)
	Command func(mcpURL string) []string
	Remove  func() []string
	Note    string
}

// Clients: the clients `connect` knows.
var Clients = map[string]Client{
	"gemini-cli": {Name: "gemini-cli", Title: "Gemini CLI", File: ".gemini/settings.json",
		Entry: func(u string) map[string]any { return map[string]any{"httpUrl": u} }},
	"cursor": {Name: "cursor", Title: "Cursor", File: ".cursor/mcp.json",
		Entry: func(u string) map[string]any { return map[string]any{"url": u} }},
	"claude-code": {Name: "claude-code", Title: "Claude Code",
		Command: func(u string) []string {
			return []string{"claude", "mcp", "add", "--transport", "http", "--scope", "user", EntryName, u}
		},
		Remove: func() []string { return []string{"claude", "mcp", "remove", "--scope", "user", EntryName} }},
	"openai": {Name: "openai", Title: "an OpenAI-compatible client",
		Note: "no configuration file: give the client the base URL and any API key (agent mode sends the agent's)"},
}

// Names of the known clients, sorted.
func Names() []string {
	out := make([]string, 0, len(Clients))
	for n := range Clients {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Options of one `connect` run.
type Options struct {
	Client   Client
	Identity string // the agent's identity file (absolute)
	AgentID  int64
	Proxy    string // the egress proxy agent mode passes requests to
	Port     int    // agent mode's loopback port
	Binary   string // this provenza-proxy (absolute)
	Home     string
	Remove   bool
	Service  bool // run agent mode as a systemd --user service
	Out      io.Writer
	Run      func(name string, args ...string) error // runs a command (systemctl, claude)
}

func (o Options) listen() string   { return "127.0.0.1:" + strconv.Itoa(o.Port) }
func (o Options) base() string     { return "http://" + o.listen() }
func (o Options) MCPURL() string   { return o.base() + "/_mcp" }
func (o Options) LLMURL() string   { return o.base() + "/_llm/v1" }
func (o Options) UnitName() string { return fmt.Sprintf("provenza-agent-%d.service", o.AgentID) }
func (o Options) unitPath() string {
	return filepath.Join(o.Home, ".config", "systemd", "user", o.UnitName())
}

// Unit: the systemd --user unit that runs agent mode for this agent.
func (o Options) Unit() string {
	return fmt.Sprintf(`# Provenza agent mode for agent #%d (provenza-proxy connect): signs every
# request with the agent's key and passes it to the egress proxy.
[Unit]
Description=Provenza agent mode (agent #%d)

[Service]
ExecStart=%s -agent-identity %s -listen %s -upstream %s
Restart=on-failure
RestartSec=2s
NoNewPrivileges=yes

[Install]
WantedBy=default.target
`, o.AgentID, o.AgentID, quote(o.Binary), quote(o.Identity), o.listen(), o.Proxy)
}

func quote(s string) string {
	if strings.ContainsAny(s, " \t\"'\\") {
		return strconv.Quote(s)
	}
	return s
}

// Do connects (or, with Remove, disconnects) the client.
func Do(o Options) error {
	if o.Remove {
		return remove(o)
	}
	if o.Service {
		if err := service(o); err != nil {
			return err
		}
	}
	return configure(o)
}

func (o Options) printf(format string, a ...any) { fmt.Fprintf(o.Out, format, a...) }

// service: the unit written and started; when this user has no systemd
// session (su, a container), what to run instead.
func service(o Options) error {
	if err := portFree(o); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(o.unitPath()), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(o.unitPath(), []byte(o.Unit()), 0o644); err != nil {
		return err
	}
	o.printf("  ✓ agent mode: %s (127.0.0.1:%d -> %s)\n", o.unitPath(), o.Port, o.Proxy)
	err := o.Run("systemctl", "--user", "daemon-reload")
	if err == nil {
		err = o.Run("systemctl", "--user", "enable", o.UnitName())
	}
	if err == nil {
		err = o.Run("systemctl", "--user", "restart", o.UnitName()) // started, or with a changed identity or port
	}
	if err != nil {
		o.printf("  ! systemd --user is not reachable here (%v): start agent mode yourself,\n", err)
		o.printf("    %s -agent-identity %s -listen %s -upstream %s\n", o.Binary, o.Identity, o.listen(), o.Proxy)
		o.printf("    or log in as this user over ssh (not su) and run connect again.\n")
		return nil
	}
	o.printf("  ✓ started: systemctl --user status %s\n", o.UnitName())
	o.printf("    To keep it running after you log out: sudo loginctl enable-linger %s\n", os.Getenv("USER"))
	return nil
}

// portFree: the port is free, or agent mode of this very agent holds it.
func portFree(o Options) error {
	ln, err := net.Listen("tcp", o.listen())
	if err == nil {
		return ln.Close()
	}
	if raw, rerr := os.ReadFile(o.unitPath()); rerr == nil && strings.Contains(string(raw), "-listen "+o.listen()+" ") {
		return nil
	}
	return fmt.Errorf("127.0.0.1:%d is taken by another program: choose another with --port", o.Port)
}

func configure(o Options) error {
	c := o.Client
	switch {
	case c.File != "":
		path := filepath.Join(o.Home, c.File)
		if err := setEntry(path, c.Entry(o.MCPURL())); err != nil {
			o.printf("  ! %s: %v\n", path, err)
			o.printf("    add it by hand under \"mcpServers\": %q: %s\n", EntryName, mustJSON(c.Entry(o.MCPURL())))
			return nil
		}
		o.printf("  ✓ %s: MCP server %q -> %s\n", path, EntryName, o.MCPURL())
	case c.Command != nil:
		cmd := c.Command(o.MCPURL())
		if c.Remove != nil {
			_ = o.Run(c.Remove()[0], c.Remove()[1:]...) // replaced, not added twice
		}
		if err := o.Run(cmd[0], cmd[1:]...); err != nil {
			o.printf("  ! %s (%v): run it yourself:\n    %s\n", cmd[0], err, strings.Join(cmd, " "))
			return nil
		}
		o.printf("  ✓ %s\n", strings.Join(cmd, " "))
	default:
		o.printf("  %s\n", c.Note)
	}
	o.printf("\n  %s talks to Provenza as agent #%d:\n", c.Title, o.AgentID)
	o.printf("    MCP:            %s   (the servers in Gateways -> MCP tools)\n", o.MCPURL())
	o.printf("    OpenAI-style:   base_url %s   (AI connections in Gateways -> AI providers)\n", o.LLMURL())
	o.printf("  Every call is signed with the agent's key, checked against its rights and the\n")
	o.printf("  signed policy, and recorded (Agent activity). Agent mode listens on the loopback:\n")
	o.printf("  any local process that reaches it acts as this agent.\n")
	return nil
}

func remove(o Options) error {
	c := o.Client
	if c.File != "" {
		path := filepath.Join(o.Home, c.File)
		if removed, err := dropEntry(path); err != nil {
			o.printf("  ! %s: %v\n", path, err)
		} else if removed {
			o.printf("  ✓ %s: MCP server %q removed\n", path, EntryName)
		}
	}
	if c.Remove != nil {
		cmd := c.Remove()
		if err := o.Run(cmd[0], cmd[1:]...); err != nil {
			o.printf("  ! %s: run it yourself: %s\n", cmd[0], strings.Join(cmd, " "))
		} else {
			o.printf("  ✓ %s\n", strings.Join(cmd, " "))
		}
	}
	if o.Service {
		if _, err := os.Stat(o.unitPath()); err == nil {
			_ = o.Run("systemctl", "--user", "disable", "--now", o.UnitName())
			if err := os.Remove(o.unitPath()); err != nil {
				return err
			}
			_ = o.Run("systemctl", "--user", "daemon-reload")
			o.printf("  ✓ agent mode stopped and removed (%s)\n", o.UnitName())
		}
	}
	return nil
}

// ---------------------------------------------------------------- client files

// readConfig: a client's JSON configuration ({} when there is none).
func readConfig(path string) (map[string]any, []byte, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{}, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}, raw, nil
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, nil, fmt.Errorf("not plain JSON (comments?), left as it is: %w", err)
	}
	return m, raw, nil
}

// writeConfig: atomically, keeping the file's mode; the first time, the
// original is kept next to it (<file>.provenza-backup).
func writeConfig(path string, m map[string]any, before []byte) error {
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if bytes.Equal(out, before) {
		return nil
	}
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
		backup := path + ".provenza-backup"
		if _, err := os.Stat(backup); errors.Is(err, os.ErrNotExist) && before != nil {
			if err := os.WriteFile(backup, before, mode); err != nil {
				return err
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp-%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, out, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// setEntry: mcpServers.provenza = entry, everything else as it was.
func setEntry(path string, entry map[string]any) error {
	m, before, err := readConfig(path)
	if err != nil {
		return err
	}
	servers, ok := m["mcpServers"].(map[string]any)
	if !ok {
		if m["mcpServers"] != nil {
			return errors.New(`"mcpServers" is not an object`)
		}
		servers = map[string]any{}
	}
	servers[EntryName] = entry
	m["mcpServers"] = servers
	return writeConfig(path, m, before)
}

// dropEntry: mcpServers.provenza taken out; whether it was there.
func dropEntry(path string) (bool, error) {
	m, before, err := readConfig(path)
	if err != nil || before == nil {
		return false, err
	}
	servers, _ := m["mcpServers"].(map[string]any)
	if _, ok := servers[EntryName]; !ok {
		return false, nil
	}
	delete(servers, EntryName)
	return true, writeConfig(path, m, before)
}

func mustJSON(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

// RunCommand: the default Options.Run.
func RunCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return fmt.Errorf("%w: %s", err, firstLine(msg))
		}
		return err
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
