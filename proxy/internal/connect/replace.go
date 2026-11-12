// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package connect

// An earlier agent of this user on this machine.
//
// `connect` with a new enrollment token makes a new agent, and its identity is
// written where the earlier one's was. The earlier agent's agent mode then
// either keeps the port (the new one cannot start) or, after the next sign-in,
// comes back with the new identity on the same port. So before the new agent
// mode starts, `connect` takes away what this user set up for an earlier agent
// that uses the same port or the same identity file:
//
//   - the process (agent mode started without systemd, or by hand);
//   - its sign-in entry (Windows) or its systemd --user unit;
//   - its pid file.
//
// Only this user's own things are touched, and only an agent mode (a
// provenza-proxy started with -agent-identity): an agent mode of another
// agent on another port, with another identity file, is left alone; so is
// any other program on the port, which still ends `connect` with the message
// to choose another port.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// replaceEarlier stops and removes the agent mode of an earlier agent that
// serves the same port or identity file as o. It never fails `connect`: what
// it cannot remove, the port check after it reports.
func replaceEarlier(o Options) {
	for _, id := range replaceEarlierServices(o) {
		o.printf("  ✓ the earlier agent #%d no longer starts here (this machine's agent is now #%d)\n", id, o.AgentID)
	}
	files, _ := filepath.Glob(filepath.Join(o.stateDir(), "agent-*.pid"))
	for _, f := range files {
		id := numberIn(filepath.Base(f), "agent-", ".pid")
		if id == 0 || id == o.AgentID {
			continue
		}
		pid := readPid(f)
		if pid < 2 || !procIsAgent(pid) {
			_ = os.Remove(f) // nothing runs under it any more
			continue
		}
		if procServes(pid, o) {
			procTerminate(pid)
			_ = os.Remove(f)
			o.printf("  ✓ stopped the agent mode of the earlier agent #%d (pid %d)\n", id, pid)
		}
	}
	// one started by hand, or whose pid file is gone: found by what it serves
	// (not when this agent's own unit runs it: systemctl restarts that one)
	if unitOwnsPort(o) {
		return
	}
	for _, pid := range agentModesServing(o) {
		if pid == os.Getpid() || pid == readPid(o.pidPath()) {
			continue // this very agent's own: StartDetached replaces it
		}
		procTerminate(pid)
		o.printf("  ✓ stopped an earlier agent mode on %s (pid %d)\n", o.listen(), pid)
	}
}

// numberIn: N in <prefix>N<suffix> (0: not that shape).
func numberIn(s, prefix, suffix string) int64 {
	if !strings.HasPrefix(s, prefix) || !strings.HasSuffix(s, suffix) || len(s) <= len(prefix)+len(suffix) {
		return 0
	}
	n, err := strconv.ParseInt(s[len(prefix):len(s)-len(suffix)], 10, 64)
	if err != nil || n < 1 {
		return 0
	}
	return n
}

func readPid(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0
	}
	return pid
}

// servesSame: a command line (a unit's ExecStart, a sign-in entry) of an agent
// mode serving o's port or o's identity file.
func servesSame(cmdline string, o Options, listenFlag, portFlag, identityFlag string) bool {
	fields := splitArgs(cmdline)
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case listenFlag:
			if listenFlag != "" && fields[i+1] == o.listen() {
				return true
			}
		case portFlag:
			if portFlag != "" && fields[i+1] == strconv.Itoa(o.Port) {
				return true
			}
		case identityFlag:
			if samePath(fields[i+1], o.Identity) {
				return true
			}
		}
	}
	return false
}

func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if filepath.Separator == '\\' || strings.Contains(a, `\`) {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// splitArgs: a command line as written by Unit() or AutostartCommand()
// (arguments separated by spaces, an argument with spaces in double quotes).
func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote, have := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) && s[i+1] == '"':
			cur.WriteByte('"')
			i++
			have = true
		case c == '"':
			inQuote = !inQuote
			have = true
		case (c == ' ' || c == '\t') && !inQuote:
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteByte(c)
			have = true
		}
	}
	if have {
		out = append(out, cur.String())
	}
	return out
}
