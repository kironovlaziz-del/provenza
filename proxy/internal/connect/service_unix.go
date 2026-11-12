// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

//go:build !windows

package connect

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// detachAttr: agent mode in the background gets a session of its own.
func detachAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }

// procIsAgent: the process exists and is an agent mode (not a number that now
// belongs to something else).
func procIsAgent(pid int) bool {
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	return err == nil && strings.Contains(string(cmdline), "-agent-identity")
}

// procTerminate: SIGTERM, and a moment for it to go.
func procTerminate(pid int) {
	p, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = p.Signal(syscall.SIGTERM)
	for i := 0; i < 30; i++ {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// unitOwnsPort: the unit of this very agent is the one listening on the port.
func unitOwnsPort(o Options) bool {
	raw, err := os.ReadFile(o.unitPath())
	return err == nil && strings.Contains(string(raw), "-listen "+o.listen()+" ")
}

// service: the unit written and started; when this user has no systemd
// session (su, a container), what to run instead.
func service(o Options) error {
	replaceEarlier(o)
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
		// no systemd session for this user (su, sudo -u, a container): run it in the background now
		if o.Start == nil {
			o.Start = StartDetached
		}
		pid, serr := o.Start(o)
		if serr != nil {
			o.printf("  ! systemd --user is not reachable here (%v), and agent mode did not start (%v): run it yourself,\n", err, serr)
			o.printf("    %s -agent-identity %s -listen %s -upstream %s\n", o.Binary, o.Identity, o.listen(), o.Proxy)
			return nil
		}
		o.printf("  ✓ agent mode started in the background (pid %d, log %s)\n", pid, o.logPath())
		o.printf("    Without a systemd session for this user it does not come back after a restart: then run\n")
		o.printf("      %s connect %s\n", o.Binary, o.Client.Name)
		o.printf("    or, once, as root: loginctl enable-linger %s - and log in as %s over ssh, not su.\n", userName(), userName())
		return nil
	}
	o.printf("  ✓ started: systemctl --user status %s\n", o.UnitName())
	o.printf("    To keep it running after you log out, once, as root: loginctl enable-linger %s\n", userName())
	return nil
}

// removeService: the unit stopped and taken away.
func removeService(o Options) error {
	if _, err := os.Stat(o.unitPath()); err == nil {
		_ = o.Run("systemctl", "--user", "disable", "--now", o.UnitName())
		if err := os.Remove(o.unitPath()); err != nil {
			return err
		}
		_ = o.Run("systemctl", "--user", "daemon-reload")
		o.printf("  ✓ agent mode stopped and removed (%s)\n", o.UnitName())
	}
	return nil
}

// killTree: the process (a client command that did not finish).
func killTree(p *os.Process) error { return p.Kill() }

// procServes: the agent mode with this pid listens on o's address or signs with o's identity file.
func procServes(pid int, o Options) bool {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-listen" && args[i+1] == o.listen() ||
			args[i] == "-agent-identity" && samePath(args[i+1], o.Identity) {
			return true
		}
	}
	return false
}

// agentModesServing: this user's agent modes that serve o (only this user's
// processes: another user's cmdline is readable, so the owner is checked).
func agentModesServing(o Options) []int {
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	var out []int
	for _, d := range dirs {
		pid, err := strconv.Atoi(filepath.Base(d))
		if err != nil || pid < 2 {
			continue
		}
		st, err := os.Stat(d)
		if err != nil {
			continue
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); !ok || int(sys.Uid) != os.Getuid() {
			continue
		}
		if procIsAgent(pid) && procServes(pid, o) {
			out = append(out, pid)
		}
	}
	return out
}

// replaceEarlierServices: the units of earlier agents serving o, stopped and removed.
func replaceEarlierServices(o Options) []int64 {
	units, _ := filepath.Glob(filepath.Join(filepath.Dir(o.unitPath()), "provenza-agent-*.service"))
	var gone []int64
	for _, u := range units {
		id := numberIn(filepath.Base(u), "provenza-agent-", ".service")
		if id == 0 || id == o.AgentID {
			continue
		}
		raw, err := os.ReadFile(u)
		if err != nil {
			continue
		}
		exec := ""
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "ExecStart=") {
				exec = strings.TrimPrefix(line, "ExecStart=")
			}
		}
		if !servesSame(exec, o, "-listen", "", "-agent-identity") {
			continue
		}
		_ = o.Run("systemctl", "--user", "disable", "--now", filepath.Base(u))
		if os.Remove(u) == nil {
			gone = append(gone, id)
		}
	}
	if len(gone) > 0 {
		_ = o.Run("systemctl", "--user", "daemon-reload")
	}
	return gone
}
