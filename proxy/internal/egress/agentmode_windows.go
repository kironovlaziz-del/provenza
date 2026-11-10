// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

//go:build windows

package egress

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// listenUnix: not on Windows. A unix socket there carries no owner-only
// guarantee that this code could check, so agent mode listens on the
// loopback instead (-listen 127.0.0.1:<port>).
func listenUnix(string) (net.Listener, error) {
	return nil, errors.New("agent mode on Windows listens on the loopback (-listen 127.0.0.1:<port>), not on a unix socket")
}

// identityFileProblem: the identity file holds the agent's private key. On
// Windows its access list must name only this user, SYSTEM and the
// administrators: `provenza-proxy enroll` sets exactly that, and this
// check refuses a file that anyone else - Everyone, Users, Authenticated
// Users - could read. It cannot tell, so it refuses: a file whose access list
// could not be read is not accepted.
func identityFileProblem(path string, _ os.FileInfo) error {
	cmd := exec.Command(system32(`WindowsPowerShell\v1.0\powershell.exe`), "-NoProfile", "-NonInteractive", "-Command",
		"$p=$env:PROVENZA_ACL_PATH; (Get-Acl -LiteralPath $p).Sddl; "+
			"[Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
	cmd.Env = append(os.Environ(), "PROVENZA_ACL_PATH="+path)
	out, err := cmd.Output()
	if err != nil {
		return &permError{path: path, msg: "its access list could not be read (" + err.Error() + "); reset it with: " + fixCommand(path)}
	}
	lines := strings.Fields(strings.TrimSpace(string(out)))
	if len(lines) != 2 {
		return &permError{path: path, msg: "its access list could not be read; reset it with: " + fixCommand(path)}
	}
	if err := sddlProblem(lines[0], lines[1]); err != nil {
		return &permError{path: path, msg: err.Error() + "; reset it with: " + fixCommand(path)}
	}
	return nil
}

func fixCommand(path string) string {
	return `icacls "` + path + `" /inheritance:r /grant:r "%USERNAME%:F"`
}

// system32: a tool of Windows itself, by its full path, not by name from the
// PATH (which may hold another program of that name first).
func system32(rel string) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", rel)
}
