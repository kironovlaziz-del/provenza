// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

//go:build !windows

package egress

import (
	"net"
	"os"
	"syscall"
)

// listenUnix: a unix socket with mode 0600, owner only.
func listenUnix(path string) (net.Listener, error) {
	old := syscall.Umask(0o177) // the socket is created with mode 0600: no moment where others may connect
	l, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// identityFileProblem: the identity file holds the agent's private key and
// must be the owner's alone (mode 600).
func identityFileProblem(path string, st os.FileInfo) error {
	if st.Mode().Perm()&0o077 != 0 {
		return &permError{path: path, msg: "is readable by other users; chmod 600 it (it holds the agent's private key)"}
	}
	return nil
}
