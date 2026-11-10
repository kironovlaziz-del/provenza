// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

//go:build windows

package connect

import (
	"encoding/csv"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// detachAttr: agent mode in the background has no console of its own and is
// not stopped with the window it was started from (DETACHED_PROCESS |
// CREATE_NEW_PROCESS_GROUP).
func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: 0x00000008 | 0x00000200}
}

// procIsAgent: the process exists and is a provenza-proxy (not a number that
// now belongs to something else). Windows lists no command line cheaply, so
// the image name is what is checked.
func procIsAgent(pid int) bool {
	out, err := exec.Command(sys32("tasklist.exe"), "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH").Output()
	if err != nil {
		return false
	}
	rec, err := csv.NewReader(strings.NewReader(string(out))).Read()
	return err == nil && len(rec) > 0 && strings.HasPrefix(strings.ToLower(rec[0]), "provenza-proxy")
}

// procTerminate: the process ends (Windows has no SIGTERM for a background
// process), and a moment for it to go.
func procTerminate(pid int) {
	_ = exec.Command(sys32("taskkill.exe"), "/PID", fmt.Sprint(pid), "/F").Run()
	for i := 0; i < 30; i++ {
		if !procIsAgent(pid) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// unitOwnsPort: there are no units on Windows; a pid file (checked by portFree) is the sign.
func unitOwnsPort(Options) bool { return false }

// service: agent mode started now in the background, and set to start at this
// user's sign-in (the Run key of the user's own registry hive: no
// administrator rights, nothing for other users).
func service(o Options) error {
	if err := portFree(o); err != nil {
		return err
	}
	if err := o.Run(sys32("reg.exe"), o.runKeyAddArgs()...); err != nil {
		o.printf("  ! could not set agent mode to start at sign-in (%v): after a restart, run\n", err)
		o.printf("      %s connect %s\n", quote(o.Binary), o.Client.Name)
	} else {
		o.printf("  ✓ agent mode starts at your sign-in (%s\\%s)\n", runKey, o.runValueName())
	}
	if o.Start == nil {
		o.Start = StartDetached
	}
	pid, err := o.Start(o)
	if err != nil {
		o.printf("  ! agent mode did not start (%v): run it yourself,\n", err)
		o.printf("    %s -agent-identity %s -listen %s -upstream %s\n", winQuote(o.Binary), winQuote(o.Identity), o.listen(), o.Proxy)
		return nil
	}
	o.printf("  ✓ agent mode started in the background (pid %d, 127.0.0.1:%d -> %s, log %s)\n", pid, o.Port, o.Proxy, o.logPath())
	return nil
}

// removeService: the sign-in entry taken away (agent mode itself is stopped by the caller).
func removeService(o Options) error {
	if err := o.Run(sys32("reg.exe"), "query", runKey, "/v", o.runValueName()); err != nil {
		return nil // not set
	}
	if err := o.Run(sys32("reg.exe"), "delete", runKey, "/v", o.runValueName(), "/f"); err != nil {
		return fmt.Errorf("could not remove %s\\%s: %w", runKey, o.runValueName(), err)
	}
	o.printf("  ✓ agent mode no longer starts at sign-in\n")
	return nil
}
