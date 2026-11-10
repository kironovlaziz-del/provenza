// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	getConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	freeConsole           = kernel32.NewProc("FreeConsole")
)

// leaveOwnConsole: when the console window was made for this process alone
// (agent-start run at sign-in), it is let go and the window closes at once -
// nobody can close it by hand while agent mode is still starting. Run from a
// terminal, the terminal's console is shared and stays.
func leaveOwnConsole() {
	var ids [2]uint32
	n, _, _ := getConsoleProcessList.Call(uintptr(unsafe.Pointer(&ids[0])), uintptr(len(ids)))
	if n == 1 {
		freeConsole.Call()
	}
}
