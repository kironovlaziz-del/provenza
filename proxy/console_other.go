// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

//go:build !windows

package main

// leaveOwnConsole: only Windows opens a window for agent-start.
func leaveOwnConsole() {}
