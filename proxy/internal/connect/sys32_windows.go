// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

//go:build windows

package connect

import (
	"os"
	"path/filepath"
)

// sys32: a tool of Windows itself, by its full path. Not by name from the
// PATH: a PATH may hold another program of that name first (Git for Windows
// has its own `whoami`), or one a user could put there.
func sys32(name string) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", name)
}
