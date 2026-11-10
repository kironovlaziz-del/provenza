// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

//go:build !windows

package connect

// protectFile: nothing to add: the file was created with mode 600.
func protectFile(string) error { return nil }
