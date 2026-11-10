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
)

// protectFile: the file holds the agent's private key. A file created in the
// user's profile inherits the profile's access list; this removes the
// inheritance and leaves this user alone on it (administrators and the system
// keep the rights Windows gives them anyway). When it cannot be done the
// enrollment fails: a key that others may read is not left behind.
func protectFile(path string) error {
	out, err := exec.Command(sys32("whoami.exe"), "/user", "/fo", "csv", "/nh").Output()
	if err != nil {
		return fmt.Errorf("could not tell which user this is: %w", err)
	}
	rec, err := csv.NewReader(strings.NewReader(string(out))).Read()
	if err != nil || len(rec) != 2 || !strings.HasPrefix(rec[1], "S-1-") {
		return fmt.Errorf("could not tell which user this is (whoami: %q)", strings.TrimSpace(string(out)))
	}
	if b, err := exec.Command(sys32("icacls.exe"), path, "/inheritance:r", "/grant:r", "*"+rec[1]+":F").CombinedOutput(); err != nil {
		return fmt.Errorf("could not restrict %s to this user (icacls: %s): %w", path, strings.TrimSpace(string(b)), err)
	}
	return nil
}
