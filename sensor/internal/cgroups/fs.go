// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package cgroups

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ID is the cgroup's 64-bit id, the value the kernel program sees.
func ID(dir string) (uint64, error) {
	h, _, err := unix.NameToHandleAt(unix.AT_FDCWD, dir, 0)
	if err != nil {
		return 0, err
	}
	b := h.Bytes()
	if len(b) < 8 {
		return 0, fmt.Errorf("%s: short cgroup handle", dir)
	}
	return binary.NativeEndian.Uint64(b[:8]), nil
}

// Of is the cgroup v2 path of a process, relative to the root ("a/b").
func Of(pid string) (string, error) {
	f, err := os.Open(filepath.Join("/proc", pid, "cgroup"))
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "0::"); ok {
			return strings.Trim(rest, "/"), nil
		}
	}
	return "", errors.New("no cgroup v2 entry")
}

// Dir is one cgroup directory found by Walk.
type Dir struct {
	Rel string // relative to the root, no leading slash
	ID  uint64
	UID uint32 // owner of the directory
}

// Walk lists every cgroup under root.
func Walk(root string) ([]Dir, error) {
	var out []Dir
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root {
				return err
			}
			return nil // removed meanwhile
		}
		if !d.IsDir() || p == root {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		id, err := ID(p)
		if err != nil {
			return nil
		}
		var st unix.Stat_t
		owner := uint32(0)
		if unix.Stat(p, &st) == nil {
			owner = st.Uid
		}
		out = append(out, Dir{Rel: filepath.ToSlash(rel), ID: id, UID: owner})
		return nil
	})
	return out, err
}

// Under is where root sits inside its cgroup v2 hierarchy ("" when root is the
// mount point itself): the kernel names cgroups by their path in the
// hierarchy, Walk by their path under root.
func Under(root string) string {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return ""
	}
	defer f.Close()
	return under(f, root)
}

func under(mountinfo io.Reader, root string) string {
	root = filepath.Clean(root)
	best := ""
	sc := bufio.NewScanner(mountinfo)
	for sc.Scan() {
		// id parent major:minor root mountpoint options ... - fstype source options
		fields := strings.Fields(sc.Text())
		sep := -1
		for i, x := range fields {
			if x == "-" {
				sep = i
				break
			}
		}
		if sep < 5 || sep+1 >= len(fields) || fields[sep+1] != "cgroup2" {
			continue
		}
		mp := filepath.Clean(fields[4])
		if (root == mp || strings.HasPrefix(root, mp+"/")) && len(mp) > len(best) {
			best = mp
		}
	}
	if best == "" {
		return ""
	}
	return strings.Trim(strings.TrimPrefix(root, best), "/")
}
