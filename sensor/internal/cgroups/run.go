// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package cgroups

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// RunPrefix names the cgroups made for `provenza-sensor run --agent N`:
// provenza-agent-<N>-<random>, created by the sensor (owned by root).
const RunPrefix = "provenza-agent-"

var runName = regexp.MustCompile(`^provenza-agent-([0-9]{1,12})-[0-9a-f]{16}$`)

// RunAgent returns the agent id a run cgroup was made for, if rel is one.
func RunAgent(rel string, owner uint32) (int64, bool) {
	if owner != 0 {
		return 0, false // only the sensor (root) creates them
	}
	m := runName.FindStringSubmatch(filepath.Base(rel))
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	return n, err == nil
}

// NewRun creates a run cgroup next to the process's own cgroup (so systemd
// still sees the unit as running), or under <root>/provenza.slice when that
// is not possible. Returns its path relative to root.
func NewRun(root, parentRel string, agentID int64) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s%d-%s", RunPrefix, agentID, hex.EncodeToString(b))
	try := []string{}
	if p := strings.Trim(parentRel, "/"); p != "" {
		try = append(try, p)
	}
	try = append(try, "provenza.slice")
	var lastErr error
	for _, parent := range try {
		dir := filepath.Join(root, parent)
		if parent == "provenza.slice" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				lastErr = err
				continue
			}
		}
		full := filepath.Join(dir, name)
		if err := os.Mkdir(full, 0o755); err != nil {
			lastErr = err
			continue
		}
		return filepath.ToSlash(filepath.Join(parent, name)), nil
	}
	return "", fmt.Errorf("creating a cgroup for the agent: %w", lastErr)
}

// Move puts a process into the cgroup.
func Move(root, rel string, pid int) error {
	return os.WriteFile(filepath.Join(root, rel, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644)
}

// Empty reports whether no process is left in the cgroup.
func Empty(root, rel string) bool {
	data, err := os.ReadFile(filepath.Join(root, rel, "cgroup.events"))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "populated 0")
}

// Remove deletes an empty run cgroup.
func Remove(root, rel string) error {
	return os.Remove(filepath.Join(root, rel))
}
