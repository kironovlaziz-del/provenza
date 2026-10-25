// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package cgroups

import (
	"strings"
	"testing"
)

func TestUnder(t *testing.T) {
	mi := strings.Join([]string{
		"25 1 0:22 / /sys/fs/cgroup rw,nosuid shared:4 - tmpfs tmpfs rw",
		"26 25 0:23 / /sys/fs/cgroup/unified rw,nosuid shared:5 - cgroup2 cgroup2 rw",
		"27 25 0:24 / /sys/fs/cgroup/cpu rw,nosuid shared:6 - cgroup cgroup rw,cpu",
	}, "\n")
	for root, want := range map[string]string{
		"/sys/fs/cgroup/unified":       "",
		"/sys/fs/cgroup/unified/":      "",
		"/sys/fs/cgroup/unified/pvz/a": "pvz/a",
		"/sys/fs/cgroup/unifiedX":      "",
		"/sys/fs/cgroup/cpu/x":         "",
		"/elsewhere":                   "",
	} {
		if got := under(strings.NewReader(mi), root); got != want {
			t.Errorf("%s: %q, want %q", root, got, want)
		}
	}
}
