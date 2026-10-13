// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

// Package cgroups matches cgroup paths against workload patterns.
package cgroups

import (
	"path"
	"strings"
)

// Pattern is one workload pattern ("system.slice/billing-agent.service"),
// relative to the cgroup root, with shell wildcards per segment.
type Pattern struct {
	Raw      string
	Segments []string
	Literal  bool
	Workload uint32
}

func NewPattern(raw string, workload uint32) Pattern {
	raw = strings.Trim(raw, "/")
	segs := strings.Split(raw, "/")
	lit := !strings.ContainsAny(raw, "*?[\\")
	return Pattern{Raw: raw, Segments: segs, Literal: lit, Workload: workload}
}

// Match reports whether rel ("a/b/c", no leading slash) is the pattern.
func (p Pattern) Match(rel string) bool {
	parts := strings.Split(strings.Trim(rel, "/"), "/")
	if len(parts) != len(p.Segments) {
		return false
	}
	for i, seg := range p.Segments {
		ok, err := path.Match(seg, parts[i])
		if err != nil || !ok {
			return false
		}
	}
	return true
}

// Parent is the pattern without its last segment ("" for top level).
func (p Pattern) Parent() Pattern {
	if len(p.Segments) <= 1 {
		return Pattern{Workload: p.Workload, Literal: true}
	}
	return NewPattern(strings.Join(p.Segments[:len(p.Segments)-1], "/"), p.Workload)
}

// KernelPath is how the cgroup_mkdir tracepoint spells a path.
func KernelPath(rel string) string {
	rel = strings.Trim(rel, "/")
	if rel == "" {
		return ""
	}
	return "/" + rel
}
