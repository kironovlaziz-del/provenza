// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package dnsproxy

import "strings"

// Names is the set of names a workload may resolve: exact names and
// "*.suffix" (any name below suffix, not suffix itself).
type Names struct {
	exact    map[string]bool
	suffixes []string
}

func NewNames(list []string) Names {
	n := Names{exact: map[string]bool{}}
	for _, s := range list {
		s = Canonical(s)
		if s == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(s, "*."); ok {
			n.suffixes = append(n.suffixes, "."+rest)
		} else {
			n.exact[s] = true
		}
	}
	return n
}

func (n Names) Allows(name string) bool {
	name = Canonical(name)
	if n.exact[name] {
		return true
	}
	for _, s := range n.suffixes {
		if strings.HasSuffix(name, s) && len(name) > len(s) {
			return true
		}
	}
	return false
}

// Canonical: lower case, no trailing dot.
func Canonical(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}
