// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

// Workloads under the signed policy (docs/pvp/edge.md, section 5). The
// policy the server sends a sensor is not signed; with policy.pin, each
// workload the verified release names is held to it - the server's version
// may be tighter, never looser:
//
//   - a destination (or source) is let through only when the signed workload
//     allows it too: inside one of its networks, the same host name (or under
//     its "*." name), the same protocol, a port it allows;
//   - the stricter mode wins (enforce over alert over observe), isolation by
//     either side holds, "listed" DNS wins over "any";
//   - its cgroup patterns, users and agent are the signed ones, and they come
//     first: the server can add patterns, users and workloads (governing more
//     is tighter), but cannot take a cgroup or a user away from a signed
//     workload, nor stop governing one by dropping or disabling the workload.
//
// A workload the release does not name is applied as the server sends it: it
// governs what was not governed at all.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/kironovlaziz-del/provenza/sensor/internal/config"
	"github.com/kironovlaziz-del/provenza/sensor/internal/trust"
)

// signedWorkloads: the enabled workloads of a verified release; ok false when
// the release predates signed workloads.
func signedWorkloads(rel *trust.Release) (map[uint32]config.Workload, bool, error) {
	section, ok := rel.Bundle["egress_workloads"].(map[string]any)
	if !ok {
		return nil, false, nil
	}
	out := map[uint32]config.Workload{}
	for k, v := range section {
		id, err := strconv.ParseUint(k, 10, 32)
		if err != nil || id == 0 || uint32(id) >= config.ReservedWorkloads {
			return nil, true, fmt.Errorf("signed workload %q: bad id", k)
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, true, err
		}
		var w struct {
			config.Workload
			Enabled bool `json:"enabled"`
		}
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, true, fmt.Errorf("signed workload %s: %w", k, err)
		}
		if !w.Enabled {
			continue
		}
		w.Workload.ID = uint32(id)
		out[uint32(id)] = w.Workload
	}
	return out, true, nil
}

// constrain: the policy to enforce - the server's, held to the signed
// workloads - with notes on what was not applied.
func constrain(server *config.Policy, signed map[uint32]config.Workload) (*config.Policy, []string) {
	eff := *server
	eff.Workloads = nil
	var notes []string
	seen := map[uint32]bool{}
	for _, w := range server.Workloads {
		s, ok := signed[w.ID]
		if !ok {
			eff.Workloads = append(eff.Workloads, w)
			continue
		}
		seen[w.ID] = true
		c := s
		c.Signed = true
		c.Name = w.Name
		c.Mode = stricterMode(w.Mode, s.Mode)
		c.Isolated = w.Isolated || s.Isolated
		c.IsolatedReason = w.IsolatedReason
		if !w.Isolated {
			c.IsolatedReason = s.IsolatedReason
		}
		c.DNS = s.DNS
		if s.DNS == "any" && w.DNS == "listed" {
			c.DNS = "listed"
		}
		var de, di int
		c.EgressAllow, de = covered(w.EgressAllow, s.EgressAllow, true)
		c.IngressAllow, di = covered(w.IngressAllow, s.IngressAllow, false)
		if dropped := de + di; dropped > 0 {
			notes = append(notes, fmt.Sprintf("workload %d: %d allowed destinations or sources are not in the "+
				"signed release, not applied", w.ID, dropped))
		}
		c.ExtraPatterns = without(w.CgroupPatterns, s.CgroupPatterns)
		c.ExtraUsers = without(w.RunAsUsers, s.RunAsUsers)
		eff.Workloads = append(eff.Workloads, c)
	}
	var missing []uint32
	for id := range signed {
		if !seen[id] {
			missing = append(missing, id)
		}
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i] < missing[j] })
	for _, id := range missing {
		c := signed[id]
		c.Signed = true
		eff.Workloads = append(eff.Workloads, c)
		notes = append(notes, fmt.Sprintf("workload %d is in the signed release but not in the server's policy: "+
			"governed as signed until a release without it is in force", id))
	}
	return &eff, notes
}

func stricterMode(a, b string) string {
	rank := map[string]int{"observe": 0, "alert": 1, "enforce": 2}
	if rank[a] > rank[b] {
		return a
	}
	return b
}

func without(list, signed []string) []string {
	have := map[string]bool{}
	for _, s := range signed {
		have[s] = true
	}
	var out []string
	for _, s := range list {
		if !have[s] {
			out = append(out, s)
		}
	}
	return out
}

// covered: the server's rules, one per destination (or source), port and
// protocol, that a signed rule allows too; and how many were not.
func covered(server, signed []config.Allow, egress bool) ([]config.Allow, int) {
	var out []config.Allow
	dropped := 0
	for _, a := range server {
		target := a.Source
		if egress {
			target = a.Dest
		}
		for _, port := range a.Ports {
			for _, proto := range a.Protocols {
				ok := false
				for _, s := range signed {
					st := s.Source
					if egress {
						st = s.Dest
					}
					if coversTarget(st, target) && coversPort(s.Ports, port) && coversProto(s.Protocols, proto) {
						ok = true
						break
					}
				}
				if !ok {
					dropped++
					continue
				}
				r := config.Allow{Ports: []int{port}, Protocols: []string{proto}}
				if egress {
					r.Dest = a.Dest
				} else {
					r.Source = a.Source
				}
				out = append(out, r)
			}
		}
	}
	return out, dropped
}

func coversPort(ports []int, p int) bool {
	for _, s := range ports {
		if s == 0 || s == p {
			return true
		}
	}
	return false
}

func coversProto(protos []string, p string) bool {
	for _, s := range protos {
		if strings.EqualFold(s, p) || strings.EqualFold(s, "any") {
			return true
		}
	}
	return false
}

// coversTarget: the signed destination (network or host name) includes the server's.
func coversTarget(signed, server string) bool {
	sp, sNet := parsePrefix(signed)
	wp, wNet := parsePrefix(server)
	if sNet || wNet {
		return sNet && wNet && sp.Addr().Is4() == wp.Addr().Is4() && sp.Bits() <= wp.Bits() && sp.Contains(wp.Addr())
	}
	s := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(signed)), ".")
	w := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(server)), ".")
	if s == "" || w == "" {
		return false
	}
	if s == w {
		return true
	}
	if rest, ok := strings.CutPrefix(s, "*."); ok {
		w = strings.TrimPrefix(w, "*.")
		return strings.HasSuffix(w, "."+rest)
	}
	return false
}

// effectivePolicy: the server's policy held to the verified release, with
// notes for the heartbeat - every workload isolated while the local kill
// switch is engaged (killswitch.go).
func (d *Daemon) effectivePolicy(p *config.Policy) (*config.Policy, []string) {
	eff, notes := d.heldToRelease(p)
	if r := d.ks.engaged(); r != "" {
		eff = isolateAll(eff, r)
		notes = append(notes, "local kill switch: "+r+" - every workload is isolated")
	}
	return eff, notes
}

func (d *Daemon) heldToRelease(p *config.Policy) (*config.Policy, []string) {
	if d.signed == nil {
		return p, nil
	}
	rel := d.signed.current()
	if rel == nil {
		return p, []string{"no signed release verified yet: the server's workloads are applied as it sent them"}
	}
	signed, ok, err := signedWorkloads(rel)
	if err != nil {
		return p, []string{"the signed release's workloads: " + err.Error()}
	}
	if !ok {
		return p, []string{fmt.Sprintf("the signed release #%d predates signed workloads: the server's "+
			"workloads are applied as it sent them", rel.Number)}
	}
	return constrain(p, signed)
}
