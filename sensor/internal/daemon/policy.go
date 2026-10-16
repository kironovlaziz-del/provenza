// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/bpfobj"
	"github.com/kironovlaziz-del/provenza/sensor/internal/cgroups"
	"github.com/kironovlaziz-del/provenza/sensor/internal/client"
	"github.com/kironovlaziz-del/provenza/sensor/internal/config"
	"github.com/kironovlaziz-del/provenza/sensor/internal/kern"
)

// dnsBasePort is where per-workload DNS listeners start. The kernel rewrites
// redirected queries to 127.0.0.1:<dnsBasePort+index>.
const dnsBasePort = 15353

// pattern is a workload pattern plus the workload it points to.
type pattern struct {
	p   cgroups.Pattern
	wid uint32
}

func (p pattern) Match(rel string) bool { return p.p.Match(rel) }

// applyPolicy pushes a new policy into the kernel and updates all local
// state (patterns, cgroup map, uid map, DNS names).
func (d *Daemon) applyPolicy(ctx context.Context, p *config.Policy) error {
	if err := p.Check(); err != nil {
		return fmt.Errorf("policy check: %w", err)
	}

	// Build patterns and the list of kernel workloads.
	var pats []pattern
	var kws []kern.Workload
	wls := make(map[uint32]*wlState, len(p.Workloads))
	idx := 0
	for _, w := range p.Workloads {
		for _, raw := range w.CgroupPatterns {
			pats = append(pats, pattern{p: cgroups.NewPattern(raw, w.ID), wid: w.ID})
		}
		kw := kern.Workload{
			ID:       w.ID,
			Mode:     modeOf(w.Mode),
			DNS:      dnsModeOf(w.DNS),
			Isolated: w.Isolated,
		}
		if w.DNS != "off" {
			kw.DNSPort = dnsBasePort + uint16(idx)
		}
		rules := rulesFor(w, bpfobj.DirEgress)
		rules = append(rules, rulesFor(w, bpfobj.DirIngress)...)
		kw.Rules = rules
		kws = append(kws, kw)

		ws := &wlState{cfg: w, dnsPort: kw.DNSPort}
		if w.DNS == "listed" || w.DNS == "any" {
			ws.dnsNames, ws.dnsSfx = dnsNames(w)
		}
		wls[w.ID] = ws
		idx++
	}
	sort.Slice(pats, func(i, j int) bool { return pats[i].p.Raw < pats[j].p.Raw })

	if err := d.kernel.ApplyPolicy(kws); err != nil {
		return fmt.Errorf("apply policy: %w", err)
	}

	// Rewrite the uid->workload map: keep only the current set.
	newUIDs := map[uint32]uint32{}
	for _, w := range p.Workloads {
		for _, name := range w.RunAsUsers {
			uid, err := lookupUID(name)
			if err != nil {
				slog.Warn("run_as_user", "name", name, "err", err)
				continue
			}
			newUIDs[uid] = w.ID
			if !d.uidSet[uid] {
				if err := d.kernel.SetUID(uid, w.ID); err != nil {
					slog.Warn("set uid", "uid", uid, "err", err)
				}
			} else {
				if err := d.kernel.SetUID(uid, w.ID); err != nil {
					slog.Warn("set uid", "uid", uid, "err", err)
				}
			}
		}
	}
	for uid := range d.uidSet {
		if _, ok := newUIDs[uid]; !ok {
			_ = d.kernel.DeleteUID(uid)
		}
	}
	d.uidSet = map[uint32]bool{}
	for uid := range newUIDs {
		d.uidSet[uid] = true
	}

	// Store the current state before walking cgroups: the walk uses patterns.
	d.mu.Lock()
	d.policy = p
	d.patterns = pats
	d.wls = wls
	d.lastPolicyAt = time.Now()
	d.mu.Unlock()

	// Govern existing cgroups immediately.
	if err := d.resyncCgroups(); err != nil {
		slog.Warn("cgroup resync", "err", err)
	}

	// Sockets must re-classify: uid and cgroup maps changed.
	if err := d.kernel.BumpEpoch(); err != nil {
		slog.Warn("bump epoch", "err", err)
	}

	if err := client.SavePolicy(d.cfg.StateDir, p); err != nil {
		slog.Warn("save policy", "err", err)
	}

	d.dns.reload(ctx, wls)
	slog.Info("policy applied", "version", p.Version, "workloads", len(p.Workloads))
	return nil
}

// resyncCgroups walks every cgroup and rewrites the governed set so it
// matches the current patterns. Run cgroups (provenza-agent-N-*) are kept.
func (d *Daemon) resyncCgroups() error {
	dirs, err := cgroups.Walk(d.cfg.CgroupRoot)
	if err != nil {
		return err
	}
	d.mu.Lock()
	pats := append([]pattern(nil), d.patterns...)
	old := d.cgWid
	d.mu.Unlock()

	keep := map[uint64]bool{}
	newMap := map[uint64]uint32{}
	for _, dir := range dirs {
		var wid uint32
		var ok bool
		if agent, isRun := cgroups.RunAgent(dir.Rel, dir.UID); isRun {
			wid, ok = d.workloadForAgent(agent)
		} else {
			wid, ok = matchPattern(pats, dir.Rel)
		}
		if !ok {
			continue
		}
		entry := bpfobj.CgEntry{Wid: wid, Kind: bpfobj.CgGoverned, Since: uint64(time.Now().UnixNano())}
		if err := d.kernel.SetCgroup(dir.ID, entry); err != nil {
			slog.Warn("set cgroup", "id", dir.ID, "err", err)
			continue
		}
		keep[dir.ID] = true
		newMap[dir.ID] = wid
	}
	for id := range old {
		if !keep[id] {
			_ = d.kernel.DeleteCgroup(id)
		}
	}
	d.mu.Lock()
	d.cgWid = newMap
	d.mu.Unlock()
	return nil
}

// cgroupWalkLoop periodically re-syncs the governed cgroup set so that
// cgroups removed without a tracepoint event (or created before us) are
// handled correctly.
func (d *Daemon) cgroupWalkLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := d.resyncCgroups(); err != nil {
				slog.Warn("cgroup walk", "err", err)
			}
		}
	}
}

// workloadForAgent returns the workload whose agent_id is n.
func (d *Daemon) workloadForAgent(n int64) (uint32, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.policy == nil {
		return 0, false
	}
	for _, w := range d.policy.Workloads {
		if w.AgentID != nil && *w.AgentID == n {
			return w.ID, true
		}
	}
	return 0, false
}

// matchPattern returns the workload id of the first pattern matching rel.
func matchPattern(pats []pattern, rel string) (uint32, bool) {
	for _, p := range pats {
		if p.Match(rel) {
			return p.wid, true
		}
	}
	return 0, false
}

// rulesFor turns EgressAllow or IngressAllow into kernel rules. Host names
// (non-network Dest/Source) are skipped here; they are added at runtime when
// the DNS proxy resolves them.
func rulesFor(w config.Workload, dir uint8) []kern.Rule {
	var list []config.Allow
	var field string
	switch dir {
	case bpfobj.DirEgress:
		list, field = w.EgressAllow, "dest"
	case bpfobj.DirIngress:
		list, field = w.IngressAllow, "source"
	}
	var out []kern.Rule
	for _, a := range list {
		var raw string
		if field == "dest" {
			raw = a.Dest
		} else {
			raw = a.Source
		}
		prefix, ok := parsePrefix(raw)
		if !ok {
			continue
		}
		for _, port := range a.Ports {
			if port < 0 || port > 65535 {
				continue
			}
			for _, proto := range a.Protocols {
				p := protoNum(proto)
				if p == 0 && !strings.EqualFold(proto, "any") && proto != "" {
					continue
				}
				out = append(out, kern.Rule{
					Dir:   dir,
					Proto: p,
					Port:  uint16(port),
					Net:   prefix,
				})
			}
		}
	}
	return out
}

// parsePrefix turns a Dest/Source string into an address prefix. It returns
// false for host names (which the DNS proxy handles).
func parsePrefix(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, false
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// dnsNames extracts the set of host names a workload may resolve. Names are
// kept lower-cased, without the trailing dot. "*.x" goes to the suffix list.
func dnsNames(w config.Workload) (map[string]bool, []string) {
	exact := map[string]bool{}
	var sfx []string
	for _, a := range w.EgressAllow {
		dest := strings.TrimSpace(a.Dest)
		if dest == "" || isNetwork(dest) {
			continue
		}
		d := strings.TrimSuffix(strings.ToLower(dest), ".")
		if rest, ok := strings.CutPrefix(d, "*."); ok {
			sfx = append(sfx, "."+rest)
			continue
		}
		exact[d] = true
	}
	return exact, sfx
}

func isNetwork(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	return false
}

func modeOf(s string) uint8 {
	switch s {
	case "observe":
		return bpfobj.ModeObserve
	case "alert":
		return bpfobj.ModeAlert
	case "enforce":
		return bpfobj.ModeEnforce
	}
	return bpfobj.ModeObserve
}

func dnsModeOf(s string) uint8 {
	switch s {
	case "listed":
		return bpfobj.DNSListed
	case "any":
		return bpfobj.DNSAny
	}
	return bpfobj.DNSOff
}

func protoNum(s string) uint8 {
	switch strings.ToLower(s) {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	case "":
		return 0
	}
	return 0
}

// lookupUID resolves a user name to a numeric uid.
func lookupUID(name string) (uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}
