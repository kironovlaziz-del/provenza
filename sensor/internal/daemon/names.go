// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

// The names behind the addresses a workload connects to. The kernel sees
// only addresses; a workload with dns "listed" or "any" resolves through the
// sensor's own listener (dns.go), which notes here which name each answer's
// addresses came from. An event to such an address then carries the name too
// (dst_name), so what a workload reached reads as "api.openai.com:443", not a
// cloud provider's address - and an allow list can be made of names.
//
// A note, never a decision: nothing here allows or refuses anything.

import (
	"net/netip"
	"sync"
	"time"
)

const (
	// how long a name is kept for an address after the last answer that gave it
	nameKeep = time.Hour
	// names kept per workload: past it, expired ones go first, then any
	nameCacheMax = 4096
)

type nameEntry struct {
	name  string
	until time.Time
}

type nameCache struct {
	mu    sync.Mutex
	byWid map[uint32]map[netip.Addr]nameEntry
}

func newNameCache() *nameCache {
	return &nameCache{byWid: map[uint32]map[netip.Addr]nameEntry{}}
}

// put notes that name resolved to ips for workload wid.
func (c *nameCache) put(wid uint32, name string, ips []netip.Addr, now time.Time) {
	if c == nil || name == "" || len(ips) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.byWid[wid]
	if m == nil {
		m = map[netip.Addr]nameEntry{}
		c.byWid[wid] = m
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		if _, ok := m[ip]; !ok && len(m) >= nameCacheMax {
			c.evictLocked(m, now)
		}
		m[ip] = nameEntry{name: name, until: now.Add(nameKeep)}
	}
}

// evictLocked makes room in m: the expired entries, or else one entry.
func (c *nameCache) evictLocked(m map[netip.Addr]nameEntry, now time.Time) {
	for ip, e := range m {
		if now.After(e.until) {
			delete(m, ip)
		}
	}
	if len(m) < nameCacheMax {
		return
	}
	for ip := range m {
		delete(m, ip)
		return
	}
}

// get: the name ip was last resolved from for workload wid, if not expired.
func (c *nameCache) get(wid uint32, ip netip.Addr, now time.Time) (string, bool) {
	if c == nil {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.byWid[wid][ip.Unmap()]
	if !ok || now.After(e.until) {
		return "", false
	}
	return e.name, true
}

// forget drops what is noted for workloads no longer in the policy.
func (c *nameCache) forget(keep func(wid uint32) bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for wid := range c.byWid {
		if !keep(wid) {
			delete(c.byWid, wid)
		}
	}
}
