// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package kern

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
	"github.com/kironovlaziz-del/provenza/sensor/internal/bpfobj"
)

// Rule allows one direction, protocol and port (0 = any) for a network.
type Rule struct {
	Dir   uint8 // bpfobj.DirEgress: destination; DirIngress: source of inbound, Port = local port
	Proto uint8 // 6 tcp, 17 udp
	Port  uint16
	Net   netip.Prefix
}

// Workload is one governed workload as the kernel sees it.
type Workload struct {
	ID       uint32
	Mode     uint8
	DNS      uint8
	Isolated bool
	DNSPort  uint16
	DNSv6    bool
	Rules    []Rule
}

// graceAfterFlip lets programs that read the old generation finish before
// its entries are deleted.
const graceAfterFlip = 50 * time.Millisecond

type genState struct {
	gen  uint32
	wls  []bpfobj.WlKey
	k4   []bpfobj.LPM4
	k6   []bpfobj.LPM6
	live map[uint32][]Rule // rules added between generations (DNS answers)
}

func (k *Kernel) globals() (bpfobj.Globals, error) {
	var g bpfobj.Globals
	err := k.Globals.Lookup(uint32(0), &g)
	return g, err
}

// ApplyPolicy writes the whole policy as the next generation and switches to
// it in one map write. Entries of the previous generation go afterwards.
func (k *Kernel) ApplyPolicy(ws []Workload) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	g, err := k.globals()
	if err != nil {
		return err
	}
	next := genState{gen: g.Gen + 1}
	if err := k.writeGen(&next, ws); err != nil {
		k.deleteGen(&next)
		return err
	}
	g.Gen = next.gen
	if err := k.Globals.Update(uint32(0), g, ebpf.UpdateAny); err != nil {
		k.deleteGen(&next)
		return fmt.Errorf("switching policy generation: %w", err)
	}
	prev := k.cur
	k.cur = &next
	if prev != nil {
		time.Sleep(graceAfterFlip)
		k.deleteGen(prev)
	}
	return nil
}

func (k *Kernel) writeGen(s *genState, ws []Workload) error {
	for _, w := range ws {
		key := bpfobj.WlKey{Gen: s.gen, Wid: w.ID}
		val := bpfobj.WlCfg{Mode: w.Mode, DNS: w.DNS, DNSPort: w.DNSPort}
		if w.Isolated {
			val.Isolated = 1
		}
		if w.DNSv6 {
			val.Flags |= bpfobj.WlDNSv6
		}
		if err := k.Workloads.Update(key, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("workload %d: %w", w.ID, err)
		}
		s.wls = append(s.wls, key)
		for _, r := range w.Rules {
			if err := k.putRule(s, w.ID, r); err != nil {
				return fmt.Errorf("workload %d: %w", w.ID, err)
			}
		}
	}
	return nil
}

func (k *Kernel) putRule(s *genState, wid uint32, r Rule) error {
	one := uint8(1)
	addr := r.Net.Addr()
	if addr.Is4() || addr.Is4In6() {
		key := bpfobj.LPM4{Gen: s.gen, Wid: wid, Dir: r.Dir, Proto: r.Proto, Port: r.Port, Addr: addr.Unmap().As4()}
		bits := r.Net.Bits()
		if addr.Is4In6() {
			bits -= 96
		}
		key.Prefixlen = uint32(bpfobj.FixedBits + bits)
		if err := k.Allow4.Update(key, one, ebpf.UpdateAny); err != nil {
			return err
		}
		s.k4 = append(s.k4, key)
		return nil
	}
	key := bpfobj.LPM6{Gen: s.gen, Wid: wid, Dir: r.Dir, Proto: r.Proto, Port: r.Port, Addr: addr.As16()}
	key.Prefixlen = uint32(bpfobj.FixedBits + r.Net.Bits())
	if err := k.Allow6.Update(key, one, ebpf.UpdateAny); err != nil {
		return err
	}
	s.k6 = append(s.k6, key)
	return nil
}

func (k *Kernel) deleteGen(s *genState) {
	for _, key := range s.k4 {
		_ = k.Allow4.Delete(key)
	}
	for _, key := range s.k6 {
		_ = k.Allow6.Delete(key)
	}
	for _, key := range s.wls {
		_ = k.Workloads.Delete(key)
	}
}

// AddLive adds rules to the generation in force (addresses learned from DNS
// answers); the caller also passes them in its next ApplyPolicy.
func (k *Kernel) AddLive(wid uint32, rules []Rule) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.cur == nil {
		return errors.New("no policy in force yet")
	}
	for _, r := range rules {
		if err := k.putRule(k.cur, wid, r); err != nil {
			return err
		}
	}
	return nil
}

// SetCgroup names a cgroup (by id) as governed, exempt or pending.
func (k *Kernel) SetCgroup(id uint64, e bpfobj.CgEntry) error {
	return k.Cgroups.Update(id, e, ebpf.UpdateAny)
}

func (k *Kernel) DeleteCgroup(id uint64) error {
	err := k.Cgroups.Delete(id)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (k *Kernel) SetUID(uid, wid uint32) error {
	return k.UIDs.Update(uid, wid, ebpf.UpdateAny)
}

func (k *Kernel) DeleteUID(uid uint32) error {
	err := k.UIDs.Delete(uid)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// BumpEpoch makes sockets re-classify after cgroups or uids changed.
func (k *Kernel) BumpEpoch() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	g, err := k.globals()
	if err != nil {
		return err
	}
	g.Epoch++
	return k.Globals.Update(uint32(0), g, ebpf.UpdateAny)
}

// SetLiteral / SetWatch fill the maps the cgroup_mkdir tracepoint reads.
func (k *Kernel) SetLiteral(hash uint64, wid uint32) error {
	return k.Literal.Update(hash, wid, ebpf.UpdateAny)
}

func (k *Kernel) SetWatch(hash uint64) error {
	return k.WatchParents.Update(hash, uint8(1), ebpf.UpdateAny)
}

// ReplaceKeys drops every key of a hash map not in keep.
func ReplaceKeys[K comparable](m *ebpf.Map, keep map[K]bool) {
	var key K
	var stale []K
	it := m.Iterate()
	var val []byte
	for it.Next(&key, &val) {
		if !keep[key] {
			stale = append(stale, key)
		}
	}
	for _, s := range stale {
		_ = m.Delete(s)
	}
}

// PathHash is the FNV-1a 64 the cgroup_mkdir program computes over a path
// ("/system.slice/x.service").
func PathHash(path string) uint64 {
	h := uint64(0xcbf29ce484222325)
	for i := 0; i < len(path); i++ {
		h ^= uint64(path[i])
		h *= 0x100000001b3
	}
	return h
}

// EgressProxy is the workload of a verified egress proxy
// (internal/daemon/proxyrun.go): out to any address on any TCP or UDP port,
// in on any TCP port - the proxy enforces its own routes.
func EgressProxy(id uint32) Workload {
	var rules []Rule
	for _, n := range []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")} {
		rules = append(rules,
			Rule{Dir: bpfobj.DirEgress, Proto: 6, Net: n},
			Rule{Dir: bpfobj.DirEgress, Proto: 17, Net: n},
			Rule{Dir: bpfobj.DirIngress, Proto: 6, Net: n})
	}
	return Workload{ID: id, Mode: bpfobj.ModeEnforce, DNS: bpfobj.DNSOff, Rules: rules}
}
