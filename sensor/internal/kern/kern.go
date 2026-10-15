// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

// Package kern loads the sensor's kernel program, attaches it, and is the
// only code that writes its maps.
package kern

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/kironovlaziz-del/provenza/sensor/internal/bpfobj"
)

// Hooks maps each cgroup program to its attach type.
var hooks = []struct {
	prog   string
	attach ebpf.AttachType
	name   string
}{
	{"pvz_connect4", ebpf.AttachCGroupInet4Connect, "connect4"},
	{"pvz_connect6", ebpf.AttachCGroupInet6Connect, "connect6"},
	{"pvz_sendmsg4", ebpf.AttachCGroupUDP4Sendmsg, "sendmsg4"},
	{"pvz_sendmsg6", ebpf.AttachCGroupUDP6Sendmsg, "sendmsg6"},
	{"pvz_recvmsg4", ebpf.AttachCGroupUDP4Recvmsg, "recvmsg4"},
	{"pvz_recvmsg6", ebpf.AttachCGroupUDP6Recvmsg, "recvmsg6"},
	{"pvz_getpeername4", ebpf.AttachCgroupInet4GetPeername, "getpeername4"},
	{"pvz_getpeername6", ebpf.AttachCgroupInet6GetPeername, "getpeername6"},
	{"pvz_sock_create", ebpf.AttachCGroupInetSockCreate, "sock_create"},
	{"pvz_egress", ebpf.AttachCGroupInetEgress, "egress"},
	{"pvz_ingress", ebpf.AttachCGroupInetIngress, "ingress"},
}

// Options for Load.
type Options struct {
	// Cgroup the programs attach to; they act on it and everything below.
	// The host's cgroup v2 root in production.
	AttachCgroup string
	// Directory in bpffs where the links are pinned, so containment stays in
	// force while the daemon restarts. "" = do not pin (tests).
	PinDir string
	// Ring buffer size in bytes (power of two); 0 = the object's default.
	RingBytes uint32
}

// Kernel is the loaded program and its maps.
type Kernel struct {
	coll  *ebpf.Collection
	links []link.Link

	Cgroups      *ebpf.Map
	UIDs         *ebpf.Map
	Workloads    *ebpf.Map
	Allow4       *ebpf.Map
	Allow6       *ebpf.Map
	Globals      *ebpf.Map
	Literal      *ebpf.Map
	WatchParents *ebpf.Map
	Stats        *ebpf.Map
	Events       *ebpf.Map

	// What is in force, for the heartbeat.
	Hooks []string
	LSM   bool
	Mkdir bool
	Notes []string // why an optional part is missing

	mu  sync.Mutex // serializes map writes from the daemon's goroutines
	cur *genState
}

// Load loads everything the kernel accepts, without attaching anything. The
// core programs are required; LSM and the cgroup tracepoints are optional.
//
// The caller fills the maps, then calls Attach: on a restart, pinned hooks
// switch to the new programs (and their maps) at that moment, so the maps
// must already hold the whole policy.
func Load(opt Options) (*Kernel, error) {
	spec, err := bpfobj.Spec()
	if err != nil {
		return nil, err
	}
	if opt.RingBytes != 0 {
		spec.Maps["events"].MaxEntries = opt.RingBytes
	}
	optional := map[string]bool{}
	for _, p := range append(append([]string{}, bpfobj.LSMProgs...), bpfobj.MkdirProgs...) {
		optional[p] = true
	}

	// Maps first, shared by every program.
	core := spec.Copy()
	for name := range core.Programs {
		if optional[name] {
			delete(core.Programs, name)
		}
	}
	coll, err := ebpf.NewCollection(core)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("the kernel refused the sensor's program: %+v", ve)
		}
		return nil, fmt.Errorf("loading the sensor's program: %w", err)
	}
	k := &Kernel{coll: coll}
	k.Cgroups = coll.Maps["cgroups"]
	k.UIDs = coll.Maps["uids"]
	k.Workloads = coll.Maps["workloads"]
	k.Allow4 = coll.Maps["allow4"]
	k.Allow6 = coll.Maps["allow6"]
	k.Globals = coll.Maps["globals"]
	k.Literal = coll.Maps["literal_paths"]
	k.WatchParents = coll.Maps["watch_parents"]
	k.Stats = coll.Maps["stats"]
	k.Events = coll.Maps["events"]

	// Optional programs reuse the same maps.
	k.LSM = k.loadOptional(spec, bpfobj.LSMProgs, "BPF LSM (socket families other than IP)")
	k.Mkdir = k.loadOptional(spec, bpfobj.MkdirProgs, "cgroup tracepoints (new cgroups governed at creation)")
	return k, nil
}

func (k *Kernel) loadOptional(spec *ebpf.CollectionSpec, progs []string, what string) bool {
	s := spec.Copy()
	for name := range s.Programs {
		if !contains(progs, name) {
			delete(s.Programs, name)
		}
	}
	replace := map[string]*ebpf.Map{}
	for name := range s.Maps {
		if m := k.coll.Maps[name]; m != nil {
			replace[name] = m
		}
	}
	c, err := ebpf.NewCollectionWithOptions(s, ebpf.CollectionOptions{MapReplacements: replace})
	if err != nil {
		k.Notes = append(k.Notes, fmt.Sprintf("%s: not available on this kernel (%v)", what, err))
		return false
	}
	for name, p := range c.Programs {
		k.coll.Programs[name] = p
	}
	return true
}

// Attach puts the programs on their hooks (see Load).
func (k *Kernel) Attach(opt Options) error {
	for _, h := range hooks {
		prog := k.coll.Programs[h.prog]
		l, err := k.attachCgroup(opt, h.name, prog, h.attach)
		if err != nil {
			return fmt.Errorf("attaching %s to %s: %w", h.name, opt.AttachCgroup, err)
		}
		k.links = append(k.links, l)
		k.Hooks = append(k.Hooks, h.name)
	}
	// A BPF LSM program loads and attaches even when the kernel was booted
	// without "bpf" in its active LSMs - and then never runs. Report it as
	// missing rather than claim a protection that is not there.
	if k.LSM {
		if active, err := bpfLSMActive(); err == nil && !active {
			k.LSM = false
			k.Notes = append(k.Notes, "BPF LSM: loaded, but not active in this kernel "+
				"(add bpf to the lsm= boot parameter)")
		}
	}
	if k.LSM {
		l, err := k.pinnedOr(opt, "socket_family", func() (link.Link, error) {
			return link.AttachLSM(link.LSMOptions{Program: k.coll.Programs["pvz_socket_family"]})
		})
		if err != nil {
			k.LSM = false
			k.Notes = append(k.Notes, fmt.Sprintf("BPF LSM: not attached (%v)", err))
		} else {
			k.links = append(k.links, l)
			k.Hooks = append(k.Hooks, "lsm_socket_create")
		}
	}
	if k.Mkdir {
		for _, tp := range []struct{ prog, name string }{
			{"pvz_cgroup_mkdir", "cgroup_mkdir"}, {"pvz_cgroup_rmdir", "cgroup_rmdir"},
		} {
			prog := k.coll.Programs[tp.prog]
			l, err := k.pinnedOr(opt, tp.name, func() (link.Link, error) {
				return link.AttachRawTracepoint(link.RawTracepointOptions{Name: tp.name, Program: prog})
			})
			if err != nil {
				k.Mkdir = false
				k.Notes = append(k.Notes, fmt.Sprintf("cgroup tracepoint %s: not attached (%v)", tp.name, err))
				break
			}
			k.links = append(k.links, l)
			k.Hooks = append(k.Hooks, tp.name)
		}
	}
	return nil
}

// attachCgroup attaches one cgroup program. With a pin directory, a link
// pinned by an earlier run is updated to the new program in place: the hook
// is never empty across a restart or an upgrade.
func (k *Kernel) attachCgroup(opt Options, name string, prog *ebpf.Program, at ebpf.AttachType) (link.Link, error) {
	return k.pinnedOr(opt, name, func() (link.Link, error) {
		return link.AttachCgroup(link.CgroupOptions{Path: opt.AttachCgroup, Attach: at, Program: prog})
	})
}

func (k *Kernel) pinnedOr(opt Options, name string, attach func() (link.Link, error)) (link.Link, error) {
	if opt.PinDir == "" {
		return attach()
	}
	path := filepath.Join(opt.PinDir, name)
	if old, err := link.LoadPinnedLink(path, nil); err == nil {
		prog := k.programFor(name)
		if prog != nil {
			if err := old.Update(prog); err == nil {
				return old, nil
			}
		}
		// Cannot be updated (a different attach type or kernel): replace it
		// only after the new one is in place.
		l, err := attach()
		if err != nil {
			old.Close()
			return nil, err
		}
		_ = old.Unpin()
		old.Close()
		if err := l.Pin(path); err != nil {
			l.Close()
			return nil, err
		}
		return l, nil
	}
	if err := os.MkdirAll(opt.PinDir, 0o700); err != nil {
		return nil, err
	}
	l, err := attach()
	if err != nil {
		return nil, err
	}
	if err := l.Pin(path); err != nil {
		l.Close()
		return nil, fmt.Errorf("pinning %s: %w", name, err)
	}
	return l, nil
}

func (k *Kernel) programFor(hook string) *ebpf.Program {
	for _, h := range hooks {
		if h.name == hook {
			return k.coll.Programs[h.prog]
		}
	}
	switch hook {
	case "socket_family":
		return k.coll.Programs["pvz_socket_family"]
	case "cgroup_mkdir":
		return k.coll.Programs["pvz_cgroup_mkdir"]
	case "cgroup_rmdir":
		return k.coll.Programs["pvz_cgroup_rmdir"]
	}
	return nil
}

// Close releases this process's handles. Pinned links stay attached: the
// workloads stay contained until Detach.
func (k *Kernel) Close() {
	for _, l := range k.links {
		l.Close()
	}
	if k.coll != nil {
		k.coll.Close()
	}
}

// Detach removes the sensor from the kernel (provenza-sensor uninstall).
func Detach(pinDir string) error {
	entries, err := os.ReadDir(pinDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		path := filepath.Join(pinDir, e.Name())
		l, err := link.LoadPinnedLink(path, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Name(), err))
			continue
		}
		if err := l.Unpin(); err != nil {
			errs = append(errs, err)
		}
		l.Close()
	}
	if len(errs) == 0 {
		_ = os.Remove(pinDir)
	}
	return errors.Join(errs...)
}

// Reader opens the event ring buffer.
func (k *Kernel) Reader() (*ringbuf.Reader, error) {
	return ringbuf.NewReader(k.Events)
}

// Stat reads one of the per-CPU counters, summed.
func (k *Kernel) Stat(idx uint32) uint64 {
	var per []uint64
	if err := k.Stats.Lookup(idx, &per); err != nil {
		return 0
	}
	var sum uint64
	for _, v := range per {
		sum += v
	}
	return sum
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// bpfLSMActive reports whether "bpf" is among the kernel's active LSMs.
func bpfLSMActive() (bool, error) {
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false, err
	}
	for _, name := range strings.Split(strings.TrimSpace(string(b)), ",") {
		if name == "bpf" {
			return true, nil
		}
	}
	return false, nil
}
