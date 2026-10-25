// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

// The egress proxy on a proxy host (docs/pvp/edge.md, section 5):
//
//	provenza-sensor --proxy run -- provenza-proxy -config /etc/provenza-proxy/proxy.json
//
// runs the proxy in a cgroup of its own that is held - governed, but under
// no workload, so nothing gets in or out - until every process in it runs a
// binary whose SHA-256 is pinned: listed in the signed manifest the sensor
// verified itself (policy.pin), or in sensor.json's proxy_binaries when no
// pin is set. Then the cgroup may connect anywhere and accept connections:
// the proxy enforces its own routes. The check runs five times a second; a
// process that runs anything else (or is being traced) holds the cgroup
// again.
//
// The configuration is pinned too: the proxy binary - trusted once its hash
// is pinned - tells the sensor the SHA-256 of the configuration file it read
// (on the run socket, PROVENZA_SENSOR_SOCKET; the sensor knows the process
// by SO_PEERCRED and its start time), and the cgroup stays held until every
// process reported a configuration the signed manifest (proxy_configs) names.
// A pinned binary run with another configuration - another server, another
// pin, policy.mode "off" - gets nothing out.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/bpfobj"
	"github.com/kironovlaziz-del/provenza/sensor/internal/cgroups"
	"github.com/kironovlaziz-del/provenza/sensor/internal/client"
	"github.com/kironovlaziz-del/provenza/sensor/internal/config"
	"github.com/kironovlaziz-del/provenza/sensor/internal/kern"
	"github.com/kironovlaziz-del/provenza/sensor/internal/trust"
)

const (
	// widProxyHeld: governed but in no policy, so the kernel fails closed.
	widProxyHeld = config.ReservedWorkloads
	// widProxy: a verified egress proxy.
	widProxy = config.ReservedWorkloads + 1

	proxyCheckEvery = 200 * time.Millisecond
	// a run held this long is reported in the log (the first moments are the
	// sensor's own process, before it execs the proxy); an empty one is removed
	proxySettle = 3 * time.Second
)

type proxyRun struct {
	rel      string
	id       uint64
	since    time.Time
	verified bool
	reason   string
	procs    int
	sha      string
	told     bool         // its being held was logged
	tainted  map[int]bool // processes seen traced (judgeProxy)
	configs  map[int]configReport
	config   string // the configuration it was let out with
}

// configReport: the configuration a proxy process reported, and when that
// process started (a pid taken by another process later is not it).
type configReport struct {
	sha   string
	start uint64
}

// proxyWorkload is the kernel workload of a verified proxy.
func proxyWorkload() kern.Workload { return kern.EgressProxy(widProxy) }

// pinnedProxyBinaries: the binaries a proxy host lets out, or why none.
func (d *Daemon) pinnedProxyBinaries() (map[string]bool, string) {
	if d.signed != nil {
		rel := d.signed.current()
		if rel == nil {
			return nil, "no verified signed policy yet"
		}
		pins := trust.ProxyBinaries(rel.Manifest)
		if len(pins) == 0 {
			return nil, fmt.Sprintf("the signed manifest (release #%d) names no egress proxy binary", rel.Number)
		}
		return pins, ""
	}
	if len(d.cfg.ProxyBinaries) == 0 {
		return nil, "no pinned egress proxy binary (policy.pin, or proxy_binaries in sensor.json)"
	}
	pins := map[string]bool{}
	for _, h := range d.cfg.ProxyBinaries {
		pins[h] = true
	}
	return pins, ""
}

// pinnedProxyConfigs: the configurations a proxy may run with, or why none.
func (d *Daemon) pinnedProxyConfigs() (map[string]bool, string) {
	if d.signed != nil {
		rel := d.signed.current()
		if rel == nil {
			return nil, "no verified signed policy yet"
		}
		pins := trust.ProxyConfigs(rel.Manifest)
		if len(pins) == 0 {
			return nil, fmt.Sprintf("the signed manifest (release #%d) names no egress proxy configuration", rel.Number)
		}
		return pins, ""
	}
	if len(d.cfg.ProxyConfigs) == 0 {
		return nil, "no pinned egress proxy configuration (policy.pin, or proxy_configs in sensor.json)"
	}
	pins := map[string]bool{}
	for _, h := range d.cfg.ProxyConfigs {
		pins[h] = true
	}
	return pins, ""
}

// procStart: when the process started (/proc/<pid>/stat, field 22, in clock ticks since boot).
func procStart(pid int) (uint64, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	s := string(raw)
	i := strings.LastIndexByte(s, ')') // the command name may hold spaces and parentheses
	if i < 0 {
		return 0, errors.New("unreadable stat")
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return 0, errors.New("unreadable stat")
	}
	return strconv.ParseUint(f[19], 10, 64)
}

// procInfo is what the check needs to know of a process.
type procInfo struct {
	sha    string
	traced bool
	start  uint64
}

// judgeProxy: whether every process may be let out, with the binary and the
// configuration and, when not, why. A process ever seen traced stays held
// until it exits (tainted): what a tracer wrote into it does not leave with
// the tracer. Every process must have reported a pinned configuration
// (reported: what it said, from this very process - same start time).
func judgeProxy(pids []int, pins, configs map[string]bool, look func(int) (procInfo, error),
	reported map[int]configReport, tainted map[int]bool) (bool, string, string, string) {
	if len(pins) == 0 {
		return false, "", "", "no pinned egress proxy binary"
	}
	if len(configs) == 0 {
		return false, "", "", "no pinned egress proxy configuration"
	}
	sha, config, alive := "", "", 0
	verdict := ""
	for _, pid := range pids {
		info, err := look(pid)
		if errors.Is(err, fs.ErrNotExist) {
			continue // it exited
		}
		rep, said := reported[pid]
		switch {
		case err != nil:
			verdict = fmt.Sprintf("process %d: %v", pid, err)
		case info.traced:
			tainted[pid] = true
			verdict = fmt.Sprintf("process %d is being traced", pid)
		case tainted[pid]:
			verdict = fmt.Sprintf("process %d was traced: held until it exits", pid)
		case !pins[info.sha]:
			verdict = fmt.Sprintf("process %d runs %s, not a pinned egress proxy binary", pid, info.sha)
		case !said || rep.start != info.start:
			verdict = fmt.Sprintf("process %d has not reported its configuration", pid)
		case !configs[rep.sha]:
			verdict = fmt.Sprintf("process %d runs with configuration %s, not a pinned one", pid, rep.sha)
		}
		if verdict != "" {
			return false, "", "", verdict
		}
		sha, config = info.sha, rep.sha
		alive++
	}
	if alive == 0 {
		return false, "", "", "no process"
	}
	return true, sha, config, ""
}

// exeHashes hashes the binaries processes run, once per file version.
type exeHashes struct {
	mu    sync.Mutex
	cache map[exeKey]string
}

type exeKey struct {
	dev, ino uint64
	size     int64
	mtime    int64
}

func newExeHashes() *exeHashes { return &exeHashes{cache: map[exeKey]string{}} }

// look opens what the process runs - /proc/<pid>/exe is the very file the
// kernel mapped, even when its path was replaced or deleted since - and
// hashes it.
func (h *exeHashes) look(pid int) (procInfo, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return procInfo{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return procInfo{}, err
	}
	key := exeKey{size: fi.Size(), mtime: fi.ModTime().UnixNano()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		key.dev, key.ino = uint64(st.Dev), uint64(st.Ino)
	}
	h.mu.Lock()
	sum, ok := h.cache[key]
	h.mu.Unlock()
	if !ok {
		hs := sha256.New()
		if _, err := io.Copy(hs, f); err != nil {
			return procInfo{}, err
		}
		sum = hex.EncodeToString(hs.Sum(nil))
		h.mu.Lock()
		if len(h.cache) > 64 {
			h.cache = map[exeKey]string{}
		}
		h.cache[key] = sum
		h.mu.Unlock()
	}
	traced, err := tracedPid(pid)
	if err != nil {
		return procInfo{}, err
	}
	start, err := procStart(pid)
	if err != nil {
		return procInfo{}, err
	}
	return procInfo{sha: sum, traced: traced, start: start}, nil
}

// tracedPid: whether any thread of the process has a tracer.
func tracedPid(pid int) (bool, error) {
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return false, err
	}
	for _, t := range tasks {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/status", pid, t.Name()))
		if err != nil {
			continue // the thread ended
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if v, ok := strings.CutPrefix(line, "TracerPid:"); ok {
				if n, _ := strconv.Atoi(strings.TrimSpace(v)); n != 0 {
					return true, nil
				}
				break
			}
		}
	}
	return false, nil
}

// proxyWid: the workload a proxy run cgroup is governed with now. One the
// daemon does not know yet (found by a walk after a restart) starts held.
func (d *Daemon) proxyWid(id uint64, rel string) uint32 {
	d.mu.Lock()
	defer d.mu.Unlock()
	r, ok := d.proxies[id]
	if !ok {
		r = &proxyRun{rel: rel, id: id, since: time.Now(), reason: "not checked yet"}
		d.proxies[id] = r
		d.kickProxyCheck()
	}
	if r.verified {
		return widProxy
	}
	return widProxyHeld
}

func (d *Daemon) kickProxyCheck() {
	select {
	case d.proxyKick <- struct{}{}:
	default:
	}
}

// checkProxyRuns checks every proxy run cgroup and governs it accordingly.
func (d *Daemon) checkProxyRuns() {
	d.mu.Lock()
	runs := make([]*proxyRun, 0, len(d.proxies))
	for _, r := range d.proxies {
		runs = append(runs, r)
	}
	d.mu.Unlock()
	if len(runs) == 0 {
		return
	}
	pins, why := d.pinnedProxyBinaries()
	configs, cwhy := d.pinnedProxyConfigs()
	if why == "" {
		why = cwhy
	}
	changed := false
	for _, r := range runs {
		pids, err := cgroups.Procs(d.cfg.CgroupRoot, r.rel)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				d.mu.Lock()
				delete(d.proxies, r.id)
				d.mu.Unlock()
				_ = d.kernel.DeleteCgroup(r.id)
			}
			continue
		}
		if len(pids) == 0 && time.Since(r.since) > proxySettle && cgroups.Remove(d.cfg.CgroupRoot, r.rel) == nil {
			// the proxy exited: its cgroup goes
			d.mu.Lock()
			delete(d.proxies, r.id)
			delete(d.cgWid, r.id)
			d.mu.Unlock()
			_ = d.kernel.DeleteCgroup(r.id)
			slog.Info("proxy run: ended", "cgroup", r.rel)
			continue
		}
		d.mu.Lock()
		if r.tainted == nil {
			r.tainted = map[int]bool{}
		}
		tainted, reported := map[int]bool{}, map[int]configReport{}
		for _, pid := range pids {
			if r.tainted[pid] {
				tainted[pid] = true // forgotten once it exits
			}
			if c, ok := r.configs[pid]; ok {
				reported[pid] = c
			}
		}
		r.configs = reported
		d.mu.Unlock()
		ok, sha, config, reason := judgeProxy(pids, pins, configs, d.exes.look, reported, tainted)
		if why != "" {
			ok, sha, config, reason = false, "", "", why
		}
		d.mu.Lock()
		was := r.verified
		r.verified, r.sha, r.config, r.reason, r.procs, r.tainted = ok, sha, config, reason, len(pids), tainted
		// held: told once, at once when it was let out before, else once it settled
		tell := !ok && !r.told && len(pids) > 0 && (was || time.Since(r.since) > proxySettle)
		r.told = tell || (r.told && !ok)
		d.mu.Unlock()
		if tell {
			slog.Warn("proxy run: held", "cgroup", r.rel, "reason", reason)
		}
		if ok == was {
			continue
		}
		wid := widProxyHeld
		if ok {
			wid = widProxy
		}
		if err := d.kernel.SetCgroup(r.id, bpfobj.CgEntry{Wid: wid, Kind: bpfobj.CgGoverned,
			Since: uint64(time.Now().UnixNano())}); err != nil {
			slog.Warn("proxy run: govern cgroup", "cgroup", r.rel, "err", err)
			continue
		}
		d.mu.Lock()
		d.cgWid[r.id] = wid
		d.mu.Unlock()
		changed = true
		if ok {
			slog.Info("proxy run: verified, let out", "cgroup", r.rel, "sha256", sha, "config_sha256", config)
		}
	}
	if changed {
		if err := d.kernel.BumpEpoch(); err != nil {
			slog.Warn("bump epoch", "err", err)
		}
	}
}

// reportConfig: a proxy process tells the configuration it read. Taken only
// from a process in a proxy run cgroup that runs a pinned binary, untraced -
// the code that computed the hash is then the pinned one.
func (d *Daemon) reportConfig(pid int, sha string) (string, error) {
	if !config.IsSHA256(sha) {
		return "", errors.New("the configuration's SHA-256 is not 64 lowercase hex characters")
	}
	pins, why := d.pinnedProxyBinaries()
	if why != "" {
		return "", errors.New(why)
	}
	info, err := d.exes.look(pid)
	if err != nil {
		return "", err
	}
	if info.traced || !pins[info.sha] {
		return "", errors.New("only a pinned egress proxy binary, untraced, reports its configuration")
	}
	configs, why := d.pinnedProxyConfigs()
	if why != "" {
		return "", errors.New(why)
	}
	if !configs[sha] {
		return "", fmt.Errorf("configuration %s is not a pinned egress proxy configuration "+
			"(Policies -> Signed policy -> egress proxy configurations)", sha)
	}
	d.mu.Lock()
	runs := make([]*proxyRun, 0, len(d.proxies))
	for _, r := range d.proxies {
		runs = append(runs, r)
	}
	d.mu.Unlock()
	for _, r := range runs {
		pids, err := cgroups.Procs(d.cfg.CgroupRoot, r.rel)
		if err != nil {
			continue
		}
		for _, p := range pids {
			if p != pid {
				continue
			}
			d.mu.Lock()
			if r.configs == nil {
				r.configs = map[int]configReport{}
			}
			r.configs[pid] = configReport{sha: sha, start: info.start}
			d.mu.Unlock()
			d.kickProxyCheck()
			slog.Info("proxy run: configuration reported", "cgroup", r.rel, "pid", pid, "config_sha256", sha)
			return r.rel, nil
		}
	}
	return "", errors.New("the process is not in an egress proxy run")
}

func (d *Daemon) proxyLoop(ctx context.Context) {
	t := time.NewTicker(proxyCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-d.proxyKick:
		}
		d.checkProxyRuns()
	}
}

func (d *Daemon) proxyReports() []client.ProxyRunReport {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]client.ProxyRunReport, 0, len(d.proxies))
	for _, r := range d.proxies {
		st := "held"
		if r.verified {
			st = "verified"
		}
		out = append(out, client.ProxyRunReport{Cgroup: r.rel, State: st, Reason: r.reason,
			Processes: r.procs, SHA256: r.sha, Config: r.config})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Cgroup < out[j].Cgroup })
	return out
}

// runCgroupOfOurs: rel is a run cgroup the sensor made (named so and owned by
// root), which the daemon governs itself - not by the policy's patterns.
func (d *Daemon) runCgroupOfOurs(rel string) bool {
	base := filepath.Base(rel)
	if !strings.HasPrefix(base, cgroups.ProxyPrefix) && !strings.HasPrefix(base, cgroups.RunPrefix) {
		return false
	}
	fi, err := os.Stat(filepath.Join(d.cfg.CgroupRoot, rel))
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if _, agent := cgroups.RunAgent(rel, st.Uid); agent {
		return true
	}
	return cgroups.RunProxy(rel, st.Uid)
}

// ptraceWarning: on a proxy host, anyone who may attach to the proxy can
// change what it runs without its binary changing. kernel.yama.ptrace_scope
// 3 forbids that to everyone, root included (until a reboot).
func ptraceWarning(proxies bool) string {
	if !proxies {
		return ""
	}
	raw, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if v := strings.TrimSpace(string(raw)); err != nil || v != "3" {
		if err != nil {
			v = "not available"
		}
		return "kernel.yama.ptrace_scope is " + v + " on this proxy host: a process allowed to attach to " +
			"the egress proxy can change its memory without its binary changing; set it to 3"
	}
	return ""
}
