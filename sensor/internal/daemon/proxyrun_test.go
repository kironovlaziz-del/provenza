// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/kironovlaziz-del/provenza/sensor/internal/bpfobj"
	"github.com/kironovlaziz-del/provenza/sensor/internal/config"
	"github.com/kironovlaziz-del/provenza/sensor/internal/trust"
)

func TestJudgeProxy(t *testing.T) {
	good, bad := strings.Repeat("a", 64), strings.Repeat("b", 64)
	conf, other := strings.Repeat("c", 64), strings.Repeat("d", 64)
	pins, configs := map[string]bool{good: true}, map[string]bool{conf: true}
	procs := map[int]procInfo{1: {sha: good, start: 11}, 2: {sha: good, start: 12}, 3: {sha: bad},
		4: {sha: good, traced: true}, 5: {sha: good, start: 15}, 6: {sha: good, start: 16}, 8: {sha: good, start: 18}}
	look := func(pid int) (procInfo, error) {
		if p, ok := procs[pid]; ok {
			return p, nil
		}
		if pid == 9 {
			return procInfo{}, errors.New("permission denied")
		}
		return procInfo{}, fs.ErrNotExist
	}
	reported := map[int]configReport{1: {conf, 11}, 2: {conf, 12}, 6: {other, 16}, 8: {conf, 99}}
	cases := []struct {
		pids    []int
		pins    map[string]bool
		configs map[string]bool
		ok      bool
		why     string
	}{
		{[]int{1, 2}, pins, configs, true, ""},
		{[]int{1, 7}, pins, configs, true, ""}, // 7 exited
		{[]int{1, 3}, pins, configs, false, "not a pinned egress proxy binary"},
		{[]int{4}, pins, configs, false, "being traced"},
		{[]int{9}, pins, configs, false, "permission denied"},
		{[]int{7}, pins, configs, false, "no process"},
		{nil, pins, configs, false, "no process"},
		{[]int{1}, nil, configs, false, "no pinned egress proxy binary"},
		{[]int{1}, pins, nil, false, "no pinned egress proxy configuration"},
		{[]int{5}, pins, configs, false, "has not reported its configuration"},
		{[]int{6}, pins, configs, false, "not a pinned one"},
		{[]int{8}, pins, configs, false, "has not reported"}, // another process took the pid
	}
	for _, c := range cases {
		ok, sha, config, why := judgeProxy(c.pids, c.pins, c.configs, look, reported, map[int]bool{})
		if ok != c.ok || !strings.Contains(why, c.why) || (ok && (sha != good || config != conf)) {
			t.Errorf("%v: got %v %q %q %q", c.pids, ok, sha, config, why)
		}
	}
}

func TestATracedProcessStaysHeld(t *testing.T) {
	good, conf := strings.Repeat("a", 64), strings.Repeat("c", 64)
	pins, configs := map[string]bool{good: true}, map[string]bool{conf: true}
	reported := map[int]configReport{5: {conf, 1}, 6: {conf, 1}}
	traced := true
	look := func(int) (procInfo, error) { return procInfo{sha: good, traced: traced, start: 1}, nil }
	tainted := map[int]bool{}
	if ok, _, _, why := judgeProxy([]int{5}, pins, configs, look, reported, tainted); ok || !strings.Contains(why, "traced") {
		t.Fatal(why)
	}
	traced = false // the tracer detached
	if ok, _, _, why := judgeProxy([]int{5}, pins, configs, look, reported, tainted); ok || !strings.Contains(why, "until it exits") {
		t.Fatal("verified again after a tracer detached:", why)
	}
	if ok, _, _, _ := judgeProxy([]int{6}, pins, configs, look, reported, map[int]bool{}); !ok {
		t.Fatal("a new process was held")
	}
}

func TestProcStart(t *testing.T) {
	a, err := procStart(os.Getpid())
	if err != nil || a == 0 {
		t.Fatalf("%d %v", a, err)
	}
	if b, _ := procStart(os.Getpid()); b != a {
		t.Fatal("the start time changed")
	}
}

func TestExeHashesItsOwnBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	h := newExeHashes()
	for i := 0; i < 2; i++ { // the second time from the cache
		info, err := h.look(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		if info.sha != hex.EncodeToString(sum[:]) || info.traced {
			t.Fatalf("%+v", info)
		}
	}
	if len(h.cache) != 1 {
		t.Fatalf("cache %d", len(h.cache))
	}
	if _, err := h.look(1 << 30); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a gone process: %v", err)
	}
}

func TestProxyWorkloadLetsOutAndIn(t *testing.T) {
	w := proxyWorkload()
	if w.ID != widProxy || w.ID < config.ReservedWorkloads || w.Mode != bpfobj.ModeEnforce {
		t.Fatalf("%+v", w)
	}
	var out, in int
	for _, r := range w.Rules {
		if r.Port != 0 || r.Net.Bits() != 0 {
			t.Fatalf("not any port / address: %+v", r)
		}
		if r.Dir == bpfobj.DirEgress {
			out++
		} else if r.Proto == 6 {
			in++
		}
	}
	if out != 4 || in != 2 {
		t.Fatalf("egress %d ingress %d", out, in)
	}
	if err := (&config.Policy{Schema: 1, Workloads: []config.Workload{{ID: widProxy, Mode: "enforce", DNS: "off"}}}).Check(); err == nil {
		t.Fatal("the server's policy took the proxy's workload id")
	}
}

func TestPinnedProxyBinaries(t *testing.T) {
	h := strings.Repeat("c", 64)
	d := &Daemon{cfg: config.Settings{}}
	if _, why := d.pinnedProxyBinaries(); !strings.Contains(why, "no pinned") {
		t.Fatal(why)
	}
	d.cfg.ProxyBinaries = []string{h}
	if pins, why := d.pinnedProxyBinaries(); why != "" || !pins[h] {
		t.Fatal(pins, why)
	}
	// with a pin, only the signed manifest counts
	d.signed = &signedPolicy{pin: "tofu"}
	if _, why := d.pinnedProxyBinaries(); !strings.Contains(why, "no verified signed policy") {
		t.Fatal(why)
	}
	d.signed.rel = &trust.Release{Number: 3, Manifest: map[string]any{}}
	if _, why := d.pinnedProxyBinaries(); !strings.Contains(why, "names no egress proxy binary") {
		t.Fatal(why)
	}
	d.signed.rel.Manifest["proxy_binaries"] = []any{strings.Repeat("d", 64), "not-a-hash"}
	if pins, why := d.pinnedProxyBinaries(); why != "" || len(pins) != 1 || pins[h] {
		t.Fatal(pins, why)
	}
}

func TestProxyUsers(t *testing.T) {
	lookup := func(name string) (uint32, error) {
		if name == "provenza-proxy" {
			return 990, nil
		}
		return 0, errors.New("no such user")
	}
	for _, c := range []struct {
		uid   uint32
		users []string
		ok    bool
	}{
		{0, nil, true},
		{990, nil, false},
		{990, []string{"provenza-proxy"}, true},
		{991, []string{"provenza-proxy"}, false},
		{1000, []string{"1000"}, true},
		{1000, []string{"nobody-here"}, false},
	} {
		if got := proxyUserAllowed(c.uid, c.users, lookup); got != c.ok {
			t.Errorf("%d %v: %v", c.uid, c.users, got)
		}
	}
}

func TestPinnedProxyConfigs(t *testing.T) {
	h := strings.Repeat("c", 64)
	d := &Daemon{cfg: config.Settings{}}
	if _, why := d.pinnedProxyConfigs(); !strings.Contains(why, "no pinned egress proxy configuration") {
		t.Fatal(why)
	}
	d.cfg.ProxyConfigs = []string{h}
	if pins, why := d.pinnedProxyConfigs(); why != "" || !pins[h] {
		t.Fatal(pins, why)
	}
	// with a pin, only the signed manifest counts
	d.signed = &signedPolicy{pin: "tofu"}
	d.signed.rel = &trust.Release{Number: 3, Manifest: map[string]any{"proxy_binaries": []any{h}}}
	if _, why := d.pinnedProxyConfigs(); !strings.Contains(why, "names no egress proxy configuration") {
		t.Fatal(why)
	}
	d.signed.rel.Manifest["proxy_configs"] = []any{strings.Repeat("d", 64), "not-a-hash"}
	if pins, why := d.pinnedProxyConfigs(); why != "" || len(pins) != 1 || pins[h] {
		t.Fatal(pins, why)
	}
}
