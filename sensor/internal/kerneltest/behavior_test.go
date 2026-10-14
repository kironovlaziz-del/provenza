// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

// Functional tests against the running kernel. They need root (CAP_BPF,
// CAP_NET_ADMIN, CAP_SYS_ADMIN), cgroup v2, and a kernel with BPF LSM
// enabled for the raw-socket test. They run only with
// PROVENZA_SENSOR_KERNEL_TESTS=1 (as root).
package kerneltest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/kironovlaziz-del/provenza/sensor/internal/bpfobj"
	"github.com/kironovlaziz-del/provenza/sensor/internal/cgroups"
	"github.com/kironovlaziz-del/provenza/sensor/internal/kern"
)

// ---------------------------------------------------------------- helpers

type testEnv struct {
	t       *testing.T
	k       *kern.Kernel
	root    string
	testDir string
	rb      *ringbuf.Reader
}

func setup(t *testing.T) *testEnv {
	t.Helper()
	needKernel(t)

	root := os.Getenv("PROVENZA_CGROUP_ROOT")
	if root == "" {
		root = "/sys/fs/cgroup"
	}
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		t.Skipf("cgroup v2 not at %s: %v", root, err)
	}

	name := fmt.Sprintf("provenza-test-%d", rand.Int63())
	dir := filepath.Join(root, name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("create test cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })

	k, err := kern.Load(kern.Options{
		AttachCgroup: dir,
		PinDir:       "",
		RingBytes:    1 << 16,
	})
	if err != nil {
		t.Fatalf("kern.Load: %v", err)
	}
	if err := k.Attach(kern.Options{AttachCgroup: dir}); err != nil {
		k.Close()
		t.Fatalf("kern.Attach: %v", err)
	}
	t.Cleanup(k.Close)

	rb, err := k.Reader()
	if err != nil {
		t.Fatalf("ringbuf: %v", err)
	}
	t.Cleanup(func() { _ = rb.Close() })

	return &testEnv{t: t, k: k, root: root, testDir: dir, rb: rb}
}

func (e *testEnv) newWorkloadCgroup(name string) uint64 {
	e.t.Helper()
	dir := filepath.Join(e.testDir, name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		e.t.Fatalf("create %s: %v", dir, err)
	}
	pid := os.Getpid()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644); err != nil {
		e.t.Fatalf("move pid %d into %s: %v", pid, dir, err)
	}
	id, err := cgroups.ID(dir)
	if err != nil {
		e.t.Fatalf("cgroup id: %v", err)
	}
	return id
}

func (e *testEnv) applyPolicy(wid uint32, mode, dns uint8, rules []kern.Rule) {
	e.t.Helper()
	e.applyPolicyFull(wid, mode, dns, 0, rules)
}

func (e *testEnv) applyPolicyFull(wid uint32, mode, dns uint8, dnsPort uint16, rules []kern.Rule) {
	e.t.Helper()
	ws := []kern.Workload{{
		ID:      wid,
		Mode:    mode,
		DNS:     dns,
		DNSPort: dnsPort,
		Rules:   rules,
	}}
	if err := e.k.ApplyPolicy(ws); err != nil {
		e.t.Fatalf("ApplyPolicy: %v", err)
	}
}

func (e *testEnv) govern(cgid uint64, wid uint32) {
	e.t.Helper()
	if err := e.k.SetCgroup(cgid, bpfobj.CgEntry{Wid: wid, Kind: bpfobj.CgGoverned}); err != nil {
		e.t.Fatalf("SetCgroup: %v", err)
	}
}

// readEvents reads ringbuf records for d, decoding each one.
func (e *testEnv) readEvents(d time.Duration) []bpfobj.Event {
	e.t.Helper()
	deadline := time.Now().Add(d)
	var out []bpfobj.Event
	for time.Now().Before(deadline) {
		e.rb.SetDeadline(time.Now().Add(50 * time.Millisecond))
		rec, err := e.rb.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			return out
		}
		if len(rec.RawSample) < int(unsafe.Sizeof(bpfobj.Event{})) {
			continue
		}
		var ev bpfobj.Event
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &ev); err != nil {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// ---------------------------------------------------------------- tests

func TestTCPAllowDeny(t *testing.T) {
	e := setup(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)
	port := uint16(addr.Port)
	prefix, _ := netip.ParsePrefix("127.0.0.1/32")

	e.applyPolicy(1, bpfobj.ModeEnforce, bpfobj.DNSOff, []kern.Rule{{
		Dir: bpfobj.DirEgress, Proto: 6, Port: port, Net: prefix,
	}})
	cg1 := e.newWorkloadCgroup("allow")
	e.govern(cg1, 1)

	if err := dialTCP(addr, 2*time.Second); err != nil {
		t.Errorf("allowed connect failed: %v", err)
	}

	e.applyPolicy(2, bpfobj.ModeEnforce, bpfobj.DNSOff, nil)
	cg2 := e.newWorkloadCgroup("deny")
	e.govern(cg2, 2)

	if err := dialTCP(addr, 2*time.Second); err == nil {
		t.Fatalf("denied connect unexpectedly succeeded")
	} else {
		t.Logf("denied connect returned: %v", err)
	}
}

func TestUDPAllowDeny(t *testing.T) {
	e := setup(t)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().(*net.UDPAddr)
	port := uint16(addr.Port)
	prefix, _ := netip.ParsePrefix("127.0.0.1/32")

	e.applyPolicy(10, bpfobj.ModeEnforce, bpfobj.DNSOff, []kern.Rule{{
		Dir: bpfobj.DirEgress, Proto: 17, Port: port, Net: prefix,
	}})
	cg := e.newWorkloadCgroup("udp-allow")
	e.govern(cg, 10)

	if err := sendUDP(addr); err != nil {
		t.Errorf("allowed UDP send failed: %v", err)
	}

	e.applyPolicy(11, bpfobj.ModeEnforce, bpfobj.DNSOff, nil)
	if err := e.k.SetCgroup(cg, bpfobj.CgEntry{Wid: 11, Kind: bpfobj.CgGoverned}); err != nil {
		t.Fatalf("re-govern: %v", err)
	}
	if err := e.k.BumpEpoch(); err != nil {
		t.Fatalf("bump epoch: %v", err)
	}

	if err := sendUDP(addr); err == nil {
		t.Fatalf("denied UDP send unexpectedly succeeded")
	} else {
		t.Logf("denied UDP send returned: %v", err)
	}
}

func TestDNSRedirect(t *testing.T) {
	e := setup(t)

	proxy, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	defer proxy.Close()
	proxyPort := uint16(proxy.LocalAddr().(*net.UDPAddr).Port)

	go func() {
		buf := make([]byte, 512)
		for {
			n, peer, err := proxy.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = proxy.WriteTo(buf[:n], peer)
		}
	}()

	prefix0, _ := netip.ParsePrefix("0.0.0.0/0")
	e.applyPolicyFull(20, bpfobj.ModeEnforce, bpfobj.DNSListed, proxyPort, []kern.Rule{{
		Dir: bpfobj.DirEgress, Proto: 17, Port: 53, Net: prefix0,
	}})
	cg := e.newWorkloadCgroup("dns")
	e.govern(cg, 20)

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("test-query")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read from redirected DNS: %v", err)
	}
	if string(buf[:n]) != "test-query" {
		t.Fatalf("answer = %q, want %q", buf[:n], "test-query")
	}
}

func TestRawSocketLSM(t *testing.T) {
	e := setup(t)
	if !e.k.LSM {
		t.Skip("BPF LSM not available on this kernel")
	}

	e.applyPolicy(30, bpfobj.ModeEnforce, bpfobj.DNSOff, nil)
	cg := e.newWorkloadCgroup("raw")
	e.govern(cg, 30)

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0)
	if err == nil {
		_ = syscall.Close(fd)
		t.Fatalf("AF_PACKET socket unexpectedly allowed")
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Logf("AF_PACKET error = %v (want EPERM)", err)
	}

	fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("AF_INET socket denied: %v", err)
	}
	_ = syscall.Close(fd)
}

func TestIngressDeny(t *testing.T) {
	e := setup(t)

	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	local := ln.LocalAddr().(*net.UDPAddr)

	sender, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sender listen: %v", err)
	}
	defer sender.Close()

	allowPort := uint16(12345)
	prefix, _ := netip.ParsePrefix("127.0.0.1/32")
	e.applyPolicy(40, bpfobj.ModeEnforce, bpfobj.DNSOff, []kern.Rule{{
		Dir: bpfobj.DirIngress, Proto: 17, Port: allowPort, Net: prefix,
	}})
	cg := e.newWorkloadCgroup("ingress")
	e.govern(cg, 40)

	if _, err := sender.WriteTo([]byte("hi"), local); err != nil {
		t.Fatalf("send: %v", err)
	}
	_ = ln.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 16)
	if _, _, err := ln.ReadFrom(buf); err == nil {
		t.Fatalf("packet from disallowed source was not dropped")
	} else {
		t.Logf("ingress drop observed: %v", err)
	}
}

func TestIsolation(t *testing.T) {
	e := setup(t)

	ws := []kern.Workload{{ID: 50, Mode: bpfobj.ModeEnforce, DNS: bpfobj.DNSOff, Isolated: true}}
	if err := e.k.ApplyPolicy(ws); err != nil {
		t.Fatalf("apply isolated: %v", err)
	}
	cg := e.newWorkloadCgroup("isolated")
	e.govern(cg, 50)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err == nil {
		_ = syscall.Close(fd)
		t.Fatalf("isolated workload created a socket")
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Logf("socket error = %v (want EPERM)", err)
	}
}

func TestGenerationSwap(t *testing.T) {
	e := setup(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	prefix, _ := netip.ParsePrefix("127.0.0.1/32")

	e.applyPolicy(60, bpfobj.ModeEnforce, bpfobj.DNSOff, []kern.Rule{{
		Dir: bpfobj.DirEgress, Proto: 6, Port: port, Net: prefix,
	}})
	cg := e.newWorkloadCgroup("gen")
	e.govern(cg, 60)

	if err := dialTCP(ln.Addr().(*net.TCPAddr), 2*time.Second); err != nil {
		t.Fatalf("gen1: connect failed: %v", err)
	}

	for i := 0; i < 20; i++ {
		e.applyPolicy(60, bpfobj.ModeEnforce, bpfobj.DNSOff, nil)
		if err := dialTCP(ln.Addr().(*net.TCPAddr), 500*time.Millisecond); err == nil {
			t.Fatalf("gen2: connect unexpectedly allowed (iteration %d)", i)
		}
	}
}

// ---------------------------------------------------------------- utilities

func dialTCP(addr *net.TCPAddr, d time.Duration) error {
	c, err := net.DialTimeout("tcp", addr.String(), d)
	if err != nil {
		return err
	}
	_ = c.Close()
	return nil
}

func sendUDP(addr *net.UDPAddr) error {
	c, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte("x"))
	return err
}
