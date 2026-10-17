// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/bpfobj"
)

// ----------------------------------------------------------------- mapping

// actionName maps the BPF action enum to the string the backend expects.
// The mapping is stable: the backend's schema and the UI's icon depend
// on it. ActAllowed was added for the activity feed; unknown values must
// return "unknown" (not "observed"), which was the C3 fix.
func TestActionNameMapping(t *testing.T) {
	cases := map[uint8]string{
		bpfobj.ActObserved: "observed",
		bpfobj.ActAlerted:  "alerted",
		bpfobj.ActBlocked:  "blocked",
		bpfobj.ActAllowed:  "allowed",
		99:                 "unknown",
		0:                  "unknown",
	}
	for in, want := range cases {
		if got := actionName(in); got != want {
			t.Errorf("actionName(%d): want %q got %q", in, want, got)
		}
	}
}

func TestKindNameMapping(t *testing.T) {
	cases := map[uint8]string{
		bpfobj.KindConnect: "connect",
		bpfobj.KindSend:    "send",
		bpfobj.KindSocket:  "socket",
		bpfobj.KindPacket:  "packet",
		bpfobj.KindIngress: "ingress",
		bpfobj.KindDNS:     "dns",
		bpfobj.KindFamily:  "family",
		0:                  "unknown",
	}
	for in, want := range cases {
		if got := kindName(in); got != want {
			t.Errorf("kindName(%d): want %q got %q", in, want, got)
		}
	}
}

func TestProtoNameMapping(t *testing.T) {
	cases := map[uint8]string{
		6:  "tcp",
		17: "udp",
		1:  "icmp",
		0:  "",
		99: "",
	}
	for in, want := range cases {
		if got := protoName(in); got != want {
			t.Errorf("protoName(%d): want %q got %q", in, want, got)
		}
	}
}

// ------------------------------------------------------------------ addr

func TestAddrOfIPv4(t *testing.T) {
	var raw [16]byte
	copy(raw[:], []byte{1, 2, 3, 4})
	addr, ok := addrOf(2, raw) // AF_INET
	if !ok {
		t.Fatal("addrOf: want ok for family=2")
	}
	if want := netip.MustParseAddr("1.2.3.4"); addr != want {
		t.Errorf("addrOf v4: want %v got %v", want, addr)
	}
}

func TestAddrOfIPv6(t *testing.T) {
	raw := netip.MustParseAddr("2001:db8::1").As16()
	addr, ok := addrOf(10, raw) // AF_INET6
	if !ok {
		t.Fatal("addrOf: want ok for family=10")
	}
	if want := netip.MustParseAddr("2001:db8::1"); addr != want {
		t.Errorf("addrOf v6: want %v got %v", want, addr)
	}
}

func TestAddrOfUnknownFamily(t *testing.T) {
	var raw [16]byte
	if _, ok := addrOf(99, raw); ok {
		t.Errorf("addrOf: want false for family=99, got ok")
	}
}

// --------------------------------------------------------------- decode

// buildRaw serialises an Event the way the kernel does: native endian,
// exact struct layout. The same binary.Read path in handleViolation is
// exercised by the round trip.
func buildRaw(t *testing.T, e bpfobj.Event) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, e); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	return buf.Bytes()
}

// newTestDaemon builds a Daemon with just the buffers handleViolation
// and handleAllowed need. The kernel, client and clocks stay nil/zero:
// neither handler touches them.
func newTestDaemon() *Daemon {
	return &Daemon{
		viol: newViolationBuffer(nil),
		act:  newActivityBuffer(nil),
	}
}

func TestHandleViolationDecodesAllFields(t *testing.T) {
	var comm [16]byte
	copy(comm[:], "curl")
	var addr [16]byte
	copy(addr[:], []byte{1, 2, 3, 4})

	e := bpfobj.Event{
		Type:     bpfobj.EvViolation,
		Action:   bpfobj.ActBlocked,
		Kind:     bpfobj.KindConnect,
		Proto:    6,  // tcp
		Family:   2,  // AF_INET
		Isolated: 1,
		Port:     443,
		Wid:      7,
		Count:    3,
		Addr:     addr,
		Comm:     comm,
	}

	d := newTestDaemon()
	d.handleViolation(buildRaw(t, e))

	if len(d.viol.buf) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(d.viol.buf))
	}
	v := d.viol.buf[0]
	if v.WorkloadID != 7 {
		t.Errorf("WorkloadID: want 7 got %d", v.WorkloadID)
	}
	if v.Action != "blocked" {
		t.Errorf("Action: want blocked got %q", v.Action)
	}
	if v.Kind != "connect" {
		t.Errorf("Kind: want connect got %q", v.Kind)
	}
	if v.Protocol != "tcp" {
		t.Errorf("Protocol: want tcp got %q", v.Protocol)
	}
	if !v.Isolated {
		t.Error("Isolated: want true")
	}
	if v.Count != 3 {
		t.Errorf("Count: want 3 got %d", v.Count)
	}
	if v.DstIP == nil || *v.DstIP != "1.2.3.4" {
		t.Errorf("DstIP: want 1.2.3.4 got %v", v.DstIP)
	}
	if v.DstPort == nil || *v.DstPort != 443 {
		t.Errorf("DstPort: want 443 got %v", v.DstPort)
	}
	if v.Comm == nil || *v.Comm != "curl" {
		t.Errorf("Comm: want curl got %v", v.Comm)
	}
	// TsNs was 0 in the event, so eventTime returns nil; the backend
	// falls back to now(). This is the "old sensor / no clock" path.
	if v.Ts != nil {
		t.Errorf("Ts: want nil when TsNs=0, got %v", v.Ts)
	}
}

func TestHandleViolationConvertsTsNs(t *testing.T) {
	// With a valid offset, the event's TsNs becomes a *time.Time. This is
	// the whole point of the ts_ns patch: the DB gets the moment of the
	// kernel decision, not the batch flush.
	wall := time.Date(2026, 10, 17, 3, 15, 51, 0, time.UTC)
	// pretend kernel monotonic was 1s; offset converts it to wall.
	offset := time.Duration(wall.UnixNano() - 1_000_000_000)
	e := bpfobj.Event{
		Type:   bpfobj.EvViolation,
		Action: bpfobj.ActAllowed,
		Kind:   bpfobj.KindConnect,
		Proto:  6,
		Family: 2,
		Port:   443,
		Wid:    1,
		Count:  1,
		TsNs:   1_500_000_000, // monotonic 1.5s
	}

	d := newTestDaemon()
	d.ktimeOffset = offset
	d.ktimeOffsetValid = true
	d.handleViolation(buildRaw(t, e))

	if len(d.viol.buf) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(d.viol.buf))
	}
	v := d.viol.buf[0]
	if v.Ts == nil {
		t.Fatal("Ts: want non-nil, got nil")
	}
	// Ts = Unix(0, 1.5e9 + (wall - 1e9)) = wall + 0.5s.
	want := wall.Add(500 * time.Millisecond)
	if !v.Ts.Equal(want) {
		t.Errorf("Ts: want %v got %v", want, *v.Ts)
	}
}

func TestHandleViolationShortBuffer(t *testing.T) {
	d := newTestDaemon()
	d.handleViolation([]byte{1, 2, 3}) // way shorter than eventSize
	if len(d.viol.buf) != 0 {
		t.Errorf("short buffer must be ignored, got %d violations", len(d.viol.buf))
	}
}

func TestHandleAllowedDecodesAllFields(t *testing.T) {
	var comm [16]byte
	copy(comm[:], "curl")
	var addr [16]byte
	a4 := netip.MustParseAddr("1.1.1.1").As4()
	copy(addr[:], a4[:])

	e := bpfobj.Event{
		Type:   bpfobj.EvAllowed,
		Action: bpfobj.ActAllowed,
		Kind:   bpfobj.KindConnect,
		Proto:  6,
		Family: 2,
		Port:   443,
		Wid:    1,
		Count:  1,
		Addr:   addr,
		Comm:   comm,
	}
	d := newTestDaemon()
	d.handleAllowed(buildRaw(t, e))

	if len(d.act.buf) != 1 {
		t.Fatalf("expected 1 activity, got %d", len(d.act.buf))
	}
	a := d.act.buf[0]
	if a.Action != "allowed" {
		t.Errorf("Action: want allowed got %q", a.Action)
	}
	if a.WorkloadID != 1 {
		t.Errorf("WorkloadID: want 1 got %d", a.WorkloadID)
	}
	if a.DstIP == nil || *a.DstIP != "1.1.1.1" {
		t.Errorf("DstIP: want 1.1.1.1 got %v", a.DstIP)
	}
	if a.DstPort == nil || *a.DstPort != 443 {
		t.Errorf("DstPort: want 443 got %v", a.DstPort)
	}
}

func TestHandleAllowedShortBuffer(t *testing.T) {
	d := newTestDaemon()
	d.handleAllowed([]byte{1, 2, 3})
	if len(d.act.buf) != 0 {
		t.Errorf("short buffer must be ignored, got %d activities", len(d.act.buf))
	}
}

// TestEventSizeMatchesKernelLayout guards the ts_ns change: the struct
// grew from 64 to 72 bytes when we added the field. If anyone adds
// another field without updating both sides (bpf/sensor.bpf.c and
// internal/bpfobj/bpfobj.go), every event will be decoded at the wrong
// offset — silently.
func TestEventSizeMatchesKernelLayout(t *testing.T) {
	// 72 = 6×u8 + u16 + 4×u32 + u64 + 2×[16]u8 + u64 (with padding).
	// The number is asserted in bpfobj_test via BTF; here we assert the
	// same constant holds after the ts_ns addition, from the daemon side.
	const want = 72
	if got := eventSize; got != want {
		t.Fatalf("eventSize: want %d got %d — struct layout changed, update bpfobj and bpf/sensor.bpf.c together", want, got)
	}
}
