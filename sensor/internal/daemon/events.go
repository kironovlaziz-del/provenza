// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/kironovlaziz-del/provenza/sensor/internal/bpfobj"
	"github.com/kironovlaziz-del/provenza/sensor/internal/client"
)

var (
	eventSize = int(unsafe.Sizeof(bpfobj.Event{}))
	mkdirSize = int(unsafe.Sizeof(bpfobj.MkdirEvent{}))
)

// ringbufLoop reads violations and cgroup mkdir/rmdir events.
func (d *Daemon) ringbufLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		rec, err := d.rb.Read()
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			slog.Warn("ringbuf", "err", err)
			continue
		}
		if len(rec.RawSample) == 0 {
			continue
		}
		switch rec.RawSample[0] {
		case bpfobj.EvViolation:
			d.handleViolation(rec.RawSample)
		case bpfobj.EvMkdir, bpfobj.EvRmdir:
			d.handleMkdir(rec.RawSample)
		}
	}
}

func (d *Daemon) handleViolation(raw []byte) {
	if len(raw) < eventSize {
		return
	}
	var e bpfobj.Event
	if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &e); err != nil {
		return
	}
	v := client.Violation{
		WorkloadID: e.Wid,
		Action:     actionName(e.Action),
		Kind:       kindName(e.Kind),
		Protocol:   protoName(e.Proto),
		Isolated:   e.Isolated != 0,
		Count:      uint64(e.Count),
	}
	if p := int(e.Port); p != 0 {
		v.DstPort = &p
	}
	if ip, ok := addrOf(e.Family, e.Addr); ok {
		s := ip.String()
		v.DstIP = &s
	}
	if comm := strings.TrimRight(string(e.Comm[:]), "\x00"); comm != "" {
		v.Comm = &comm
	}
	d.viol.add(v)
}

func (d *Daemon) handleMkdir(raw []byte) {
	if len(raw) < mkdirSize {
		return
	}
	var m bpfobj.MkdirEvent
	if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &m); err != nil {
		return
	}
	path := strings.TrimRight(string(m.Path[:]), "\x00")
	rel := strings.TrimPrefix(path, "/")

	switch m.Type {
	case bpfobj.EvMkdir:
		d.mu.Lock()
		pats := append([]pattern(nil), d.patterns...)
		d.mu.Unlock()
		if wid, ok := matchPattern(pats, rel); ok {
			entry := bpfobj.CgEntry{Wid: wid, Kind: bpfobj.CgGoverned, Since: uint64(time.Now().UnixNano())}
			if err := d.kernel.SetCgroup(m.Cgid, entry); err != nil {
				slog.Warn("set cgroup from mkdir", "id", m.Cgid, "err", err)
			}
			d.mu.Lock()
			d.cgWid[m.Cgid] = wid
			d.mu.Unlock()
		}
	case bpfobj.EvRmdir:
		if err := d.kernel.DeleteCgroup(m.Cgid); err != nil {
			slog.Warn("delete cgroup", "id", m.Cgid, "err", err)
		}
		d.mu.Lock()
		delete(d.cgWid, m.Cgid)
		d.mu.Unlock()
	}
}

func actionName(a uint8) string {
	switch a {
	case bpfobj.ActObserved:
		return "observed"
	case bpfobj.ActAlerted:
		return "alerted"
	case bpfobj.ActBlocked:
		return "blocked"
	}
	return "observed"
}

func kindName(k uint8) string {
	switch k {
	case bpfobj.KindConnect:
		return "connect"
	case bpfobj.KindSend:
		return "send"
	case bpfobj.KindSocket:
		return "socket"
	case bpfobj.KindPacket:
		return "packet"
	case bpfobj.KindIngress:
		return "ingress"
	case bpfobj.KindDNS:
		return "dns"
	case bpfobj.KindFamily:
		return "family"
	}
	return "unknown"
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	}
	return ""
}

func addrOf(family uint8, raw [16]byte) (netip.Addr, bool) {
	switch family {
	case 2: // AF_INET
		return netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], raw[3]}), true
	case 10: // AF_INET6
		return netip.AddrFrom16(raw), true
	}
	return netip.Addr{}, false
}

// ---------------------------------------------------------------- buffer

// violationBuffer batches violations and posts them periodically.
type violationBuffer struct {
	cl *client.Client

	mu  sync.Mutex
	buf []client.Violation
}

func newViolationBuffer(cl *client.Client) *violationBuffer {
	return &violationBuffer{cl: cl}
}

func (b *violationBuffer) add(v client.Violation) {
	b.mu.Lock()
	b.buf = append(b.buf, v)
	b.mu.Unlock()
}

func (b *violationBuffer) run(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.flush(ctx)
		}
	}
}

func (b *violationBuffer) flush(ctx context.Context) {
	b.mu.Lock()
	if len(b.buf) == 0 {
		b.mu.Unlock()
		return
	}
	batch := b.buf
	b.buf = nil
	b.mu.Unlock()

	if err := b.cl.Violations(ctx, batch); err != nil {
		slog.Warn("post violations", "err", err)
		b.mu.Lock()
		b.buf = append(batch, b.buf...)
		b.mu.Unlock()
	}
}
