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
		case bpfobj.EvAllowed:
			d.handleAllowed(rec.RawSample)
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
	v.Ts = d.eventTime(e.TsNs)
	d.viol.add(v)
}

func (d *Daemon) handleAllowed(raw []byte) {
	if len(raw) < eventSize {
		return
	}
	var e bpfobj.Event
	if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &e); err != nil {
		return
	}
	a := client.Activity{
		WorkloadID: e.Wid,
		Action:     actionName(e.Action),
		Kind:       kindName(e.Kind),
		Protocol:   protoName(e.Proto),
		Isolated:   e.Isolated != 0,
		Count:      uint64(e.Count),
	}
	if p := int(e.Port); p != 0 {
		a.DstPort = &p
	}
	if ip, ok := addrOf(e.Family, e.Addr); ok {
		s := ip.String()
		a.DstIP = &s
	}
	if comm := strings.TrimRight(string(e.Comm[:]), "\x00"); comm != "" {
		a.Comm = &comm
	}
	a.Ts = d.eventTime(e.TsNs)
	d.act.add(a)
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
	case bpfobj.ActAllowed:
		return "allowed"
	}
	return "unknown"
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

// maxBuffered caps what waits for the control plane per stream: about
// 15 MB of events. Past it the oldest are dropped (and counted), so a long
// outage cannot grow the daemon's memory without bound.
const maxBuffered = 50_000

// eventBuffer batches events and posts them every 2 seconds.
//
//   - Events the control plane accepted are never sent again (the client
//     reports how many of a batch went through).
//   - A network error, a 5xx, a timeout or a rate limit: the rest waits for
//     the next flush.
//   - A refusal (4xx): the refused request is split in halves until the
//     events it cannot take are found; only those are dropped and counted.
//     One malformed event never blocks the stream behind it.
type eventBuffer[T any] struct {
	name string
	send func(context.Context, []T) error

	mu      sync.Mutex
	buf     []T
	dropped uint64
}

type (
	violationBuffer = eventBuffer[client.Violation]
	activityBuffer  = eventBuffer[client.Activity]
)

func newViolationBuffer(cl *client.Client) *violationBuffer {
	b := &violationBuffer{name: "violations"}
	if cl != nil {
		b.send = cl.Violations
	}
	return b
}

// activityBuffer: sampled allowed connections. A separate queue, so a busy
// violations path cannot starve the activity feed (and vice versa).
func newActivityBuffer(cl *client.Client) *activityBuffer {
	b := &activityBuffer{name: "activity"}
	if cl != nil {
		b.send = cl.Activities
	}
	return b
}

func (b *eventBuffer[T]) add(e T) {
	b.mu.Lock()
	b.buf = append(b.buf, e)
	b.trimLocked()
	b.mu.Unlock()
}

// trimLocked drops the oldest events past maxBuffered.
func (b *eventBuffer[T]) trimLocked() {
	if over := len(b.buf) - maxBuffered; over > 0 {
		b.buf = append(b.buf[:0:0], b.buf[over:]...)
		b.dropped += uint64(over)
	}
}

// droppedTotal: events given up on (buffer full, or refused by the API).
func (b *eventBuffer[T]) droppedTotal() uint64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}

func (b *eventBuffer[T]) run(ctx context.Context) {
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

func (b *eventBuffer[T]) flush(ctx context.Context) {
	if b.send == nil {
		return
	}
	b.mu.Lock()
	if len(b.buf) == 0 {
		b.mu.Unlock()
		return
	}
	batch := b.buf
	b.buf = nil
	b.mu.Unlock()

	rest, refused := b.deliver(ctx, batch)
	if refused > 0 {
		slog.Warn("dropped events the control plane refused", "stream", b.name, "events", refused)
	}
	b.mu.Lock()
	b.dropped += uint64(refused)
	if len(rest) > 0 {
		b.buf = append(append(make([]T, 0, len(rest)+len(b.buf)), rest...), b.buf...)
		b.trimLocked()
	}
	b.mu.Unlock()
}

// deliver sends items and returns what must wait for the next flush and
// how many events were refused for good.
func (b *eventBuffer[T]) deliver(ctx context.Context, items []T) (rest []T, refused int) {
	if len(items) == 0 {
		return nil, 0
	}
	err := b.send(ctx, items)
	if err == nil {
		return nil, 0
	}
	sent := 0
	var se *client.SendError
	if errors.As(err, &se) {
		sent = se.Sent
	}
	items = items[sent:]
	if !client.IsPermanent(err) {
		slog.Warn("post events", "stream", b.name, "err", err, "waiting", len(items))
		return items, 0
	}
	// The request with items[:n] was refused: find the events it cannot take.
	n := min(len(items), client.MaxBatch)
	if n == 1 {
		r, k := b.deliver(ctx, items[1:])
		return r, k + 1
	}
	half := n / 2
	if r, k := b.deliver(ctx, items[:half]); len(r) > 0 {
		return append(append([]T{}, r...), items[half:]...), k
	} else {
		refused += k
	}
	if r, k := b.deliver(ctx, items[half:n]); len(r) > 0 {
		return append(append([]T{}, r...), items[n:]...), refused + k
	} else {
		refused += k
	}
	r, k := b.deliver(ctx, items[n:])
	return r, refused + k
}
