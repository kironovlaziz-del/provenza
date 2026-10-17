// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"context"
	"sync"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/bpfobj"
)

// statsRing keeps the last minute of BPF counters so the daemon can report
// a per-minute rate alongside the raw totals. The kernel exposes only
// monotonic totals; without this the numbers in the UI would grow without
// bound and stop meaning anything. 61 slots at one sample per second cover
// exactly a minute plus the current tick.
const statsSlots = 61

type statsRing struct {
	mu sync.Mutex

	allowed  [statsSlots]uint64
	denied   [statsSlots]uint64
	observed [statsSlots]uint64

	// tick counts samples written so far. Below 2 there is no interval to
	// measure, so rates() returns zeros.
	tick uint64
}

func newStatsRing() *statsRing {
	return &statsRing{}
}

// push records one sample. Called from statsLoop once per second.
func (r *statsRing) push(allowed, denied, observed uint64) {
	r.mu.Lock()
	idx := r.tick % statsSlots
	r.allowed[idx] = allowed
	r.denied[idx] = denied
	r.observed[idx] = observed
	r.tick++
	r.mu.Unlock()
}

// rates returns the change over the last minute. While the ring is still
// filling it extrapolates the elapsed interval to a full minute, so the UI
// shows something plausible within the first few seconds after a restart.
func (r *statsRing) rates() (allowed, denied, observed uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.tick < 2 {
		return 0, 0, 0
	}

	cur := (r.tick - 1) % statsSlots
	var oldest uint64
	if r.tick >= statsSlots {
		oldest = (cur + 1) % statsSlots
	} else {
		oldest = 0
	}

	allowed = r.allowed[cur] - r.allowed[oldest]
	denied = r.denied[cur] - r.denied[oldest]
	observed = r.observed[cur] - r.observed[oldest]

	if r.tick < statsSlots {
		span := r.tick - 1
		allowed = allowed * 60 / span
		denied = denied * 60 / span
		observed = observed * 60 / span
	}
	return allowed, denied, observed
}

// statsAndRates is the shape status --json serializes: raw totals plus the
// per-minute rate computed from the ring.
func (d *Daemon) statsAndRates() StatsSection {
	a, dn, o := d.stats.rates()
	return StatsSection{
		DroppedEvents:  d.kernel.Stat(bpfobj.StatEventsLost),
		Allowed:        d.kernel.Stat(bpfobj.StatAllowed),
		Denied:         d.kernel.Stat(bpfobj.StatDenied),
		Observed:       d.kernel.Stat(bpfobj.StatObserved),
		AllowedPerMin:  a,
		DeniedPerMin:   dn,
		ObservedPerMin: o,
	}
}

// statsLoop feeds the ring once per second. It is the only writer.
func (d *Daemon) statsLoop(ctx context.Context) {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.stats.push(
				d.kernel.Stat(bpfobj.StatAllowed),
				d.kernel.Stat(bpfobj.StatDenied),
				d.kernel.Stat(bpfobj.StatObserved),
			)
		}
	}
}

// eventTime converts a kernel monotonic timestamp (bpf_ktime_get_ns) to
// wall-clock time. Returns nil if tsNs is zero (event predates the field
// or came from an older object) or if the offset could not be captured
// at startup. A nil Ts travels to the backend as an omitted JSON field,
// and the backend falls back to now() — the same behaviour as before this
// change, so old sensors keep working.
func (d *Daemon) eventTime(tsNs uint64) *time.Time {
	if !d.ktimeOffsetValid || tsNs == 0 {
		return nil
	}
	t := time.Unix(0, int64(tsNs)+int64(d.ktimeOffset)).UTC()
	return &t
}
