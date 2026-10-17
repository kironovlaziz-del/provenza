// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"testing"
)

// statsRing holds one sample per second in a 61-slot circular buffer,
// so rates() can compute the delta over the last minute. While the ring
// is still filling it extrapolates: total * 60 / elapsed, so the UI
// shows a plausible rate within a few seconds of a restart instead of
// a flat zero. The tests below cover both paths and the slot wrap.

func TestRatesEmpty(t *testing.T) {
	r := newStatsRing()
	a, d, o := r.rates()
	if a != 0 || d != 0 || o != 0 {
		t.Fatalf("empty ring: want 0,0,0 got %d,%d,%d", a, d, o)
	}
}

func TestRatesSingleSample(t *testing.T) {
	// One sample is not enough: there is no interval to measure.
	r := newStatsRing()
	r.push(100, 5, 10)
	a, d, o := r.rates()
	if a != 0 || d != 0 || o != 0 {
		t.Fatalf("one sample: want 0,0,0 got %d,%d,%d", a, d, o)
	}
}

func TestRatesTwoSamplesExtrapolates(t *testing.T) {
	// span = tick-1 = 1 second. Delta 10 over 1 second extrapolates to
	// 10 * 60 / 1 = 600 per minute. Same for denied and observed.
	r := newStatsRing()
	r.push(100, 0, 0)
	r.push(110, 5, 20)
	a, d, o := r.rates()
	if a != 600 || d != 300 || o != 1200 {
		t.Fatalf("two samples: want 600,300,1200 got %d,%d,%d", a, d, o)
	}
}

func TestRatesFilledRingUsesExactWindow(t *testing.T) {
	// Once the ring wraps (>= statsSlots samples), rates() returns the
	// raw delta over the last 60 seconds, no extrapolation.
	r := newStatsRing()
	// Fill exactly statsSlots samples: tick goes 0..60, ring index 0..60.
	// At the end, tick=61, cur=0 (61-1 % 61 = 0), oldest=1.
	// We want a delta of 60 over the whole window: push 0..60 then
	// a wrap of 60 means cur - oldest = 60.
	for i := 0; i <= statsSlots; i++ {
		r.push(uint64(i), uint64(i*2), uint64(i*3))
	}
	a, d, o := r.rates()
	// After 62 pushes (statsSlots+1), tick=62, cur=0, oldest=1.
	// buf[cur] = last pushed value (i=61), buf[oldest] = value at i=1.
	// delta = 61 - 1 = 60 for allowed, 122-2=120 for denied, 183-3=180 for observed.
	if a != 60 || d != 120 || o != 180 {
		t.Fatalf("filled ring: want 60,120,180 got %d,%d,%d", a, d, o)
	}
}

func TestRatesWrapsSafely(t *testing.T) {
	// Push many more samples than the buffer size; rates() must not
	// read past the ring or return stale data. A full ring of 61 slots
	// covers exactly 60 seconds (60 intervals between the 61 samples),
	// so the delta over one full window is 60 * rate.
	r := newStatsRing()
	for i := 0; i < statsSlots*3; i++ {
		r.push(uint64(i), uint64(i), uint64(i))
	}
	a, d, o := r.rates()
	// tick=3*61=183, cur=(183-1)%61=60, oldest=(60+1)%61=0.
	// buf[60] = i=182 (last push at slot 60), buf[0] = i=122 (last push
	// at slot 0 — value 122, not 121: the loop stops at i=182 and the
	// previous wrap landed on slot 0 at i=122 = 2*61).
	// delta = 182 - 122 = 60, i.e. exactly 60 seconds of rate.
	if a != 60 || d != 60 || o != 60 {
		t.Fatalf("wrapped ring: want 60,60,60 got %d,%d,%d", a, d, o)
	}
}

func TestRatesZeroDelta(t *testing.T) {
	// No new events between samples: zero rate, no false positives.
	r := newStatsRing()
	for i := 0; i < statsSlots+5; i++ {
		r.push(100, 5, 10)
	}
	a, d, o := r.rates()
	if a != 0 || d != 0 || o != 0 {
		t.Fatalf("zero delta: want 0,0,0 got %d,%d,%d", a, d, o)
	}
}
