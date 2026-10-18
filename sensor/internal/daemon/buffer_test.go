// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/kironovlaziz-del/provenza/sensor/internal/client"
)

// fakeAPI stands in for the client: it sends in requests of client.MaxBatch
// like the real one and answers each request with status(request).
type fakeAPI struct {
	status   func(req []int) int
	accepted []int
	requests int
}

func (f *fakeAPI) send(_ context.Context, items []int) error {
	sent := 0
	for len(items) > 0 {
		n := min(len(items), client.MaxBatch)
		f.requests++
		if s := f.status(items[:n]); s/100 != 2 {
			return &client.SendError{Sent: sent, Err: &client.HTTPError{Path: "/violations", Status: s}}
		}
		f.accepted = append(f.accepted, items[:n]...)
		items = items[n:]
		sent += n
	}
	return nil
}

func newTestBuffer(f *fakeAPI, items int) *eventBuffer[int] {
	b := &eventBuffer[int]{name: "test", send: f.send}
	for i := 0; i < items; i++ {
		b.add(i)
	}
	return b
}

func TestBufferDropsOnlyTheRefusedEvent(t *testing.T) {
	// one malformed event (42) in 1200: the API refuses any request with it
	f := &fakeAPI{status: func(req []int) int {
		for _, v := range req {
			if v == 42 {
				return http.StatusUnprocessableEntity
			}
		}
		return http.StatusOK
	}}
	b := newTestBuffer(f, 1200)
	b.flush(context.Background())

	if len(b.buf) != 0 {
		t.Fatalf("nothing should wait after a refusal, %d still buffered", len(b.buf))
	}
	if b.droppedTotal() != 1 {
		t.Fatalf("dropped %d, want 1", b.droppedTotal())
	}
	if len(f.accepted) != 1199 {
		t.Fatalf("accepted %d, want 1199", len(f.accepted))
	}
	seen := map[int]bool{}
	for _, v := range f.accepted {
		if seen[v] {
			t.Fatalf("event %d sent twice", v)
		}
		seen[v] = true
	}
	// and the stream keeps flowing afterwards
	b.add(5000)
	b.flush(context.Background())
	if f.accepted[len(f.accepted)-1] != 5000 {
		t.Fatal("events after a refusal must still be delivered")
	}
}

func TestBufferKeepsEventsOnOutage(t *testing.T) {
	f := &fakeAPI{status: func([]int) int { return http.StatusServiceUnavailable }}
	b := newTestBuffer(f, 700)
	b.flush(context.Background())
	if len(b.buf) != 700 || b.droppedTotal() != 0 {
		t.Fatalf("on a 503 everything waits: buffered %d, dropped %d", len(b.buf), b.droppedTotal())
	}
	if b.buf[0] != 0 || b.buf[699] != 699 {
		t.Fatal("order must be kept")
	}
}

func TestBufferDoesNotResendAcceptedEvents(t *testing.T) {
	calls := 0
	f := &fakeAPI{status: func([]int) int {
		calls++
		if calls == 2 {
			return http.StatusBadGateway // the second request of the batch fails
		}
		return http.StatusOK
	}}
	b := newTestBuffer(f, 800)
	b.flush(context.Background())
	if len(f.accepted) != 500 || len(b.buf) != 300 || b.buf[0] != 500 {
		t.Fatalf("accepted %d, waiting %d (first %v): the accepted 500 must not wait again",
			len(f.accepted), len(b.buf), b.buf[0])
	}
	b.flush(context.Background())
	if len(f.accepted) != 800 || len(b.buf) != 0 {
		t.Fatalf("after the outage: accepted %d, waiting %d", len(f.accepted), len(b.buf))
	}
}

func TestBufferIsBounded(t *testing.T) {
	f := &fakeAPI{status: func([]int) int { return http.StatusServiceUnavailable }}
	b := newTestBuffer(f, maxBuffered+10)
	if len(b.buf) != maxBuffered || b.droppedTotal() != 10 {
		t.Fatalf("buffered %d, dropped %d", len(b.buf), b.droppedTotal())
	}
	if b.buf[0] != 10 {
		t.Fatalf("the oldest are dropped first, buffer starts at %d", b.buf[0])
	}
}

func TestPermanentErrors(t *testing.T) {
	for status, want := range map[int]bool{400: true, 413: true, 422: true, 408: false, 429: false, 500: false, 503: false} {
		err := &client.SendError{Err: &client.HTTPError{Status: status}}
		if got := client.IsPermanent(err); got != want {
			t.Errorf("HTTP %d: permanent=%v, want %v", status, got, want)
		}
	}
	if client.IsPermanent(errors.New("connection refused")) || client.IsPermanent(client.ErrUnauthorized) {
		t.Error("network errors and a refused key are not permanent")
	}
}
