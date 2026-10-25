// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/config"
)

// newTestClient builds a Client pointed at a local httptest.Server.
// config.Settings has defaults for every non-URL field, so only the URL
// and key need to be overridden.
func newTestClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	cfg := config.Defaults()
	cfg.ProvenzaURL = baseURL
	cfg.Key = "test-key"
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// jsonBody decodes the request body into out.
func jsonBody(t *testing.T, r *http.Request, out any) {
	t.Helper()
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("decode body (%s): %v", string(b), err)
	}
}

// TestHeartbeatKeepsZeroPerMin is the regression test for the bug we hit
// during the per_min rollout: 'omitempty' on AllowedPerMin hid the field
// when the value was 0, so the backend could not tell "0 per minute" from
// "field missing" and the UI kept showing the old total. The struct tags
// were changed to keep the field; this test ensures they stay that way.
func TestHeartbeatKeepsZeroPerMin(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/heartbeat") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		jsonBody(t, r, &got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.Heartbeat(context.Background(), Heartbeat{
		Hostname:       "h1",
		Version:        "v1",
		Kernel:         "linux/amd64",
		AllowedTotal:   100,
		DeniedTotal:    5,
		ObservedTotal:  10,
		AllowedPerMin:  0, // the point of the test
		DeniedPerMin:   0,
		ObservedPerMin: 0,
	})
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	for _, key := range []string{"allowed_per_min", "denied_per_min", "observed_per_min"} {
		if _, ok := got[key]; !ok {
			t.Errorf("%s is missing from the heartbeat payload; omitempty must not be set on it", key)
		}
	}
}

// TestHeartbeatSendsNonZeroPerMin covers the other direction.
func TestHeartbeatSendsNonZeroPerMin(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonBody(t, r, &got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.Heartbeat(context.Background(), Heartbeat{
		Hostname: "h1", Version: "v1", Kernel: "linux/amd64",
		AllowedPerMin: 42, DeniedPerMin: 7, ObservedPerMin: 3,
	})
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if v, _ := got["allowed_per_min"].(float64); v != 42 {
		t.Errorf("allowed_per_min: want 42 got %v", got["allowed_per_min"])
	}
	if v, _ := got["denied_per_min"].(float64); v != 7 {
		t.Errorf("denied_per_min: want 7 got %v", got["denied_per_min"])
	}
	if v, _ := got["observed_per_min"].(float64); v != 3 {
		t.Errorf("observed_per_min: want 3 got %v", got["observed_per_min"])
	}
}

// TestViolationIncludesTs guards the ts_ns end-to-end path: the daemon
// puts the kernel-supplied wall-clock time into Violation.Ts, and the
// JSON payload must carry it as an RFC3339 string with microseconds.
func TestViolationIncludesTs(t *testing.T) {
	var body struct {
		Events []map[string]any `json:"events"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonBody(t, r, &body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"accepted":1,"dropped":0}`))
	}))
	defer srv.Close()

	when := time.Date(2026, 10, 17, 3, 15, 51, 189642000, time.UTC)
	c := newTestClient(t, srv.URL)
	if err := c.Violations(context.Background(), []Violation{{
		WorkloadID: 1,
		Action:     "blocked",
		Kind:       "connect",
		Protocol:   "tcp",
		Count:      1,
		Ts:         &when,
	}}); err != nil {
		t.Fatalf("Violations: %v", err)
	}

	if len(body.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(body.Events))
	}
	ts, ok := body.Events[0]["ts"].(string)
	if !ok {
		t.Fatalf("ts missing or not a string: %v", body.Events[0]["ts"])
	}
	parsed, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		t.Fatalf("ts is not RFC3339: %v", err)
	}
	if !parsed.Equal(when) {
		t.Errorf("ts mismatch: want %v got %v", when, parsed)
	}
}

// TestActivityIncludesTs is the same shape for the activity stream.
func TestActivityIncludesTs(t *testing.T) {
	var body struct {
		Events []map[string]any `json:"events"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/activity") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		jsonBody(t, r, &body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"accepted":1,"dropped":0}`))
	}))
	defer srv.Close()

	when := time.Date(2026, 10, 17, 3, 15, 51, 500000000, time.UTC)
	c := newTestClient(t, srv.URL)
	if err := c.Activities(context.Background(), []Activity{{
		WorkloadID: 1,
		Action:     "allowed",
		Kind:       "connect",
		Protocol:   "tcp",
		Count:      1,
		Ts:         &when,
	}}); err != nil {
		t.Fatalf("Activities: %v", err)
	}

	ts, ok := body.Events[0]["ts"].(string)
	if !ok {
		t.Fatalf("ts missing on activity")
	}
	parsed, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		t.Fatalf("ts is not RFC3339: %v", err)
	}
	if !parsed.Equal(when) {
		t.Errorf("ts mismatch: want %v got %v", when, parsed)
	}
}

// TestViolationOmitsNilTs guards the "old sensor, no ts" path: a nil Ts
// must not serialize as null. The backend treats an absent key as
// "no timestamp, use now()".
func TestViolationOmitsNilTs(t *testing.T) {
	var body struct {
		Events []map[string]any `json:"events"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonBody(t, r, &body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"accepted":1,"dropped":0}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	if err := c.Violations(context.Background(), []Violation{{
		WorkloadID: 1, Action: "blocked", Kind: "connect", Count: 1, // no Ts
	}}); err != nil {
		t.Fatalf("Violations: %v", err)
	}
	if _, ok := body.Events[0]["ts"]; ok {
		t.Errorf("nil Ts must be omitted, got %v", body.Events[0]["ts"])
	}
}

// TestHeartbeatOmitsEmptySlices verifies the documented contract: nil
// slices encode as "omitempty" and are left out, not sent as null.
func TestHeartbeatOmitsEmptySlices(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.Heartbeat(context.Background(), Heartbeat{
		Hostname: "h1", Version: "v1", Kernel: "linux/amd64",
	})
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	for _, key := range []string{"\"hooks\":null", "\"warnings\":null", "\"errors\":null"} {
		if strings.Contains(body, key) {
			t.Errorf("expected %s to be omitted, body was %s", key, body)
		}
	}
}

// A refused key is no contact: a revoked sensor, or someone answering in
// Provenza's place, does not keep the local kill switch away.
func TestARefusedKeyIsNoContact(t *testing.T) {
	status := http.StatusUnauthorized
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"chain":[]}`))
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	for _, s := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		status = s
		_, _ = c.PolicyRelease(context.Background(), 0)
		if !c.Answered().IsZero() {
			t.Fatalf("HTTP %d counted as contact", s)
		}
	}
	status = http.StatusOK
	_, _ = c.PolicyRelease(context.Background(), 0)
	if c.Answered().IsZero() {
		t.Fatal("an answer did not count as contact")
	}
}
