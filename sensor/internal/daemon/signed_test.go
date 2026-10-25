// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/canon"
	"github.com/kironovlaziz-del/provenza/sensor/internal/client"
	"github.com/kironovlaziz-del/provenza/sensor/internal/config"
	"github.com/kironovlaziz-del/provenza/sensor/internal/trust"
)

func testdata(t *testing.T, name string) map[string]any {
	raw, err := os.ReadFile("../../../sdk/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	v, err := canon.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

// the body GET /policy-release answers, from the trust vectors' releases
func chainBody(t *testing.T, docs []any, current int) []byte {
	raw, err := json.Marshal(map[string]any{"current": current, "chain": docs})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSignedPolicyFollowsThePinnedChain(t *testing.T) {
	v := testdata(t, "trust-vectors.json")
	docs := v["releases"].([]any)
	dir := t.TempDir()

	s := newSignedPolicy(v["pin"].(string), dir)
	if err := s.refresh(chainBody(t, docs, 3)); err != nil {
		t.Fatal(err)
	}
	if r := s.current(); r == nil || r.Number != 3 {
		t.Fatalf("%v", r)
	}
	if rep := s.report(); rep.Pin != "pinned" || rep.Release != 3 || rep.Error != "" {
		t.Fatalf("%+v", rep)
	}

	// a restart starts from the release verified before
	again := newSignedPolicy(v["pin"].(string), dir)
	if err := again.load(); err != nil || again.current() == nil || again.current().Number != 3 {
		t.Fatalf("%v %v", again.current(), err)
	}
	// another pin does not take it
	other := newSignedPolicy(strings.Repeat("0", 64), dir)
	if err := other.load(); err != nil || other.current() != nil {
		t.Fatal("a release saved under another pin was taken")
	}
	// and a pin nothing is governed by takes nothing
	if err := other.refresh(chainBody(t, docs, 3)); err == nil || other.current() != nil {
		t.Fatal("followed a chain the pin does not govern")
	}
	if other.report().Error == "" {
		t.Fatal("no error reported")
	}

	// a tampered release is not taken; the last verified one stays
	fresh := newSignedPolicy(v["pin"].(string), t.TempDir())
	var bad map[string]any
	raw, _ := json.Marshal(docs[2])
	bad, _ = trust.ParseDocument(raw)
	bad["signatures"] = bad["signatures"].([]any)[:1]
	if err := fresh.refresh(chainBody(t, []any{docs[0], docs[1], bad}, 3)); err == nil {
		t.Fatal("a release signed by one of two verified")
	}
	if r := fresh.current(); r == nil || r.Number != 2 {
		t.Fatalf("%v", r)
	}

	// trust on first use
	tofu := newSignedPolicy("tofu", t.TempDir())
	if err := tofu.refresh(chainBody(t, docs, 3)); err != nil || tofu.current().Number != 3 || tofu.report().Pin != "tofu" {
		t.Fatalf("%v %v", tofu.current(), err)
	}
	if newSignedPolicy("", dir) != nil {
		t.Fatal("a signed policy without a pin")
	}
}

func TestSeenCommands(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_800_000_000, 0)
	s := newSeenCommands(dir)
	if ok, err := s.use("n1", now.Add(time.Minute), now); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, _ := s.use("n1", now.Add(time.Minute), now); ok {
		t.Fatal("used twice")
	}
	// after a restart too
	if ok, _ := newSeenCommands(dir).use("n1", now.Add(time.Minute), now); ok {
		t.Fatal("used twice across a restart")
	}
	// forgotten once expired
	if ok, _ := newSeenCommands(dir).use("n1", now.Add(3*time.Minute), now.Add(2*time.Minute)); !ok {
		t.Fatal("an expired record was kept")
	}
	if _, err := os.Stat(filepath.Join(dir, seenFile)); err != nil {
		t.Fatal(err)
	}
}

type ack struct {
	id     string
	status string
	err    string
}

func commandDaemon(t *testing.T, pin string) (*Daemon, *[]ack, *[]client.Command) {
	var mu sync.Mutex
	acks := &[]ack{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		parts := strings.Split(r.URL.Path, "/")
		e, _ := body["error"].(string)
		*acks = append(*acks, ack{id: parts[len(parts)-2], status: body["status"].(string), err: e})
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	cl, err := client.New(config.Settings{ProvenzaURL: srv.URL, Key: "pvz_sensor_test"})
	if err != nil {
		t.Fatal(err)
	}
	ran := &[]client.Command{}
	d := &Daemon{client: cl, sensorID: 4, signed: newSignedPolicy(pin, t.TempDir()), seen: newSeenCommands(t.TempDir()),
		clock: func() time.Time { return time.Unix(1_800_000_000, 0) },
		executor: func(_ context.Context, c client.Command) error {
			*ran = append(*ran, c)
			return nil
		}}
	return d, acks, ran
}

func TestOnlyAnAdministratorsCommandRuns(t *testing.T) {
	v := testdata(t, "sensor-command-vectors.json")
	d, acks, ran := commandDaemon(t, "tofu")
	proof := func(who string) json.RawMessage {
		raw, err := json.Marshal(v[who])
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	cmd := func(id int, kind, who string) client.Command {
		c := client.Command{ID: id, Kind: kind}
		if who != "" {
			c.Proof = proof(who)
		}
		return c
	}
	ctx := context.Background()

	// no verified release yet: refused, and the administrator sees why
	if err := d.handleOneCommand(ctx, cmd(1, "restart", "admin")); err == nil {
		t.Fatal("ran without a verified release")
	}
	d.signed.rel = &trust.Release{Number: 7, Manifest: v["manifest"].(map[string]any)}

	for i, c := range []client.Command{
		cmd(2, "restart", ""), // the server's key only
		{ID: 2, Kind: "restart", Proof: json.RawMessage("null")}, // as the server sends it
		cmd(3, "restart", "approver"),                            // not an administrator
		cmd(4, "detach", "admin"),                                // signed for another kind
	} {
		if err := d.handleOneCommand(ctx, c); err == nil {
			t.Fatalf("case %d ran", i)
		}
	}
	if err := d.handleOneCommand(ctx, cmd(5, "restart", "admin")); err != nil {
		t.Fatal(err)
	}
	// the same signed command again (the server replays it): not run
	if err := d.handleOneCommand(ctx, cmd(6, "restart", "admin")); err == nil {
		t.Fatal("a replay ran")
	}
	if len(*ran) != 1 || (*ran)[0].ID != 5 {
		t.Fatalf("ran %+v", *ran)
	}
	want := map[string]string{"1": "no signed policy verified", "2": "not signed by an administrator",
		"3": "not an administrator", "4": "the administrator signed \"restart\"", "6": "carried out already"}
	if len(*acks) != len(want)+1 { // id 2 twice
		t.Fatalf("acks %+v", *acks)
	}
	for _, a := range *acks {
		if a.status != "failed" || !strings.Contains(a.err, want[a.id]) {
			t.Errorf("ack %+v", a)
		}
	}
}
