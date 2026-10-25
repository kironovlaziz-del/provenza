// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/config"
	"github.com/kironovlaziz-del/provenza/sensor/internal/trust"
)

func TestKillReason(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	rel := &trust.Release{Number: 4, Bundle: map[string]any{"not_after": json.Number("1800000600"),
		"offline_seconds": json.Number("300")}}
	if r := killReason(rel, now.Add(-299*time.Second), now); r != "" {
		t.Fatal(r)
	}
	if r := killReason(rel, now.Add(-301*time.Second), now); !strings.Contains(r, "300 s") {
		t.Fatal(r)
	}
	if r := killReason(rel, now, now.Add(time.Hour)); !strings.Contains(r, "expired") {
		t.Fatal(r)
	}
	if r := killReason(nil, time.Time{}, now); r != "" {
		t.Fatal("no release: no kill switch", r)
	}
	// no offline_seconds: the default
	if r := killReason(&trust.Release{Bundle: map[string]any{}}, now.Add(-899*time.Second), now); r != "" {
		t.Fatal(r)
	}
}

func TestTheKillSwitchIsolatesEveryWorkload(t *testing.T) {
	p := &config.Policy{Schema: 1, Workloads: []config.Workload{{ID: 1, Mode: "observe"}, {ID: 2, Mode: "enforce"}}}
	d := &Daemon{signed: &signedPolicy{pin: "tofu"}, ks: &sensorKill{reason: "no contact"}}
	eff, notes := d.effectivePolicy(p)
	for _, w := range eff.Workloads {
		if !w.Isolated || !strings.Contains(*w.IsolatedReason, "kill switch") {
			t.Fatalf("%+v", w)
		}
	}
	if p.Workloads[0].Isolated || len(notes) != 2 {
		t.Fatalf("the server's policy was changed, or notes %q", notes)
	}
	d.ks.reason = ""
	if eff, _ := d.effectivePolicy(p); eff.Workloads[0].Isolated {
		t.Fatal("isolated without the kill switch")
	}
	if eff, _ := (&Daemon{}).effectivePolicy(p); eff != p {
		t.Fatal("a sensor without a pin changed the policy")
	}
}

func TestContactSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	raw, _ := json.Marshal(savedContact{Last: time.Now().Add(-2 * time.Hour).Unix()})
	if err := os.WriteFile(filepath.Join(dir, contactFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	k := newSensorKill(dir)
	if ago := time.Since(k.since); ago < 119*time.Minute || ago > 121*time.Minute {
		t.Fatalf("last contact %v ago", ago)
	}
	if fresh := newSensorKill(t.TempDir()); time.Since(fresh.since) > time.Second {
		t.Fatal("a first start counts from now")
	}
}
