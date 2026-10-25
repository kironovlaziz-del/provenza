// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

// The local kill switch (docs/pvp/edge.md, section 6). A sensor that follows
// the signed policy isolates every workload - nothing in or out - when
//
//   - it has not reached Provenza for the release's offline_seconds, counted
//     on the monotonic clock from the last answer (and, across a restart,
//     from the time kept in state_dir/contact.json), or
//   - the release it verified is past its not_after: an old release is never
//     used.
//
// It lifts itself once Provenza answers again (and the release is valid):
// the agents then still reach only their egress proxy, which stays stopped
// until administrators lift its own kill switch. An egress proxy run
// (proxyrun.go) is not isolated: the proxy stops itself and must reach
// Provenza to be lifted.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/client"
	"github.com/kironovlaziz-del/provenza/sensor/internal/config"
	"github.com/kironovlaziz-del/provenza/sensor/internal/trust"
)

const (
	contactFile           = "contact.json"
	defaultOfflineSeconds = 900
	killCheckEvery        = 5 * time.Second
	contactSaveEvery      = 30 * time.Second
)

type sensorKill struct {
	path string

	mu     sync.Mutex
	since  time.Time // the last contact known at start (monotonic)
	saved  time.Time // when contact.json was last written
	reason string    // engaged: why
}

type savedContact struct {
	Last int64 `json:"last"` // unix time of Provenza's last answer
}

// newSensorKill: the last contact, from contact.json across a restart.
func newSensorKill(dir string) *sensorKill {
	k := &sensorKill{path: filepath.Join(dir, contactFile), since: time.Now()}
	if raw, err := os.ReadFile(k.path); err == nil {
		var s savedContact
		if json.Unmarshal(raw, &s) == nil && s.Last > 0 {
			if ago := time.Since(time.Unix(s.Last, 0)); ago > 0 {
				k.since = time.Now().Add(-ago)
			}
		}
	}
	return k
}

func (k *sensorKill) engaged() string {
	if k == nil {
		return ""
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.reason
}

func releaseNumber(rel *trust.Release, key string, def int64) int64 {
	if n, err := strconv.ParseInt(fmt.Sprint(rel.Bundle[key]), 10, 64); err == nil && n > 0 {
		return n
	}
	return def
}

// killReason: why the kill switch should be engaged now ("" when not).
func killReason(rel *trust.Release, lastContact, now time.Time) string {
	if rel == nil {
		return ""
	}
	if notAfter := releaseNumber(rel, "not_after", 0); notAfter > 0 && now.Unix() > notAfter {
		return fmt.Sprintf("the signed release #%d has expired", rel.Number)
	}
	budget := time.Duration(releaseNumber(rel, "offline_seconds", defaultOfflineSeconds)) * time.Second
	if now.Sub(lastContact) > budget {
		return fmt.Sprintf("no contact with Provenza for more than %d s", int(budget.Seconds()))
	}
	return ""
}

// lastContact: Provenza's last answer, since this start or before it.
func (d *Daemon) lastContact() time.Time {
	last := d.ks.since
	if a := d.client.Answered(); a.After(last) {
		last = a
	}
	return last
}

// checkKillSwitch engages or lifts the kill switch; the policy is applied
// again when that changes.
func (d *Daemon) checkKillSwitch(ctx context.Context) {
	if d.ks == nil {
		return
	}
	last := d.lastContact()
	reason := killReason(d.signed.current(), last, time.Now())
	d.ks.mu.Lock()
	changed := reason != d.ks.reason
	d.ks.reason = reason
	save := !d.client.Answered().IsZero() && time.Since(d.ks.saved) > contactSaveEvery
	if save {
		d.ks.saved = time.Now()
	}
	d.ks.mu.Unlock()
	if save {
		wall := time.Now().Add(-time.Since(last)).Unix()
		if raw, err := json.Marshal(savedContact{Last: wall}); err == nil {
			tmp := d.ks.path + ".tmp"
			if err := os.WriteFile(tmp, raw, 0o600); err == nil {
				_ = os.Rename(tmp, d.ks.path)
			}
		}
	}
	if !changed {
		return
	}
	if reason != "" {
		slog.Error("LOCAL KILL SWITCH: every workload is isolated", "reason", reason)
	} else {
		slog.Warn("local kill switch lifted: Provenza answers and the signed release is valid")
	}
	d.mu.Lock()
	server := d.serverPolicy
	d.mu.Unlock()
	if server != nil {
		if err := d.applyPolicy(ctx, server); err != nil {
			slog.Error("apply policy for the kill switch", "err", err)
		}
	}
}

func (d *Daemon) killLoop(ctx context.Context) {
	t := time.NewTicker(killCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.checkKillSwitch(ctx)
		}
	}
}

// isolateAll: the policy with every workload isolated, for the kill switch.
func isolateAll(p *config.Policy, reason string) *config.Policy {
	out := *p
	out.Workloads = make([]config.Workload, len(p.Workloads))
	why := "local kill switch: " + reason
	for i, w := range p.Workloads {
		w.Isolated, w.IsolatedReason = true, &why
		out.Workloads[i] = w
	}
	return &out
}

// signedReport: what the sensor verified, with the kill switch.
func (d *Daemon) signedReport() *client.SignedPolicyReport {
	r := d.signed.report()
	if r != nil {
		r.KillSwitch = d.ks.engaged()
	}
	return r
}
