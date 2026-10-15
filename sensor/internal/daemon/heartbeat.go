// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"context"
	"log/slog"
	"os"
	"runtime"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/bpfobj"
	"github.com/kironovlaziz-del/provenza/sensor/internal/client"
)

func (d *Daemon) heartbeatLoop(ctx context.Context) {
	// Send one immediately so the UI sees us as soon as we are up.
	d.sendHeartbeat(ctx)

	t := time.NewTicker(d.heartbeatInterval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.sendHeartbeat(ctx)
		}
	}
}

func (d *Daemon) heartbeatInterval() time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.policy != nil && d.policy.HeartbeatSeconds > 0 {
		return time.Duration(d.policy.HeartbeatSeconds) * time.Second
	}
	return 30 * time.Second
}

func (d *Daemon) sendHeartbeat(ctx context.Context) {
	host, _ := os.Hostname()

	d.mu.Lock()
	ver := ""
	enforcing := false
	var wls []client.WorkloadReport
	if d.policy != nil {
		ver = d.policy.Version
		for _, w := range d.policy.Workloads {
			if w.Mode == "enforce" && !w.Isolated {
				enforcing = true
			}
			// Count governed cgroups inline. countCgroupsFor also takes
			// d.mu, and sync.Mutex is not reentrant - calling it here
			// deadlocks the daemon on its own lock (the heartbeat goroutine
			// holds d.mu and waits for itself, everything else queues behind).
			cg := 0
			for _, wid := range d.cgWid {
				if wid == w.ID {
					cg++
				}
			}
			wls = append(wls, client.WorkloadReport{ID: w.ID, Cgroups: cg})
		}
	}
	d.mu.Unlock()

	var cfgVer *string
	if ver != "" {
		v := ver
		cfgVer = &v
	}

	h := client.Heartbeat{
		Hostname:      host,
		Version:       d.version,
		Kernel:        runtime.GOOS + "/" + runtime.GOARCH,
		ConfigVersion: cfgVer,
		Enforcing:     enforcing,
		Hooks:         d.kernel.Hooks,
		Workloads:     wls,
		Warnings:      d.kernel.Notes,
		DroppedEvents: d.kernel.Stat(bpfobj.StatEventsLost),
	}
	if err := d.client.Heartbeat(ctx, h); err != nil {
		slog.Warn("heartbeat", "err", err)
	}
}
