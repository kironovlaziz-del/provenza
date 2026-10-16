// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

// Package daemon runs the egress sensor: it keeps the kernel program in
// step with the policy Provenza serves, governs cgroups, serves DNS for
// workloads, and reports violations.
package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/kironovlaziz-del/provenza/sensor/internal/client"
	"github.com/kironovlaziz-del/provenza/sensor/internal/config"
	"github.com/kironovlaziz-del/provenza/sensor/internal/kern"
)

// Daemon is the running sensor.
type Daemon struct {
	version string
	cfgPath string
	cfg     config.Settings
	client  *client.Client
	kernel  *kern.Kernel

	mu       sync.Mutex
	policy   *config.Policy
	patterns []pattern
	wls      map[uint32]*wlState
	cgWid    map[uint64]uint32
	uidSet   map[uint32]bool

	// startTime and lastPolicyAt are only read by snapshot; both are set
	// under mu or before any goroutine starts.
	startTime    time.Time
	lastPolicyAt time.Time

	rb     *ringbuf.Reader
	dns    *dnsServers
	viol   *violationBuffer
	run    *runServer
	status *statusServer

	// Loaded at start from the files enroll wrote. A nil signingKey or a
	// zero sensorID only disables command handling; policy enforcement
	// continues.
	signingKey ed25519.PublicKey
	sensorID   int
}

// wlState holds the per-workload data the daemon needs at runtime.
type wlState struct {
	cfg      config.Workload
	dnsPort  uint16
	dnsNames map[string]bool // names this workload may resolve (lowercase)
	dnsSfx   []string        // wildcard suffixes, with leading "."
}

// New builds the daemon. It loads the BPF object but does not attach it.
func New(cfgPath, version string) (*Daemon, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	cl, err := client.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}

	k, err := kern.Load(kern.Options{
		AttachCgroup: cfg.AttachCgroup,
		PinDir:       cfg.PinDir,
		RingBytes:    cfg.RingBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("kernel: %w", err)
	}

	d := &Daemon{
		version:   version,
		cfgPath:   cfgPath,
		cfg:       cfg,
		client:    cl,
		kernel:    k,
		wls:       map[uint32]*wlState{},
		cgWid:     map[uint64]uint32{},
		uidSet:    map[uint32]bool{},
		viol:      newViolationBuffer(cl),
		startTime: time.Now(),
	}
	d.dns = newDNSServers(d)

	// Command signing key and sensor id, both optional. Missing files are
	// not fatal: an old install that was never re-enrolled can still
	// enforce policy, it just cannot be commanded remotely.
	if key, err := loadSigningKey(cfg.SigningPublicKeyFile); err != nil {
		slog.Warn("no command signing key; commands will be refused", "err", err)
	} else {
		d.signingKey = key
	}
	if id, err := loadSensorID(cfg.SensorIDFile); err != nil {
		slog.Warn("no sensor id; commands will be refused", "err", err)
	} else {
		d.sensorID = id
	}

	return d, nil
}

// Run drives the daemon until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	defer d.kernel.Close()

	// Load the last policy from disk so we can already govern after a restart
	// even if Provenza is unreachable. Then try to get the current one.
	if p, err := client.LoadPolicy(d.cfg.StateDir); err != nil {
		slog.Warn("no cached policy", "err", err)
	} else if err := d.applyPolicy(ctx, p); err != nil {
		slog.Error("apply cached policy", "err", err)
	}
	if err := d.refreshPolicy(ctx); err != nil {
		slog.Warn("initial policy fetch failed", "err", err)
	}

	if err := d.kernel.Attach(kern.Options{
		AttachCgroup: d.cfg.AttachCgroup,
		PinDir:       d.cfg.PinDir,
		RingBytes:    d.cfg.RingBytes,
	}); err != nil {
		return fmt.Errorf("attach: %w", err)
	}

	// The status socket is read-only; start it only after attach, so a
	// client that asks before enforcement is up sees a coherent state.
	if err := d.startStatusServer(); err != nil {
		slog.Warn("status socket", "err", err)
	}

	rb, err := d.kernel.Reader()
	if err != nil {
		return fmt.Errorf("ringbuf: %w", err)
	}
	d.rb = rb

	var wg sync.WaitGroup
	start := func(fn func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(ctx)
		}()
	}

	if err := d.startRunServer(); err != nil {
		slog.Warn("run socket", "err", err)
	}

	start(d.policyLoop)
	start(d.heartbeatLoop)
	start(d.ringbufLoop)
	start(d.cgroupWalkLoop)
	start(d.viol.run)
	d.dns.start(ctx, &wg)

	<-ctx.Done()
	slog.Info("shutting down")
	if d.run != nil {
		d.run.close()
	}
	if d.status != nil {
		d.status.close()
	}
	d.dns.stop()
	if d.rb != nil {
		_ = d.rb.Close()
	}
	d.viol.flush(context.Background())
	wg.Wait()
	return nil
}

// policyLoop polls Provenza for a new policy.
func (d *Daemon) policyLoop(ctx context.Context) {
	for {
		interval := d.refreshInterval()
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
		if err := d.refreshPolicy(ctx); err != nil {
			if errors.Is(err, client.ErrUnauthorized) {
				slog.Error("policy: sensor key rejected, keeping current policy")
			} else {
				slog.Warn("policy refresh", "err", err)
			}
		}
	}
}

// refreshInterval returns the current refresh interval in seconds.
func (d *Daemon) refreshInterval() time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.policy != nil && d.policy.RefreshSeconds > 0 {
		return time.Duration(d.policy.RefreshSeconds) * time.Second
	}
	return 30 * time.Second
}

// refreshPolicy fetches the policy and applies it when it changed.
func (d *Daemon) refreshPolicy(ctx context.Context) error {
	d.mu.Lock()
	version := ""
	if d.policy != nil {
		version = d.policy.Version
	}
	d.mu.Unlock()

	p, err := d.client.Policy(ctx, version)
	if err != nil {
		return err
	}
	if p == nil {
		return nil // 304: current version is still in force
	}
	return d.applyPolicy(ctx, p)
}
