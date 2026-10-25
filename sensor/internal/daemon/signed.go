// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

// The signed policy at this sensor (docs/pvp/edge.md, section 5). With
// policy.pin set, the sensor follows the organization's signed policy
// releases itself, as an egress proxy does: each release must be signed by
// the quorum of the manifest the sensor already trusts - the pinned one
// before the first - so the server, which only carries them, cannot forge or
// swap one. The manifest decides two things here:
//
//   - who may command this sensor: an administrator whose passkey it lists
//     (internal/trust.VerifyCommand); the server's command key is not
//     enough any more;
//   - which egress proxy binaries a proxy host lets out (proxyrun.go).
//
// The last verified release is kept in state_dir/release.json, so a restart
// does not need to trust the server again.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/canon"
	"github.com/kironovlaziz-del/provenza/sensor/internal/client"
	"github.com/kironovlaziz-del/provenza/sensor/internal/trust"
)

const (
	releaseFile = "release.json"
	seenFile    = "commands-seen.json"
)

type signedPolicy struct {
	pin string
	dir string

	mu  sync.RWMutex
	rel *trust.Release
	err string
}

type savedRelease struct {
	Pin string          `json:"pin"`
	Doc json.RawMessage `json:"doc"`
}

func newSignedPolicy(pin, dir string) *signedPolicy {
	if pin == "" {
		return nil
	}
	return &signedPolicy{pin: pin, dir: dir}
}

func (s *signedPolicy) current() *trust.Release {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rel
}

func (s *signedPolicy) report() *client.SignedPolicyReport {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := &client.SignedPolicyReport{Pin: "pinned", Error: s.err}
	if s.pin == "tofu" {
		st.Pin = "tofu"
	}
	if s.rel != nil {
		st.Release = s.rel.Number
	}
	return st
}

// load: the release verified before a restart (for the same pin), checked again.
func (s *signedPolicy) load() error {
	raw, err := os.ReadFile(filepath.Join(s.dir, releaseFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var saved savedRelease
	if err := json.Unmarshal(raw, &saved); err != nil || saved.Pin != s.pin {
		return nil // another pin: start from it again
	}
	doc, err := trust.ParseDocument(saved.Doc)
	if err != nil {
		return nil
	}
	r, _, err := trust.VerifyRelease(doc)
	if err != nil {
		return fmt.Errorf("%s does not verify: %w", releaseFile, err)
	}
	s.mu.Lock()
	s.rel = r
	s.mu.Unlock()
	return nil
}

func (s *signedPolicy) save(r *trust.Release) error {
	doc, err := json.Marshal(r.Doc)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(savedRelease{Pin: s.pin, Doc: doc})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, releaseFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, releaseFile))
}

// refresh takes newer releases (body: what GET /policy-release answered),
// each verified here. A release that does not verify is not taken; the
// last verified one stays in force.
func (s *signedPolicy) refresh(body []byte) error {
	err := s.advance(body)
	s.mu.Lock()
	s.err = ""
	if err != nil {
		s.err = err.Error()
	}
	s.mu.Unlock()
	return err
}

func (s *signedPolicy) advance(body []byte) error {
	cur := s.current()
	v, err := canon.Parse(body)
	if err != nil {
		return err
	}
	m, _ := v.(map[string]any)
	list, _ := m["chain"].([]any)
	chain := make([]map[string]any, 0, len(list))
	for _, d := range list {
		if doc, ok := d.(map[string]any); ok {
			chain = append(chain, doc)
		}
	}
	anchor := s.pin
	if anchor == "tofu" {
		anchor = ""
	}
	next, err := trust.Advance(cur, anchor, s.pin == "tofu", chain)
	if next != nil && next != cur {
		s.mu.Lock()
		s.rel = next
		s.mu.Unlock()
		if serr := s.save(next); serr != nil {
			return serr
		}
	}
	if err != nil {
		return err
	}
	if want, ok := m["current"].(json.Number); ok {
		n, _ := strconv.Atoi(string(want))
		if next == nil || next.Number < n {
			have := 0
			if next != nil {
				have = next.Number
			}
			return fmt.Errorf("the server's release #%d does not follow from the trusted one (#%d, pin %s): "+
				"keeping the last verified release", n, have, s.pin)
		}
	}
	return nil
}

// refreshSigned asks the server for newer releases.
func (d *Daemon) refreshSigned(ctx context.Context) {
	if d.signed == nil {
		return
	}
	after := 0
	if r := d.signed.current(); r != nil {
		after = r.Number
	}
	body, err := d.client.PolicyRelease(ctx, after)
	if err == nil {
		err = d.signed.refresh(body)
	}
	if err != nil {
		d.signed.mu.Lock()
		d.signed.err = err.Error()
		d.signed.mu.Unlock()
		slog.Warn("signed policy: keeping the last verified release", "err", err)
		return
	}
	if r := d.signed.current(); r != nil && r.Number != after {
		// a newer release: the workloads are held to it from now on
		d.mu.Lock()
		server := d.serverPolicy
		d.mu.Unlock()
		if server != nil {
			if err := d.applyPolicy(ctx, server); err != nil {
				slog.Warn("apply policy under the new signed release", "err", err)
			}
		}
	}
	d.checkProxyRuns() // the manifest's proxy binaries may have changed
}

// ---------------------------------------------------------------- used commands

// seenCommands remembers the signed commands this sensor carried out until
// they expire, so the server cannot replay one (state_dir/commands-seen.json).
type seenCommands struct {
	path string
	mu   sync.Mutex
	used map[string]int64 // nonce -> expires_at (unix)
}

func newSeenCommands(dir string) *seenCommands {
	s := &seenCommands{path: filepath.Join(dir, seenFile), used: map[string]int64{}}
	if raw, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(raw, &s.used)
	}
	return s
}

// use records nonce; false when it was used already. The record is on disk
// before the command runs (a restart command must not run twice).
func (s *seenCommands) use(nonce string, expires time.Time, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for n, until := range s.used {
		if until <= now.Unix() {
			delete(s.used, n)
		}
	}
	if _, ok := s.used[nonce]; ok {
		return false, nil
	}
	s.used[nonce] = expires.Unix()
	raw, err := json.Marshal(s.used)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return false, err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, s.path)
}
