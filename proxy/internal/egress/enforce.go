// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

// The signed policy at this proxy (docs/pvp/edge.md, sections 3-4). With
// policy.mode "enforce" a request goes out only when BOTH the server's check
// AND the signed policy release this proxy verified itself allow it:
//
//   - releases come from the server, which is only the courier: each one must
//     be signed by the quorum of the manifest the proxy already trusts - the
//     pinned one (policy.pin) before the first, then each release's own - so a
//     server that forged or swapped a release gets nothing past here;
//   - the agent's own signed request (X-Provenza-Request) is checked here
//     against the key fingerprint the signed manifest names;
//   - a call the signed policy holds for approval goes out only with a human
//     approval the proxy verifies (the approver's passkey must be in the manifest);
//   - the route is the signed one: upstream, methods, prefixes and body limit
//     come from the release, not from the server's route table.
//
// The last verified release is kept in state_dir/release.json, so a restart
// does not need to trust the server again.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
	"github.com/kironovlaziz-del/provenza/proxy/internal/trust"
)

const releaseFile = "release.json"

type enforcer struct {
	cfg    PolicyConfig
	dir    string
	nonces *trust.Nonces

	mu  sync.RWMutex
	rel *trust.Release
}

type savedRelease struct {
	Pin string          `json:"pin"`
	Doc json.RawMessage `json:"doc"`
}

func newEnforcer(cfg PolicyConfig, dir string) *enforcer {
	return &enforcer{cfg: cfg, dir: dir, nonces: trust.NewNonces()}
}

func (e *enforcer) enforcing() bool { return e.cfg.Mode == "enforce" }

func (e *enforcer) current() *trust.Release {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rel
}

// load: the release verified before a restart (for the same pin), checked again.
func (e *enforcer) load() error {
	raw, err := os.ReadFile(filepath.Join(e.dir, releaseFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var s savedRelease
	if err := json.Unmarshal(raw, &s); err != nil || s.Pin != e.cfg.Pin {
		return nil // another pin: start from it again
	}
	doc, err := trust.ParseDocument(s.Doc)
	if err != nil {
		return nil
	}
	r, _, err := trust.VerifyRelease(doc)
	if err != nil {
		return fmt.Errorf("%s does not verify: %w", releaseFile, err)
	}
	e.mu.Lock()
	e.rel = r
	e.mu.Unlock()
	return nil
}

func (e *enforcer) save(r *trust.Release) error {
	doc, err := json.Marshal(r.Doc)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(savedRelease{Pin: e.cfg.Pin, Doc: doc})
	if err != nil {
		return err
	}
	tmp := filepath.Join(e.dir, releaseFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(e.dir, releaseFile))
}

// refresh takes newer releases from the server, each verified here.
func (e *enforcer) refresh(ctx context.Context, srv *server) error {
	cur := e.current()
	after := 0
	if cur != nil {
		after = cur.Number
	}
	raw, err := srv.callRaw(ctx, http.MethodGet, "/egress-proxy/policy-release?after="+strconv.Itoa(after), nil,
		srv.asProxy())
	if err != nil {
		return err
	}
	v, err := canon.Parse(raw)
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
	anchor := e.cfg.Pin
	if anchor == "tofu" {
		anchor = ""
	}
	next, err := trust.Advance(cur, anchor, e.cfg.Pin == "tofu", chain)
	if next != nil && next != cur {
		e.mu.Lock()
		e.rel = next
		e.mu.Unlock()
		if serr := e.save(next); serr != nil {
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
				"keeping the last verified release", n, have, e.cfg.Pin)
		}
	}
	return nil
}
