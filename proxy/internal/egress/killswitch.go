// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

// The local kill switch (docs/pvp/edge.md, sections 6-7). With policy.mode
// "enforce", a proxy that has not reached Provenza for the release's
// offline_seconds (counted on the monotonic clock from the last answer)
// stops: every request is refused, until administrators lift it. The state
// is kept in state_dir/killswitch.json with the release held before the
// outage, so a restart does not lift it.
//
// When Provenza answers again the proxy stays stopped and compares, item by
// item, what the server states now with that release: the manifest (agent
// keys, administrators' passkeys and quorum, proxies' and sensors' keys, the
// sensor command key, the proxy binaries), the Tool Registry pins, and the
// credentials sealed to it. A difference the newest release it verified
// states is "signed"; any other is not - a key that changed without a
// signed manifest. The report is signed with the proxy's key (and logged in
// its receipt chain) and sent to Provenza, which raises an incident for
// each difference.
//
// The quorum of the release held before the outage lifts it: each
// administrator signs, with a passkey that release lists, the report's hash
// and the differences they accept - every unsigned one must be accepted
// (or undone, which makes a new report). trust.VerifyLift checks them here.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
	"github.com/kironovlaziz-del/provenza/proxy/internal/trust"
)

const (
	killSwitchFile        = "killswitch.json"
	defaultOfflineSeconds = 900
	reconcileEvery        = 10 // guard ticks (seconds)
	reportType            = "provenza.reconciliation"
)

// manifestSections compared after an outage (app/pvp/policy_bundle.py MANIFEST_SECTIONS).
var manifestSections = []string{"quorum", "signers", "agents", "egress_proxies", "egress_sensors",
	"sensor_command_key", "proxy_binaries", "proxy_configs"}

type engagedState struct {
	EngagedAt int64             `json:"engaged_at"`
	Reason    string            `json:"reason"`
	Release   json.RawMessage   `json:"release"`   // the release held before the outage, as signed
	Envelopes map[string]string `json:"envelopes"` // SHA-256 of the envelopes held then, "<object>:<id>"
	before    *trust.Release
}

type killSwitch struct {
	path string
	mu   sync.Mutex
	st   *engagedState
	// the report last sent, by hash
	posted string
}

func newKillSwitch(dir string) *killSwitch {
	return &killSwitch{path: filepath.Join(dir, killSwitchFile)}
}

// load: a kill switch engaged before a restart stays engaged.
func (k *killSwitch) load() error {
	raw, err := os.ReadFile(k.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var st engagedState
	if err := json.Unmarshal(raw, &st); err != nil {
		return fmt.Errorf("%s: %w", killSwitchFile, err)
	}
	doc, err := trust.ParseDocument(st.Release)
	if err != nil {
		return fmt.Errorf("%s: %w", killSwitchFile, err)
	}
	rel, _, err := trust.VerifyRelease(doc)
	if err != nil {
		return fmt.Errorf("%s: the release held before the outage does not verify: %w", killSwitchFile, err)
	}
	st.before = rel
	k.mu.Lock()
	k.st = &st
	k.mu.Unlock()
	return nil
}

func (k *killSwitch) engagedNow() (bool, string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.st == nil {
		return false, ""
	}
	return true, k.st.Reason
}

func offlineBudget(rel *trust.Release) time.Duration {
	if n, err := strconv.ParseInt(fmt.Sprint(rel.Bundle["offline_seconds"]), 10, 64); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return defaultOfflineSeconds * time.Second
}

// check engages the kill switch when Provenza has been unreachable for
// longer than the release allows; whether it is engaged.
func (k *killSwitch) check(p *Proxy, rel *trust.Release) bool {
	if engaged, _ := k.engagedNow(); engaged {
		return true
	}
	down, since := p.srv.contact.state()
	budget := offlineBudget(rel)
	if !down || since <= budget {
		return false
	}
	k.engage(p, rel, fmt.Sprintf("Provenza unreachable for more than %d s", int(budget.Seconds())))
	return true
}

func (k *killSwitch) engage(p *Proxy, rel *trust.Release, reason string) {
	doc, err := json.Marshal(rel.Doc)
	if err != nil {
		p.log.Error("provenza proxy: kill switch", "err", err)
	}
	p.mu.RLock()
	env := make(map[string]string, len(p.envelopes))
	for key, sum := range p.envelopes {
		env[key] = sum
	}
	p.mu.RUnlock()
	st := &engagedState{EngagedAt: time.Now().Unix(), Reason: reason, Release: doc, Envelopes: env, before: rel}
	k.mu.Lock()
	if k.st != nil {
		k.mu.Unlock()
		return
	}
	k.st = st
	k.mu.Unlock()
	raw, err := json.Marshal(st)
	if err == nil {
		tmp := k.path + ".tmp"
		if err = os.WriteFile(tmp, raw, 0o600); err == nil {
			err = os.Rename(tmp, k.path)
		}
	}
	if err != nil {
		p.log.Error("provenza proxy: could not keep the kill switch on disk (a restart would forget it)", "err", err)
	}
	p.log.Error("provenza proxy: LOCAL KILL SWITCH - every request is refused until administrators lift it",
		"reason", reason, "release", rel.Number)
}

func (k *killSwitch) lift() error {
	k.mu.Lock()
	k.st, k.posted = nil, ""
	k.mu.Unlock()
	if err := os.Remove(k.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// guard: the kill switch's clock, the hand-over of offline actions and,
// while engaged, the reconciliation.
func (p *Proxy) guard(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for n := 1; ; n++ {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if rel := p.enf.current(); rel != nil && p.enf.enforcing() {
			p.ks.check(p, rel)
		}
		if n%reconcileEvery != 0 {
			continue
		}
		if down, _ := p.srv.contact.state(); down {
			// is it back?
			pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			_, _ = p.srv.callRaw(pctx, http.MethodGet, "/egress-proxy/config", nil, p.srv.asProxy())
			cancel()
		}
		p.uploadOffline(ctx)
		if engaged, _ := p.ks.engagedNow(); engaged {
			if err := p.reconcile(ctx); err != nil {
				p.log.Warn("provenza proxy: reconciliation", "err", err)
			}
		}
	}
}

// reconcile: the report, sent when it changed, and the lift when the quorum signed it.
func (p *Proxy) reconcile(ctx context.Context) error {
	if down, _ := p.srv.contact.state(); down {
		return nil
	}
	if p.reg == nil || p.wit == nil {
		return errors.New("this proxy has no registered key: it cannot sign a report")
	}
	if err := p.enf.refresh(ctx, p.srv); err != nil {
		p.log.Warn("provenza proxy: signed policy", "err", err)
	}
	state, err := p.srv.reconciliationState(ctx)
	if err != nil {
		return err
	}
	if err := p.refreshCredentials(ctx); err != nil {
		return err
	}
	p.ks.mu.Lock()
	st := p.ks.st
	p.ks.mu.Unlock()
	if st == nil {
		return nil
	}
	p.mu.RLock()
	envNow := make(map[string]string, len(p.envelopes))
	envSigned := map[string]string{}
	for key, sum := range p.envelopes {
		envNow[key] = sum
		if p.vouched[key] {
			envSigned[key] = sum
		}
	}
	p.mu.RUnlock()
	report, unsigned := buildReport(st, p.enf.current(), state, envNow, envSigned, p.reg.OrgID, p.reg.ProxyID)
	sha, err := canonSHA(report)
	if err != nil {
		return err
	}
	if sha != p.ks.posted {
		receipt, err := p.wit.signAs(reportType, map[string]any{"report_sha256": sha,
			"engaged_at": st.EngagedAt, "differences": len(report["differences"].([]any))})
		if err != nil {
			return err
		}
		if err := p.srv.postKillSwitch(ctx, map[string]any{"report": report, "receipt": receipt}); err != nil {
			return err
		}
		p.ks.posted = sha
		p.log.Warn("provenza proxy: reconciliation report sent; administrators lift the kill switch",
			"report", sha[:12], "differences", len(report["differences"].([]any)), "not_signed", len(unsigned))
	}
	lift, err := p.srv.liftSignatures(ctx)
	if err != nil {
		return err
	}
	if s, _ := lift["report_sha256"].(string); s != sha {
		return nil
	}
	sigs, _ := lift["signatures"].([]any)
	users, problems := trust.VerifyLift(sigs, st.before.Manifest, trust.LiftWant{ProxyID: p.reg.ProxyID.String(),
		ReportSHA256: sha, Unsigned: unsigned, NotBefore: st.EngagedAt, Now: p.now().Unix()})
	for _, pr := range problems {
		p.log.Warn("provenza proxy: a lift signature was not taken", "problem", pr)
	}
	if len(users) < trust.Quorum(st.before.Manifest) {
		return nil
	}
	if err := p.ks.lift(); err != nil {
		return err
	}
	if _, err := p.wit.signAs("provenza.proxy.lifted", map[string]any{"report_sha256": sha,
		"signers": users}); err != nil {
		p.log.Error("provenza proxy: could not log the lift", "err", err)
	}
	if err := p.srv.lifted(ctx, sha, users); err != nil {
		p.log.Warn("provenza proxy: could not tell Provenza the kill switch is lifted", "err", err)
	}
	p.log.Warn("provenza proxy: kill switch lifted by the administrators' quorum", "signers", users)
	return nil
}

// buildReport: the differences between what the server states now and the
// release held before the outage; the ids of those no newer verified
// release states.
func buildReport(st *engagedState, now *trust.Release, server map[string]any, envNow, envSigned map[string]string,
	orgID, proxyID json.Number) (map[string]any, []string) {
	before := st.before
	if now == nil {
		now = before
	}
	diffs := []any{}
	var unsigned []string
	add := func(area, section string, b, n, signed any, label func(string, any) string) {
		bm, bIsMap := b.(map[string]any)
		nm, nIsMap := n.(map[string]any)
		sm, _ := signed.(map[string]any)
		if (bIsMap || b == nil) && (nIsMap || n == nil) && (bIsMap || nIsMap) {
			keys := map[string]bool{}
			for k := range bm {
				keys[k] = true
			}
			for k := range nm {
				keys[k] = true
			}
			list := make([]string, 0, len(keys))
			for k := range keys {
				list = append(list, k)
			}
			sort.Strings(list)
			for _, key := range list {
				one(&diffs, &unsigned, area, section, key, bm[key], nm[key], sm[key], label)
			}
			return
		}
		one(&diffs, &unsigned, area, section, "", b, n, signed, label)
	}
	sectionLabel := func(section string) func(string, any) string {
		return func(key string, v any) string {
			m, _ := v.(map[string]any)
			for _, f := range []string{"email", "name", "slug"} {
				if s, ok := m[f].(string); ok && s != "" {
					return s
				}
			}
			if key == "" {
				return section
			}
			return section + " " + key
		}
	}
	srvManifest, _ := server["manifest"].(map[string]any)
	for _, s := range manifestSections {
		add("manifest", s, before.Manifest[s], srvManifest[s], now.Manifest[s], sectionLabel(s))
	}
	entries := func(bundle map[string]any) any {
		tr, _ := bundle["tool_registry"].(map[string]any)
		return tr["entries"]
	}
	srvRegistry, _ := server["tool_registry"].(map[string]any)
	add("bundle", "tool_registry", entries(before.Bundle), srvRegistry["entries"], entries(now.Bundle),
		sectionLabel("tool"))
	envBefore := map[string]any{}
	for k, v := range st.Envelopes {
		envBefore[k] = v
	}
	envAfter := map[string]any{}
	for k, v := range envNow {
		envAfter[k] = v
	}
	// a credential sealed again during the outage: signed when an administrator of the
	// newest verified release vouched for the envelope (trust.VerifySealed)
	signedEnv := map[string]any{}
	for k, v := range envSigned {
		signedEnv[k] = v
	}
	add("credentials", "sealed", envBefore, envAfter, signedEnv, func(key string, _ any) string { return key })
	report := map[string]any{"type": reportType, "v": 1, "org_id": orgID, "proxy_id": proxyID,
		"engaged_at": st.EngagedAt, "reason": st.Reason,
		"release_before": map[string]any{"number": before.Number, "manifest_sha256": before.ManifestSHA},
		"release_now":    map[string]any{"number": now.Number, "manifest_sha256": now.ManifestSHA},
		"differences":    diffs}
	return report, unsigned
}

func one(diffs *[]any, unsigned *[]string, area, section, key string, b, n, signed any,
	label func(string, any) string) {
	bs, ns := valueSHA(b), valueSHA(n)
	if eq(bs, ns) {
		return
	}
	id := area + "." + section
	if key != "" {
		id += "." + key
	}
	// signed: the newest verified release states it just so (removed: it is gone from that release too)
	isSigned := eq(ns, valueSHA(signed)) && (area != "credentials" || n != nil)
	v := n
	if v == nil {
		v = b
	}
	*diffs = append(*diffs, map[string]any{"id": id, "area": area, "section": section, "key": key,
		"label": label(key, v), "before": strOrNil(bs), "now": strOrNil(ns), "signed": isSigned})
	if !isSigned {
		*unsigned = append(*unsigned, id)
	}
}

func valueSHA(v any) *string {
	if v == nil {
		return nil
	}
	s, err := canon.SHA256(v)
	if err != nil {
		return nil
	}
	return &s
}

func eq(a, b *string) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }

func strOrNil(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}
