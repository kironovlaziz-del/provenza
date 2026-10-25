// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

// Requests while Provenza is unreachable (docs/pvp/edge.md, section 6). With
// policy.mode "enforce", a request to an egress route that the agent signed
// itself (X-Provenza-Request, no check id: there was nobody to check it) is
// judged by the signed policy release alone:
//
//   - the agent's signature must verify with the key the release's manifest
//     names for it, the request must be fresh and used once;
//   - the release must allow it outright - a call that needs a person's
//     approval, or that belongs to a delegation chain, waits for Provenza;
//   - the route is the signed one.
//
// What was done - the signed request, the outcome, the proxy's receipt - is
// kept in state_dir/offline.jsonl and handed to Provenza when it answers
// again (POST /egress-proxy/offline-actions), which records each as an
// action and raises an incident for one that does not verify. After the
// release's offline_seconds without Provenza the local kill switch stops
// everything (killswitch.go).

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
	"github.com/kironovlaziz-del/provenza/proxy/internal/policy"
	"github.com/kironovlaziz-del/provenza/proxy/internal/trust"
)

const (
	offlineFile      = "offline.jsonl"
	offlineUploading = "offline.uploading.jsonl"
	offlineBatch     = 100
	// a signed-only request while the last call reached Provenza: ask again at most this often
	probeEvery = 2 * time.Second
)

// offlineNonce: what the server takes as the nonce of an offline action (its check id is "offline-<nonce>").
var offlineNonce = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)

// offlineEntry is one request handled while Provenza was unreachable.
type offlineEntry struct {
	Request    json.RawMessage `json:"request"` // the agent's signed request, as it sent it
	Descriptor Descriptor      `json:"descriptor"`
	Decision   string          `json:"decision"` // allowed | denied
	Reason     string          `json:"reason,omitempty"`
	Outcome    map[string]any  `json:"outcome,omitempty"`
	DurationMS int64           `json:"duration_ms"`
	Receipt    map[string]any  `json:"receipt,omitempty"`
	Release    int             `json:"release"`
	At         int64           `json:"at"`
}

type offlineLog struct {
	dir string
	mu  sync.Mutex
}

func newOfflineLog(dir string) *offlineLog { return &offlineLog{dir: dir} }

func (l *offlineLog) add(e offlineEntry) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(filepath.Join(l.dir, offlineFile), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// pending: the entries not handed over yet. What is being handed over moves
// to offline.uploading.jsonl first, so new entries keep going to the log.
func (l *offlineLog) pending() ([]json.RawMessage, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	up := filepath.Join(l.dir, offlineUploading)
	if _, err := os.Stat(up); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(filepath.Join(l.dir, offlineFile), up); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil
			}
			return nil, err
		}
	}
	f, err := os.Open(up)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []json.RawMessage
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			out = append(out, json.RawMessage(line))
		}
	}
	return out, sc.Err()
}

// handedOver: the first n pending entries were taken; the rest stay.
func (l *offlineLog) handedOver(n int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	up := filepath.Join(l.dir, offlineUploading)
	raw, err := os.ReadFile(up)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if n >= len(lines) {
		return os.Remove(up)
	}
	return os.WriteFile(up, []byte(strings.Join(lines[n:], "\n")+"\n"), 0o600)
}

// uploadOffline hands over what was done offline, once Provenza answers.
func (p *Proxy) uploadOffline(ctx context.Context) {
	if down, _ := p.srv.contact.state(); down {
		return
	}
	entries, err := p.offline.pending()
	if err != nil {
		p.log.Error("provenza proxy: the offline log", "err", err)
		return
	}
	for len(entries) > 0 {
		batch := entries
		if len(batch) > offlineBatch {
			batch = batch[:offlineBatch]
		}
		results, err := p.srv.offlineActions(ctx, batch)
		if err != nil {
			p.log.Warn("provenza proxy: could not hand over the offline actions yet", "pending", len(entries), "err", err)
			return
		}
		for _, r := range results {
			if r["status"] != "recorded" && r["status"] != "duplicate" {
				p.log.Warn("provenza proxy: Provenza did not take an offline action", "result", r)
			}
		}
		if err := p.offline.handedOver(len(batch)); err != nil {
			p.log.Error("provenza proxy: the offline log", "err", err)
			return
		}
		p.log.Info("provenza proxy: offline actions handed over", "count", len(batch))
		entries = entries[len(batch):]
	}
}

// unreachable: whether Provenza cannot be reached now - asked again when the
// last call did reach it (a signed-only request is taken only offline).
func (p *Proxy) unreachable(ctx context.Context) bool {
	if down, _ := p.srv.contact.state(); down {
		return true
	}
	p.probeMu.Lock()
	recent := time.Since(p.probed) < probeEvery
	if !recent {
		p.probed = time.Now()
	}
	p.probeMu.Unlock()
	if recent {
		return false
	}
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := p.srv.callRaw(pctx, http.MethodGet, "/egress-proxy/config", nil, p.srv.asProxy())
	return errors.Is(err, errUnavailable)
}

// decodeSignedRequest: the header's JSON as the agent sent it.
func decodeSignedRequest(header string) (json.RawMessage, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(header, "="))
	if err != nil || !json.Valid(raw) {
		return nil, errors.New("the signed request is not base64url JSON")
	}
	return raw, nil
}

// serveOffline: a request the agent signed but could not have checked.
func (p *Proxy) serveOffline(w http.ResponseWriter, r *http.Request, route Route, path string, body []byte,
	d Descriptor, input any, inputSHA, header string) {
	ctx := r.Context()
	if !p.enf.enforcing() {
		refuse(w, http.StatusBadRequest, "provenza_check_required",
			"a signed request (X-Provenza-Request) comes with the agent's check id (X-Provenza-Check-Id)")
		return
	}
	if !p.unreachable(ctx) {
		refuse(w, http.StatusBadRequest, "provenza_check_required",
			"Provenza is reachable: check the request first (X-Provenza-Check-Id)")
		return
	}
	rel := p.enf.current()
	if rel == nil {
		refuse(w, http.StatusServiceUnavailable, "provenza_unavailable",
			"Provenza is unreachable and this proxy has verified no signed policy; the request was not sent")
		return
	}
	if p.ks.check(p, rel) {
		refuse(w, http.StatusServiceUnavailable, "provenza_kill_switch",
			"Provenza has been unreachable for longer than the signed policy allows; this proxy stopped")
		return
	}
	raw, err := decodeSignedRequest(header)
	sr, perr := trust.ParseSignedRequest(header)
	if err != nil || perr != nil {
		refuse(w, http.StatusUnauthorized, "provenza_agent_signature", "the agent's signed request cannot be read")
		return
	}
	tool := "proxy." + d.Route
	fp, err := sr.Verify("proxy", tool, inputSHA, p.enf.nonces, p.now())
	if err != nil {
		refuse(w, http.StatusUnauthorized, "provenza_agent_signature", "the agent's signed request: "+err.Error())
		return
	}
	nonce, _ := sr.Payload["nonce"].(string)
	if !offlineNonce.MatchString(nonce) {
		refuse(w, http.StatusBadRequest, "provenza_agent_signature", "the signed request's nonce cannot name an offline action")
		return
	}
	chk := &checkResult{CheckID: "offline-" + nonce, AgentID: sr.Payload["agent_id"], ChainID: sr.Payload["chain_id"],
		Tool: tool, InputSHA: inputSHA}
	fields := map[string]any{"check_id": chk.CheckID, "agent_id": chk.AgentID, "chain_id": chk.ChainID,
		"action_type": "proxy", "tool_name": tool, "input_sha256": inputSHA, "agent_signature": "verified",
		"policy": nil} // check_id "offline-<nonce>": there was no check
	entry := offlineEntry{Request: raw, Descriptor: d, Release: rel.Number, At: time.Now().Unix()}
	deny := func(why string) {
		entry.Decision, entry.Reason = policy.Denied, why
		entry.Receipt = p.receiptFor(fields, nil, policy.Denied)
		if err := p.offline.add(entry); err != nil {
			p.log.Error("provenza proxy: could not log an offline refusal", "err", err)
		}
		refuse(w, http.StatusForbidden, "provenza_denied", "Refused by the signed policy (Provenza is unreachable): "+why)
	}
	if chk.ChainID != nil {
		deny("a delegation chain is checked by Provenza: it is unreachable")
		return
	}
	verdict, why, ref := p.judge(chk, "proxy", tool, input, inputSHA, true, &fp)
	fields["policy"] = ref
	switch {
	case verdict == policy.PendingApproval:
		deny("it needs a person's approval, given through Provenza: it is unreachable")
		return
	case verdict != policy.Allowed:
		deny(why)
		return
	}
	signed, ok := p.signedRoute(ref, d.Route, route)
	if !ok {
		deny("egress route '" + d.Route + "' is not in the signed policy")
		return
	}
	p.log.Info("provenza proxy: Provenza is unreachable; a signed request is sent under the signed policy",
		"route", d.Route, "release", rel.Number)
	p.forward(w, r, signed, path, body, chk.CheckID, fields, func(_ context.Context, status int, h *string, n int64,
		errCode string, dur time.Duration, receipt map[string]any) {
		entry.Decision = policy.Allowed
		entry.Outcome = map[string]any{"status": status, "response_sha256": h, "response_bytes": n}
		if errCode != "" {
			entry.Outcome["error"] = errCode
		}
		entry.DurationMS, entry.Receipt = dur.Milliseconds(), receipt
		if err := p.offline.add(entry); err != nil {
			p.log.Error("provenza proxy: could not log an offline action", "err", err)
		}
	})
}

// receiptFor: the proxy's receipt for an outcome (nil: no key, or it failed).
func (p *Proxy) receiptFor(fields, output map[string]any, decision string) map[string]any {
	if p.wit == nil {
		return nil
	}
	sha := nullSHA
	if output != nil {
		var err error
		if sha, err = canonSHA(output); err != nil {
			return nil
		}
	}
	rf := map[string]any{"output_sha256": sha, "decision": decision}
	for k, v := range fields {
		rf[k] = v
	}
	rec, err := p.wit.sign(rf)
	if err != nil {
		p.log.Error("provenza proxy: could not sign a receipt", "err", err)
		return nil
	}
	return rec
}

func canonSHA(v map[string]any) (string, error) {
	parsed, err := canon.Of(v)
	if err != nil {
		return "", err
	}
	return canon.SHA256(parsed)
}
