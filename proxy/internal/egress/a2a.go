// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

// A2A through the proxy (backend/app/pvp/a2a_gateway.py, app/api/a2a_gateway.py;
// act.go). Agents talk to remote agents at http://<proxy>/_a2a/<peer>, as they
// would at the server's A2A gateway. A peer whose credential is sealed to the
// proxies is reached from here only: the proxy fetches its live card with the
// credential (the server decides whether it is still the approved one), the
// server checks and decides the request and returns the exact JSON-RPC
// request for the peer, the proxy sends it with the credential and hands the
// answer back to the server, which reads it as its gateway does (task
// ownership, the answer's structure) and gives the agent its response. What
// is recorded of the answer is its status and hash. Other peers are relayed
// to the server's A2A gateway as they are.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
	"github.com/kironovlaziz-del/provenza/proxy/internal/policy"
)

const (
	a2aMaxCard     = 1 << 20
	a2aMaxResponse = 8 << 20
	a2aCardPath    = "/.well-known/agent-card.json"
)

var a2aSlugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// A2APeer: a remote agent whose credential the proxies hold.
type A2APeer struct {
	ID               json.Number `json:"id"`
	Slug             string      `json:"slug"`
	CardURL          string      `json:"card_url"`
	AuthHeader       string      `json:"auth_header"`
	CredentialSource string      `json:"credential_source"`
	TimeoutSeconds   int64       `json:"timeout_seconds"`
}

func (p *Proxy) a2aPeer(slug string) (A2APeer, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	a, ok := p.a2aPeers[slug]
	return a, ok
}

func (p *Proxy) serveA2A(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.EscapedPath(), "/_a2a/")
	slug, card := strings.CutSuffix(rest, a2aCardPath)
	slug = strings.TrimSuffix(slug, "/")
	if !a2aSlugRe.MatchString(slug) {
		rpcError(w, http.StatusNotFound, nil, -32601, "no such peer", nil)
		return
	}
	key := agentKeyOf(r)
	if key == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		rpcError(w, http.StatusUnauthorized, nil, -32001, "send the agent's key (X-Agent-Key or Bearer)", nil)
		return
	}
	if card {
		p.a2aCard(w, r, key, slug)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxAgentBody+1))
	if err != nil || len(raw) > maxAgentBody {
		rpcError(w, http.StatusRequestEntityTooLarge, nil, -32600, "the request is too large", nil)
		return
	}
	peer, ours := p.a2aPeer(slug)
	if !ours {
		p.relayA2A(w, r, key, "/a2a-gateway/"+slug, raw)
		return
	}
	p.a2aCall(w, r, key, peer, raw)
}

// relayA2A passes a request to the server's A2A gateway. For the card (raw
// nil) a 200 answer's body is returned for the caller to rewrite.
func (p *Proxy) relayA2A(w http.ResponseWriter, r *http.Request, key, path string, raw []byte) []byte {
	method := http.MethodPost
	var body io.Reader = bytes.NewReader(raw)
	if raw == nil {
		method, body = http.MethodGet, nil
	}
	target := p.srv.base + "/api/v1" + path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), method, target, body)
	if err != nil {
		rpcError(w, http.StatusBadGateway, nil, -32603, "the request could not be relayed", nil)
		return nil
	}
	req.Header.Set("X-Agent-Key", key)
	if raw != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if v := r.Header.Get("A2A-Version"); v != "" {
		req.Header.Set("A2A-Version", v)
	}
	resp, err := p.srv.http.Do(req)
	if err != nil {
		rpcError(w, http.StatusServiceUnavailable, nil, -32603, "Provenza is unreachable; nothing was sent", nil)
		return nil
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if raw == nil && resp.StatusCode == http.StatusOK {
		return out
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(out)
	return nil
}

// a2aCard: the approved card as the server's gateway serves it, pointing at this proxy.
func (p *Proxy) a2aCard(w http.ResponseWriter, r *http.Request, key, slug string) {
	out := p.relayA2A(w, r, key, "/a2a-gateway/"+slug+a2aCardPath, nil)
	if out == nil {
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	re := regexp.MustCompile(`"https?://[^"]*/api/v1/a2a-gateway/` + regexp.QuoteMeta(slug) + `"`)
	out = re.ReplaceAll(out, []byte(`"`+scheme+"://"+r.Host+"/_a2a/"+slug+`"`))
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

func a2aTimeout(s int64) time.Duration {
	if s <= 0 {
		return 60 * time.Second
	}
	return time.Duration(s) * time.Second
}

// liveCard: the peer's card as it serves it now, fetched with its credential;
// or why it could not be fetched.
func (p *Proxy) liveCard(ctx context.Context, peer A2APeer) (map[string]any, string) {
	cred := map[string]any{"object": "a2a_peer", "id": peer.ID.String(), "source": peer.CredentialSource,
		"header": peer.AuthHeader}
	header, value, ok := p.credentialFor(ctx, cred, peer.CardURL)
	if !ok {
		return nil, "proxy.sealed_credential_missing"
	}
	cctx, cancel := context.WithTimeout(ctx, a2aTimeout(peer.TimeoutSeconds))
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, peer.CardURL, nil)
	if err != nil {
		return nil, "upstream.unreachable"
	}
	req.Header.Set("Accept", "application/json")
	if header != "" && value != "" {
		req.Header.Set(header, value)
	}
	resp, err := p.upstream.Do(req)
	if err != nil {
		if errors.Is(cctx.Err(), context.DeadlineExceeded) {
			return nil, "upstream.timeout"
		}
		return nil, "upstream.unreachable"
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, a2aMaxCard+1))
	if len(raw) > a2aMaxCard {
		return nil, "upstream.response_too_large"
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "upstream.http_error"
	}
	v, err := canon.Parse(raw)
	card, _ := v.(map[string]any)
	if err != nil || card == nil {
		return nil, "upstream.bad_card"
	}
	return card, ""
}

// cardDigest: the server's manifest_digest of the pinned part of a card
// (a2a_wire.pinned_card: everything but its signatures, which can be
// re-issued without the card changing).
func cardDigest(card map[string]any) (string, error) {
	pinned := make(map[string]any, len(card))
	for k, v := range card {
		if k != "signatures" {
			pinned[k] = v
		}
	}
	return manifestDigest(pinned)
}

func (p *Proxy) a2aCall(w http.ResponseWriter, r *http.Request, key string, peer A2APeer, raw []byte) {
	ctx := r.Context()
	body, err := canon.Parse(raw)
	if err != nil {
		rpcError(w, http.StatusBadRequest, nil, -32700, "Parse error", nil)
		return
	}
	plan := map[string]any{"slug": peer.Slug, "body": body}
	if v := r.Header.Get("A2A-Version"); v != "" {
		plan["a2a_version"] = v
	} else if v := r.URL.Query().Get("A2A-Version"); v != "" {
		plan["a2a_version"] = v
	}
	var liveDigest string // what this proxy hashed of the card it fetched (the signed Tool Registry pins it)
	if card, why := p.liveCard(ctx, peer); why != "" {
		plan["live_error"] = why
	} else if d, err := cardDigest(card); err != nil {
		plan["live_error"] = "proxy.digest"
	} else {
		plan["live_card"], liveDigest = card, d
	}
	planRaw, _ := json.Marshal(plan)
	m, err := p.srv.plan(ctx, "a2a", key, planRaw)
	if err != nil {
		var se *serverError
		if errors.As(err, &se) && se.Status == http.StatusNotFound {
			rpcError(w, http.StatusNotFound, nil, -32001, "no such peer", nil)
			return
		}
		p.serverFailure(w, err)
		return
	}
	if m["decision"] == "reply" {
		status := http.StatusOK
		fmt.Sscan(fmt.Sprint(m["status"]), &status)
		writeJSON(w, status, m["response"])
		return
	}
	if m["decision"] != policy.Allowed {
		rpcError(w, http.StatusOK, nil, -32000, "Refused by Provenza", nil)
		return
	}
	chk := checkOf(m)
	actionType, _ := m["action_type"].(string)
	a := &action{plan: m, check: chk, started: time.Now(), fields: map[string]any{"check_id": chk.CheckID,
		"agent_id": chk.AgentID, "chain_id": chk.ChainID, "action_type": actionType, "tool_name": chk.Tool,
		"input_sha256": chk.InputSHA, "agent_signature": "not_presented", "policy": nil}}
	markSigned(ctx, a.fields, chk)
	if liveDigest != "" {
		chk.ToolDigest = &liveDigest
	}
	if sd, _ := m["tool_digest"].(string); p.enf.enforcing() && sd != liveDigest {
		p.refuseA2A(w, ctx, a, m["rid"], policy.Denied, "the server judged another card than the one this proxy fetched")
		return
	}
	req, _ := m["request"].(map[string]any)
	target, _ := req["url"].(string)
	wire, _ := req["body"].(map[string]any)
	rid := m["rid"]
	if chk.Tool != "a2a."+peer.Slug || target == "" || wire == nil {
		p.refuseA2A(w, ctx, a, rid, policy.Denied, "the planned request is not this one")
		return
	}
	if p.enf.enforcing() {
		if !p.judgedQuiet(ctx, a, m["input"]) {
			p.answerA2ARefused(w, a, rid)
			return
		}
		signed, ok := p.signedRow("a2a_peers", "slug", peer.Slug)
		if !ok || signed["endpoint_url"] != target || signed["card_url"] != peer.CardURL ||
			signed["auth_header"] != peer.AuthHeader {
			p.refuseA2A(w, ctx, a, rid, policy.Denied, "A2A peer '"+peer.Slug+"' is not in the signed policy as configured")
			return
		}
	}
	complete := map[string]any{"check_id": chk.CheckID, "rid": rid, "canonical": m["canonical"],
		"version": m["version"], "wire_id": wire["id"]}
	// what is recorded of the answer - the server computes the same from what it is given
	output := map[string]any{"status": 0, "response_sha256": nil}
	cred, _ := m["credential"].(map[string]any)
	if header, value, ok := p.credentialFor(ctx, cred, target); !ok {
		complete["status"], complete["upstream_error"] = 0, "proxy.sealed_credential_missing"
		output["error"] = "proxy.sealed_credential_missing"
	} else {
		status, ctype, resp, upErr := p.sendA2A(ctx, peer, target, wire, req["headers"], header, value)
		complete["status"], complete["content_type"] = status, ctype
		output["status"] = status
		if len(resp) > 0 {
			sum := sha256.Sum256(resp)
			output["response_sha256"] = hex.EncodeToString(sum[:])
			complete["response"] = base64.StdEncoding.EncodeToString(resp)
		}
		if upErr != "" {
			complete["upstream_error"], output["error"] = upErr, upErr
		}
	}
	complete["duration_ms"] = time.Since(a.started).Milliseconds()
	if rec := p.receipt(a, output, policy.Allowed); rec != nil {
		complete["receipt"] = rec
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.cfg.ServerTimeout.Duration)
	defer cancel()
	var answer struct {
		ActionID int64          `json:"action_id"`
		Response map[string]any `json:"response"`
	}
	if err := p.srv.call(rctx, http.MethodPost, "/egress-proxy/a2a/complete", complete, p.srv.asProxy(), &answer); err != nil {
		p.log.Error("provenza proxy: could not record an A2A exchange (open redemption)", "check", short(chk.CheckID),
			"err", err)
		rpcError(w, http.StatusOK, rid, -32000, "The answer could not be recorded by Provenza; it is not passed on", nil)
		return
	}
	writeJSON(w, http.StatusOK, answer.Response)
}

// sendA2A: the JSON-RPC request to the peer, with its credential.
func (p *Proxy) sendA2A(ctx context.Context, peer A2APeer, target string, wire map[string]any, headers any,
	header, value string) (int, string, []byte, string) {
	raw, err := json.Marshal(wire)
	if err != nil {
		return 0, "", nil, "proxy.bad_request"
	}
	cctx, cancel := context.WithTimeout(ctx, a2aTimeout(peer.TimeoutSeconds))
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, target, bytes.NewReader(raw))
	if err != nil {
		return 0, "", nil, "upstream.unreachable"
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if h, ok := headers.(map[string]any); ok {
		for k, v := range h {
			if s, ok := v.(string); ok {
				req.Header.Set(k, s)
			}
		}
	}
	if header != "" && value != "" {
		req.Header.Set(header, value)
	}
	resp, err := p.upstream.Do(req)
	if err != nil {
		if errors.Is(cctx.Err(), context.DeadlineExceeded) {
			return 0, "", nil, "upstream.timeout"
		}
		return 0, "", nil, "upstream.unreachable"
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, a2aMaxResponse+1))
	if len(out) > a2aMaxResponse {
		return resp.StatusCode, "", nil, "upstream.response_too_large"
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), out, ""
}

func (p *Proxy) refuseA2A(w http.ResponseWriter, ctx context.Context, a *action, rid any, verdict, why string) {
	a.refusal = [2]string{verdict, why}
	p.recordRefusal(ctx, a)
	p.answerA2ARefused(w, a, rid)
}

func (p *Proxy) answerA2ARefused(w http.ResponseWriter, a *action, rid any) {
	rpcError(w, http.StatusOK, rid, -32000, "Refused by the signed policy at the egress proxy",
		map[string]any{"action_id": a.actionID, "reason": a.refusal[1]})
}

// syncA2A reports each served peer's card (as an admin's sync would).
func (p *Proxy) syncA2A(ctx context.Context) {
	p.mu.RLock()
	peers := make([]A2APeer, 0, len(p.a2aPeers))
	for _, a := range p.a2aPeers {
		peers = append(peers, a)
	}
	p.mu.RUnlock()
	quiet := context.WithValue(ctx, noFetch{}, true)
	for _, peer := range peers {
		body := map[string]any{"peer_id": peer.ID}
		if card, why := p.liveCard(quiet, peer); why != "" {
			body["error"] = why
		} else {
			body["card"] = card
		}
		if err := p.srv.call(ctx, http.MethodPost, "/egress-proxy/a2a/sync", body, p.srv.asProxy(), nil); err != nil {
			p.log.Warn("provenza proxy: A2A sync report", "peer", peer.Slug, "err", err)
		}
	}
}
