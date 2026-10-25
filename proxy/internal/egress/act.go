// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

// The gateways' protocols, executed here (backend/app/pvp/proxy_actions.py;
// docs/pvp/edge.md, section 4). An upstream that takes a credential - an HTTP
// tool, an AI connection, an MCP server, an A2A peer - is reached only through
// a proxy, because only a proxy can open its credential. The agent speaks the
// gateway's own protocol to the proxy:
//
//	/_tools/call     an HTTP tool call (the body of /http-tools/call)  tools.go
//	/_llm/v1/...     OpenAI chat completions and models                llm.go
//	/_mcp            an MCP endpoint (Streamable HTTP)                 mcp.go
//	/_a2a/<peer>     A2A JSON-RPC and the peer's card                  a2a.go
//
// For each call the proxy asks the server for a plan (the server judges it as
// its gateway does and records a refusal at once), judges it itself under the
// signed policy with policy.mode "enforce", sends it with the credential and
// reports what happened - metadata and hashes, with its signed receipt.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
	"github.com/kironovlaziz-del/provenza/proxy/internal/policy"
)

const maxAgentBody = 1 << 20

// adapter: the handler for a gateway protocol path, if raw is one.
func (p *Proxy) adapter(raw string) (http.HandlerFunc, bool) {
	switch {
	case raw == "/_tools/call":
		return p.serveTool, true
	case strings.HasPrefix(raw, "/_llm/"):
		return p.serveLLM, true
	case raw == "/_mcp" || raw == "/_mcp/":
		return p.serveMCP, true
	case strings.HasPrefix(raw, "/_a2a/"):
		return p.serveA2A, true
	}
	if strings.HasPrefix(raw, "/_") && !strings.HasPrefix(raw, RelayPrefix) {
		return func(w http.ResponseWriter, _ *http.Request) {
			refuse(w, http.StatusNotFound, "provenza_unknown_route", "no such gateway path: "+raw)
		}, true
	}
	return nil, false
}

// action: a planned gateway action, as the server answered.
type action struct {
	plan     map[string]any
	check    *checkResult
	fields   map[string]any // what the receipt names
	started  time.Time
	refusal  [2]string // verdict, why - when the proxy refused it after all
	actionID int64     // the recorded action, once recorded
}

// readAgentRequest: the agent's key and body, or a refusal already written.
func readAgentRequest(w http.ResponseWriter, r *http.Request) (string, []byte, bool) {
	if r.Method != http.MethodPost {
		refuse(w, http.StatusMethodNotAllowed, "provenza_method", "use POST")
		return "", nil, false
	}
	key := r.Header.Get("X-Agent-Key")
	if key == "" {
		if b, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			key = strings.TrimSpace(b)
		}
	}
	if key == "" {
		refuse(w, http.StatusUnauthorized, "provenza_agent_key_required", "send the agent's key (X-Agent-Key)")
		return "", nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAgentBody+1))
	if err != nil || len(body) > maxAgentBody {
		refuse(w, http.StatusRequestEntityTooLarge, "provenza_body_too_large", "the request is too large")
		return "", nil, false
	}
	if !json.Valid(body) {
		refuse(w, http.StatusBadRequest, "provenza_body", "the request is not JSON")
		return "", nil, false
	}
	return key, body, true
}

// planned asks the server; nil when it refused (the agent has its answer then).
func (p *Proxy) planned(w http.ResponseWriter, r *http.Request, kind, key string, body []byte) *action {
	m, err := p.srv.plan(r.Context(), kind, key, body)
	if err != nil {
		p.serverFailure(w, err)
		return nil
	}
	if m["decision"] != policy.Allowed {
		// refused or held by the server: recorded there; the gateway's own answer
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Provenza-Refused", "1")
		_ = json.NewEncoder(w).Encode(m)
		return nil
	}
	chk := checkOf(m)
	a := &action{plan: m, check: chk, started: time.Now()}
	actionType, _ := m["action_type"].(string)
	a.fields = map[string]any{"check_id": chk.CheckID, "agent_id": chk.AgentID, "chain_id": chk.ChainID,
		"action_type": actionType, "tool_name": chk.Tool, "input_sha256": chk.InputSHA,
		"agent_signature": "not_presented", "policy": nil}
	markSigned(r.Context(), a.fields, chk)
	return a
}

// judged: with policy.mode "enforce", the signed policy's verdict on the
// planned action (input: what the server recorded as its input). false: it
// was refused here, recorded and answered.
func (p *Proxy) judged(w http.ResponseWriter, ctx context.Context, a *action, input any) bool {
	if !p.enf.enforcing() {
		return true
	}
	sha, err := canon.SHA256(input)
	if err != nil || sha != a.check.InputSHA {
		p.refuseAction(w, ctx, a, policy.Denied, "the planned input is not the checked one")
		return false
	}
	actionType, _ := a.fields["action_type"].(string)
	signed, fp := signedFor(ctx, a.check)
	if p.enf.strict() && !signed {
		p.refuseAction(w, ctx, a, policy.Denied, "enforce mode: the agent's signed request is not this action's")
		return false
	}
	verdict, why, release := p.judge(a.check, actionType, a.check.Tool, input, sha, signed, fp)
	a.fields["policy"] = release
	if verdict != policy.Allowed {
		p.refuseAction(w, ctx, a, verdict, why)
		return false
	}
	return true
}

// signedRow: an enabled row of a section of the signed policy, by a field's value.
func (p *Proxy) signedRow(section, field, value string) (map[string]any, bool) {
	rel := p.enf.current()
	if rel == nil {
		return nil, false
	}
	rows, _ := rel.Bundle[section].(map[string]any)
	for _, v := range rows {
		row, _ := v.(map[string]any)
		if s, _ := row[field].(string); s == value && row["enabled"] == true {
			return row, true
		}
	}
	return nil, false
}

func (p *Proxy) receipt(a *action, output map[string]any, decision string) map[string]any {
	if p.wit == nil {
		return nil
	}
	sha := nullSHA
	if output != nil {
		parsed, err := canon.Of(output)
		if err == nil {
			sha, err = canon.SHA256(parsed)
		}
		if err != nil {
			p.log.Error("provenza proxy: could not hash an output", "err", err)
			return nil
		}
	}
	rf := map[string]any{"output_sha256": sha, "decision": decision}
	for k, v := range a.fields {
		rf[k] = v
	}
	rec, err := p.wit.sign(rf)
	if err != nil {
		p.log.Error("provenza proxy: could not sign a receipt", "check", short(a.check.CheckID), "err", err)
		return nil
	}
	return rec
}

// refuseAction: the proxy does not send a planned action after all; recorded
// as refused under the signed policy.
func (p *Proxy) refuseAction(w http.ResponseWriter, ctx context.Context, a *action, verdict, why string) {
	if verdict != policy.PendingApproval {
		verdict = policy.Denied
	}
	a.refusal = [2]string{verdict, why}
	p.recordRefusal(ctx, a)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Provenza-Refused", "1")
	_ = json.NewEncoder(w).Encode(map[string]any{"decision": verdict, "action_id": a.actionID,
		"reason": "Refused by the signed policy at the egress proxy: " + why})
}

// recordRefusal records a.refusal with the proxy's receipt.
func (p *Proxy) recordRefusal(ctx context.Context, a *action) {
	verdict := a.refusal[0]
	enforcement := map[string]any{"decision": verdict, "reason": a.refusal[1]}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.cfg.ServerTimeout.Duration)
	defer cancel()
	id, err := p.srv.completeAction(rctx, a.check.CheckID, nil, time.Since(a.started),
		p.receipt(a, nil, verdict), enforcement)
	if err != nil {
		p.log.Warn("provenza proxy: could not record a refusal", "check", short(a.check.CheckID), "err", err)
	}
	a.actionID = id
}

// done records what the proxy did; the action's id, or 0 when it could not be recorded.
func (p *Proxy) done(ctx context.Context, a *action, output map[string]any) int64 {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.cfg.ServerTimeout.Duration)
	defer cancel()
	id, err := p.srv.completeAction(rctx, a.check.CheckID, output, time.Since(a.started),
		p.receipt(a, output, policy.Allowed), nil)
	if err != nil {
		p.log.Error("provenza proxy: could not record an action it executed (open redemption)",
			"check", short(a.check.CheckID), "err", err)
	}
	return id
}

// credentialFor: the header and value to send with a call to target - from the
// envelope sealed to this proxy (only for its origin), or this proxy's
// configuration ("<object>:<id>" in local_secrets). ok false: none that may be used.
func (p *Proxy) credentialFor(ctx context.Context, cred map[string]any, target string) (string, string, bool) {
	source, _ := cred["source"].(string)
	object, _ := cred["object"].(string)
	id := fmt.Sprint(cred["id"])
	header, _ := cred["header"].(string)
	switch {
	case source == "" || source == "none":
		return "", "", true
	case sealedSource(source):
		v, ok := p.credential(ctx, object, id, target)
		return header, v, ok
	case source == "local":
		h, v, err := p.cfg.localSecret(object+":"+id, header, target)
		if err != nil {
			p.log.Error("provenza proxy: local credential", "object", object, "id", id, "err", err)
			return "", "", false
		}
		return h, v, true
	}
	return "", "", false
}
