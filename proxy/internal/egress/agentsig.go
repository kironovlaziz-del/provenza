// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

// Enforce mode (docs/pvp/edge.md, section 4): no action without the agent's
// own signature and the signed policy. The signed policy says so itself
// (the release's "enforcement" section); this proxy then
//
//   - takes on every path - egress routes and the gateways' protocols - only
//     requests the agent signed (X-Provenza-Request over the HTTP request it
//     sent: route, method, path, hashes of the query and the body), verified
//     here with the key the signed manifest names for that agent, fresh and
//     once;
//   - passes that signed request on to the server, which verifies it again
//     with the agent's registered key (a plan or a mediated check);
//   - tells the server it enforces the signed policy (X-Provenza-Proxy-Mode):
//     in enforce mode the server takes part in nothing else.
//
// The SDKs sign their requests; stock clients (OpenAI, MCP, A2A) go through
// the proxy's agent mode (agentmode.go), which signs for them with the
// agent's key.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
	"github.com/kironovlaziz-del/provenza/proxy/internal/trust"
)

const (
	requestHeader    = "X-Provenza-Request"
	descriptorHeader = "X-Provenza-Descriptor"
	proxyModeHeader  = "X-Provenza-Proxy-Mode"
)

// releaseEnforces: the release says "enforcement": {"mode": "enforce"}.
func releaseEnforces(rel *trust.Release) bool {
	if rel == nil {
		return false
	}
	e, _ := rel.Bundle["enforcement"].(map[string]any)
	return e != nil && e["mode"] == "enforce"
}

// strict: requests must carry the agent's signed request - this proxy's
// configuration asks for it, or the signed policy (enforce mode).
func (e *enforcer) strict() bool {
	return e.enforcing() && (e.cfg.RequireAgentSignature || releaseEnforces(e.current()))
}

// agentRequest: the agent's signed request for the HTTP request in hand,
// verified here.
type agentRequest struct {
	header      string // as the agent sent it
	descriptor  string // base64url JSON of the request it signed, for the server
	fingerprint string
	agentID     any
}

type agentRequestKey struct{}

func agentRequestOf(ctx context.Context) *agentRequest {
	a, _ := ctx.Value(agentRequestKey{}).(*agentRequest)
	return a
}

// describe: the HTTP request as the agent signs it - route is the first path
// segment ("_llm", "_mcp", "_a2a", "_tools" or an egress route), path the rest.
func describe(r *http.Request, body []byte) (Descriptor, any, string, error) {
	raw := r.URL.EscapedPath()
	slug, rest, _ := strings.Cut(strings.TrimPrefix(raw, "/"), "/")
	var query *string
	if r.URL.RawQuery != "" {
		query = sha256Hex([]byte(r.URL.RawQuery))
	}
	d := Descriptor{Route: slug, Method: r.Method, Path: "/" + rest, QuerySHA256: query, BodySHA256: sha256Hex(body),
		BodyBytes: int64(len(body))}
	dmap, err := canon.Of(d)
	if err != nil {
		return d, nil, "", err
	}
	sha, err := canon.SHA256(dmap)
	return d, dmap, sha, err
}

// signedAdapterRequest: for a gateway protocol path, the agent's signed
// request verified (required when strict). The body is read and put back.
// nil and false: refused, the answer is written.
func (p *Proxy) signedAdapterRequest(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	header := r.Header.Get(requestHeader)
	if header == "" {
		if p.enf.strict() && r.Method == http.MethodPost {
			refuse(w, http.StatusUnauthorized, "provenza_agent_signature_required",
				"enforce mode: this proxy takes only requests the agent signed (X-Provenza-Request; the proxy's "+
					"agent mode signs for clients that cannot)")
			return nil, false
		}
		return r, true
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAgentBody+1))
	if err != nil || len(body) > maxAgentBody {
		refuse(w, http.StatusRequestEntityTooLarge, "provenza_body_too_large", "the request is too large")
		return nil, false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	d, _, sha, err := describe(r, body)
	if err != nil {
		refuse(w, http.StatusBadRequest, "provenza_body", "the request cannot be described")
		return nil, false
	}
	sr, err := trust.ParseSignedRequest(header)
	var fp string
	if err == nil {
		fp, err = sr.Verify("proxy", "proxy."+d.Route, sha, p.enf.nonces, p.now())
	}
	if err != nil {
		refuse(w, http.StatusUnauthorized, "provenza_agent_signature", "the agent's signed request: "+err.Error())
		return nil, false
	}
	desc, _ := json.Marshal(d)
	a := &agentRequest{header: header, descriptor: base64.RawURLEncoding.EncodeToString(desc), fingerprint: fp,
		agentID: sr.Payload["agent_id"]}
	return r.WithContext(context.WithValue(r.Context(), agentRequestKey{}, a)), true
}

// signedFor: whether the agent's verified signed request is this check's
// agent's, and its key fingerprint.
func signedFor(ctx context.Context, chk *checkResult) (bool, *string) {
	a := agentRequestOf(ctx)
	if a == nil || chk == nil || !sameNumber(a.agentID, chk.AgentID) {
		return false, nil
	}
	fp := a.fingerprint
	return true, &fp
}

// markSigned: the receipt says the agent's signature was verified, when it was.
func markSigned(ctx context.Context, fields map[string]any, chk *checkResult) {
	if ok, _ := signedFor(ctx, chk); ok {
		fields["agent_signature"] = "verified"
	}
}

// agentHeaders: the agent's signed request, for the server to verify again.
func agentHeaders(ctx context.Context, headers map[string]string) {
	if a := agentRequestOf(ctx); a != nil {
		headers[requestHeader] = a.header
		headers[descriptorHeader] = a.descriptor
	}
}
