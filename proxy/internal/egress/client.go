// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

// Route as the server hands it to proxies (GET /egress-proxy/config).
type Route struct {
	ID               json.Number `json:"id"`
	Slug             string      `json:"slug"`
	UpstreamURL      string      `json:"upstream_url"`
	Methods          []string    `json:"methods"`
	PathPrefixes     []string    `json:"path_prefixes"`
	CredentialSource string      `json:"credential_source"`
	AuthHeader       string      `json:"auth_header"`
	MaxBodyBytes     int64       `json:"max_body_bytes"`
}

// errUnavailable: the server could not decide - the request is not sent (fail-closed).
var errUnavailable = errors.New("provenza unavailable")

// serverError: the server refused the call itself (4xx).
type serverError struct {
	Status int
	Detail any
}

func (e *serverError) Error() string { return fmt.Sprintf("provenza: HTTP %d: %v", e.Status, e.Detail) }

type server struct {
	base     string
	proxyKey string
	mode     string // "enforce": policy.mode, said to the server
	http     *http.Client
	// when Provenza last answered (killswitch.go: offline time is counted from it)
	contact contactClock
}

func newServer(base, proxyKey string, timeout time.Duration) *server {
	return &server{base: base, proxyKey: proxyKey, http: &http.Client{Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// contactClock: the last time Provenza answered, on the monotonic clock (a
// changed system clock neither shortens nor extends the time offline).
type contactClock struct {
	mu   sync.Mutex
	last time.Time
	down bool // the last call could not reach it
}

func (c *contactClock) answered() {
	c.mu.Lock()
	c.last, c.down = time.Now(), false
	c.mu.Unlock()
}

func (c *contactClock) unreachable() {
	c.mu.Lock()
	c.down = true
	c.mu.Unlock()
}

// state: whether the last call failed, and how long ago Provenza last answered.
func (c *contactClock) state() (bool, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last.IsZero() {
		return c.down, 0
	}
	return c.down, time.Since(c.last)
}

// call sends one request; headers carry either the proxy key or an agent key.
func (s *server) call(ctx context.Context, method, path string, body any, headers map[string]string, out any) error {
	raw, err := s.callRaw(ctx, method, path, body, headers)
	if err != nil || out == nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// callJSON: the answer parsed with numbers kept as text - what is hashed or
// verified (signed documents, approvals) must not pass through float64.
func (s *server) callJSON(ctx context.Context, method, path string, body any, headers map[string]string) (map[string]any, error) {
	raw, err := s.callRaw(ctx, method, path, body, headers)
	if err != nil {
		return nil, err
	}
	v, err := canon.Parse(raw)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	if m == nil {
		return nil, fmt.Errorf("%s: not a JSON object", path)
	}
	return m, nil
}

// callRaw sends one request and returns the answer's body.
func (s *server) callRaw(ctx context.Context, method, path string, body any, headers map[string]string) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.base+"/api/v1"+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "provenza-egress-proxy")
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		s.contact.unreachable()
		return nil, fmt.Errorf("%w: %s: %v", errUnavailable, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil || resp.StatusCode >= 500 || (resp.StatusCode >= 300 && resp.StatusCode < 400) {
		s.contact.unreachable()
		return nil, fmt.Errorf("%w: %s: HTTP %d", errUnavailable, path, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		// a refused key (a revoked proxy, or someone answering in Provenza's place) is no
		// contact: the offline time keeps running and the kill switch engages
		s.contact.answered()
	}
	if resp.StatusCode >= 400 {
		var e struct {
			Detail any `json:"detail"`
		}
		_ = json.Unmarshal(raw, &e)
		return nil, &serverError{Status: resp.StatusCode, Detail: e.Detail}
	}
	return raw, nil
}

func (s *server) asProxy() map[string]string {
	h := map[string]string{"X-Proxy-Key": s.proxyKey}
	if s.mode != "" {
		h[proxyModeHeader] = s.mode // enforce: this proxy judges by the signed policy itself (agentsig.go)
	}
	return h
}

// proxyConfig: what the server tells a proxy to serve (GET /egress-proxy/config).
type proxyConfig struct {
	Routes         []Route     `json:"routes"`
	MCPServers     []MCPServer `json:"mcp_servers"`
	A2APeers       []A2APeer   `json:"a2a_peers"`
	RefreshSeconds int         `json:"refresh_seconds"`
}

func (s *server) config(ctx context.Context) (*proxyConfig, time.Duration, error) {
	var out proxyConfig
	raw, err := s.callRaw(ctx, http.MethodGet, "/egress-proxy/config", nil, s.asProxy())
	if err != nil {
		return nil, 0, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return nil, 0, err
	}
	every := time.Duration(out.RefreshSeconds) * time.Second
	if every <= 0 {
		every = time.Minute
	}
	return &out, every, nil
}

// checkResult: a check and what it was issued for (numbers kept as text).
type checkResult struct {
	Decision string
	Reason   string
	CheckID  string
	AgentID  any // json.Number
	ChainID  any // json.Number or nil
	Tool     string
	InputSHA string
	Approval map[string]any // the signed approval that released it, if one did
	// ToolDigest: the digest of the tool's definition as the proxy found it live
	// (an MCP tool, an A2A card) or pinned (an HTTP tool) - the signed Tool
	// Registry pins it
	ToolDigest *string
}

func checkOf(m map[string]any) *checkResult {
	str := func(k string) string { s, _ := m[k].(string); return s }
	ap, _ := m["approval"].(map[string]any)
	return &checkResult{Decision: str("decision"), Reason: str("reason"), CheckID: str("check_id"),
		AgentID: m["agent_id"], ChainID: m["chain_id"], Tool: str("tool_name"), InputSHA: str("input_sha256"),
		Approval: ap}
}

// check asks the server on the agent's behalf (mediated mode): the proxy's own
// key and the key the agent sent. The proxy cannot sign as the agent; like the
// gateways, it is the witness.
func (s *server) check(ctx context.Context, agentKey string, d Descriptor, signed string) (*checkResult, error) {
	headers := s.asProxy()
	headers["X-Agent-Key"] = agentKey
	if signed != "" {
		headers[requestHeader] = signed // the agent's own signed request: the server verifies it as well
	}
	m, err := s.callJSON(ctx, http.MethodPost, "/egress-proxy/check", d, headers)
	if err != nil {
		return nil, err
	}
	return checkOf(m), nil
}

// checkInfo: what a check an agent brings (SDK mode) was issued for.
func (s *server) checkInfo(ctx context.Context, checkID string) (*checkResult, error) {
	m, err := s.callJSON(ctx, http.MethodPost, "/egress-proxy/check-info", map[string]any{"check_id": checkID},
		s.asProxy())
	if err != nil {
		return nil, err
	}
	out := checkOf(m)
	out.CheckID = checkID
	return out, nil
}

// registration: what the server answers about this proxy - the context its
// envelopes must name.
type registration struct {
	ProxyID json.Number `json:"proxy_id"`
	OrgID   json.Number `json:"org_id"`
}

// registerKey: the proxy's own public key, registered once, and the
// encryption key credentials are sealed to, signed by it.
func (s *server) registerKey(ctx context.Context, publicKey, encryptionKey, signature string) (*registration, error) {
	body := map[string]any{"public_key": publicKey}
	if encryptionKey != "" {
		body["encryption_key"], body["encryption_key_signature"] = encryptionKey, signature
	}
	raw, err := s.callRaw(ctx, http.MethodPost, "/egress-proxy/key", body, s.asProxy())
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out registration
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// sealedCredential: one envelope sealed to this proxy.
type sealedCredential struct {
	Object   string
	ObjectID string
	Envelope map[string]any
	Sealer   map[string]any // the administrator's signature over it (trust.VerifySealed), if any
}

// credentials: the envelopes sealed to this proxy (GET /egress-proxy/credentials).
func (s *server) credentials(ctx context.Context) ([]sealedCredential, error) {
	m, err := s.callJSON(ctx, http.MethodGet, "/egress-proxy/credentials", nil, s.asProxy())
	if err != nil {
		return nil, err
	}
	list, _ := m["credentials"].([]any)
	out := make([]sealedCredential, 0, len(list))
	for _, v := range list {
		c, _ := v.(map[string]any)
		obj, _ := c["object"].(string)
		env, _ := c["envelope"].(map[string]any)
		if obj == "" || env == nil {
			continue
		}
		sealer, _ := c["sealer"].(map[string]any)
		out = append(out, sealedCredential{Object: obj, ObjectID: fmt.Sprint(c["object_id"]), Envelope: env,
			Sealer: sealer})
	}
	return out, nil
}

type redeemResult struct {
	Allowed  bool   `json:"allowed"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	ActionID int64  `json:"action_id"`
}

// redeem reserves the check for the request; enforcement (nil: none) is the
// proxy's own refusal under the signed policy, with its receipt.
func (s *server) redeem(ctx context.Context, checkID string, d Descriptor, enforcement map[string]any) (*redeemResult, error) {
	body := map[string]any{"check_id": checkID, "route": d.Route, "method": d.Method, "path": d.Path,
		"query_sha256": d.QuerySHA256, "body_sha256": d.BodySHA256, "body_bytes": d.BodyBytes}
	if enforcement != nil {
		body["enforcement"] = enforcement
	}
	var out redeemResult
	err := s.call(ctx, http.MethodPost, "/egress-proxy/redeem", body, s.asProxy(), &out)
	return &out, err
}

func (s *server) complete(ctx context.Context, checkID string, status int, respHash *string, respBytes int64,
	errCode string, d time.Duration, receipt map[string]any) error {
	body := map[string]any{"check_id": checkID, "status": status, "response_sha256": respHash,
		"response_bytes": respBytes, "duration_ms": d.Milliseconds()}
	if errCode != "" {
		body["error"] = errCode
	}
	if receipt != nil {
		body["receipt"] = receipt
	}
	return s.call(ctx, http.MethodPost, "/egress-proxy/complete", body, s.asProxy(), nil)
}

// plan: a gateway action the agent sent to this proxy, for the server to
// judge (POST /egress-proxy/<kind>/plan; app/pvp/proxy_actions.py). body is
// passed as the agent sent it; the answer keeps numbers as text.
func (s *server) plan(ctx context.Context, kind, agentKey string, body []byte) (map[string]any, error) {
	headers := s.asProxy()
	headers["X-Agent-Key"] = agentKey
	agentHeaders(ctx, headers)
	return s.callJSON(ctx, http.MethodPost, "/egress-proxy/"+kind+"/plan", json.RawMessage(body), headers)
}

// completeAction records a gateway action this proxy executed: its output
// (metadata only), or enforcement - the proxy refused it after all.
func (s *server) completeAction(ctx context.Context, checkID string, output map[string]any, d time.Duration,
	receipt, enforcement map[string]any) (int64, error) {
	status := 0
	if n, ok := output["status"].(int); ok {
		status = n
	}
	body := map[string]any{"check_id": checkID, "status": status, "duration_ms": d.Milliseconds(), "output": output}
	if receipt != nil {
		body["receipt"] = receipt
	}
	if enforcement != nil {
		body["enforcement"] = enforcement
	}
	var out struct {
		ActionID int64 `json:"action_id"`
	}
	err := s.call(ctx, http.MethodPost, "/egress-proxy/complete", body, s.asProxy(), &out)
	return out.ActionID, err
}

// offlineActions hands over what this proxy did while Provenza was
// unreachable (offline.go); the answer says what became of each.
func (s *server) offlineActions(ctx context.Context, actions []json.RawMessage) ([]map[string]any, error) {
	var out struct {
		Results []map[string]any `json:"results"`
	}
	err := s.call(ctx, http.MethodPost, "/egress-proxy/offline-actions", map[string]any{"actions": actions},
		s.asProxy(), &out)
	return out.Results, err
}

// reconciliationState: the server's current manifest and Tool Registry, to
// compare with the release held before the outage (killswitch.go).
func (s *server) reconciliationState(ctx context.Context) (map[string]any, error) {
	return s.callJSON(ctx, http.MethodGet, "/egress-proxy/reconciliation", nil, s.asProxy())
}

// postKillSwitch reports the kill switch and its reconciliation report.
func (s *server) postKillSwitch(ctx context.Context, body map[string]any) error {
	return s.call(ctx, http.MethodPost, "/egress-proxy/kill-switch", body, s.asProxy(), nil)
}

// liftSignatures: the administrators' signatures collected for the report.
func (s *server) liftSignatures(ctx context.Context) (map[string]any, error) {
	return s.callJSON(ctx, http.MethodGet, "/egress-proxy/kill-switch/lift", nil, s.asProxy())
}

// lifted tells the server the kill switch is lifted.
func (s *server) lifted(ctx context.Context, reportSHA string, signers []string) error {
	return s.call(ctx, http.MethodPost, "/egress-proxy/kill-switch/lifted",
		map[string]any{"report_sha256": reportSHA, "signers": signers}, s.asProxy(), nil)
}
