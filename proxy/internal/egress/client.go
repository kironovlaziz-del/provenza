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
	"time"
)

// Route as the server hands it to proxies (GET /egress-proxy/config).
type Route struct {
	Slug             string   `json:"slug"`
	UpstreamURL      string   `json:"upstream_url"`
	Methods          []string `json:"methods"`
	PathPrefixes     []string `json:"path_prefixes"`
	CredentialSource string   `json:"credential_source"`
	AuthHeader       string   `json:"auth_header"`
	Secret           string   `json:"secret"` // kept in memory only
	MaxBodyBytes     int64    `json:"max_body_bytes"`
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
	http     *http.Client
}

func newServer(base, proxyKey string, timeout time.Duration) *server {
	return &server{base: base, proxyKey: proxyKey, http: &http.Client{Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// call sends one request; headers carry either the proxy key or an agent key.
func (s *server) call(ctx context.Context, method, path string, body any, headers map[string]string, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.base+"/api/v1"+path, reader)
	if err != nil {
		return err
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
		return fmt.Errorf("%w: %s: %v", errUnavailable, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil || resp.StatusCode >= 500 || (resp.StatusCode >= 300 && resp.StatusCode < 400) {
		return fmt.Errorf("%w: %s: HTTP %d", errUnavailable, path, resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		var e struct {
			Detail any `json:"detail"`
		}
		_ = json.Unmarshal(raw, &e)
		return &serverError{Status: resp.StatusCode, Detail: e.Detail}
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (s *server) asProxy() map[string]string { return map[string]string{"X-Proxy-Key": s.proxyKey} }

func (s *server) config(ctx context.Context) ([]Route, time.Duration, error) {
	var out struct {
		Routes         []Route `json:"routes"`
		RefreshSeconds int     `json:"refresh_seconds"`
	}
	if err := s.call(ctx, http.MethodGet, "/egress-proxy/config", nil, s.asProxy(), &out); err != nil {
		return nil, 0, err
	}
	every := time.Duration(out.RefreshSeconds) * time.Second
	if every <= 0 {
		every = time.Minute
	}
	return out.Routes, every, nil
}

// agentID of an agent key (GET /agent-identity/me, called with that key).
func (s *server) agentID(ctx context.Context, agentKey string) (int64, error) {
	var out struct {
		AgentID int64 `json:"agent_id"`
	}
	err := s.call(ctx, http.MethodGet, "/agent-identity/me", nil, map[string]string{"X-Agent-Key": agentKey}, &out)
	return out.AgentID, err
}

type checkResult struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	CheckID  string `json:"check_id"`
}

// check asks the server on the agent's behalf, with the agent's own key.
func (s *server) check(ctx context.Context, agentKey string, agentID int64, d Descriptor) (*checkResult, error) {
	var out checkResult
	err := s.call(ctx, http.MethodPost, "/agents/actions/check", map[string]any{
		"agent_id": agentID, "action_type": "proxy", "tool_name": "proxy." + d.Route, "input": d,
	}, map[string]string{"X-Agent-Key": agentKey}, &out)
	return &out, err
}

type redeemResult struct {
	Allowed  bool   `json:"allowed"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	ActionID int64  `json:"action_id"`
}

func (s *server) redeem(ctx context.Context, checkID string, d Descriptor) (*redeemResult, error) {
	body := map[string]any{"check_id": checkID, "route": d.Route, "method": d.Method, "path": d.Path,
		"query_sha256": d.QuerySHA256, "body_sha256": d.BodySHA256, "body_bytes": d.BodyBytes}
	var out redeemResult
	err := s.call(ctx, http.MethodPost, "/egress-proxy/redeem", body, s.asProxy(), &out)
	return &out, err
}

func (s *server) complete(ctx context.Context, checkID string, status int, respHash *string, respBytes int64,
	errCode string, d time.Duration) error {
	body := map[string]any{"check_id": checkID, "status": status, "response_sha256": respHash,
		"response_bytes": respBytes, "duration_ms": d.Milliseconds()}
	if errCode != "" {
		body["error"] = errCode
	}
	return s.call(ctx, http.MethodPost, "/egress-proxy/complete", body, s.asProxy(), nil)
}
