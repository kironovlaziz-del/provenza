// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

// Package egress is the Provenza egress proxy: agents reach external APIs only
// through it, and it holds the credentials (docs/pvp/spec.md, 5.5).
//
//	agent ──HTTP──► 127.0.0.1:8443/<route>/<path>
//	   mediated  X-Agent-Key: the proxy checks for that agent (/egress-proxy/check)
//	   SDK       X-Provenza-Check-Id: the agent already holds a check
//	──► redeem (the exact request, hashes only) ──► upstream from the route table,
//	    credential injected ──► response streamed back ──► complete (status, hash)
//
// What reaches the upstream is decided by the server and the route table, never
// by the request: the upstream host, the credential, the methods and path
// prefixes. The agent's own credentials and Provenza headers are never forwarded.
package egress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Descriptor is the request as checked and redeemed: hashes only, never content.
type Descriptor struct {
	Route       string  `json:"route"`
	Method      string  `json:"method"`
	Path        string  `json:"path"`
	QuerySHA256 *string `json:"query_sha256"`
	BodySHA256  *string `json:"body_sha256"`
	BodyBytes   int64   `json:"body_bytes"`
}

func sha256Hex(b []byte) *string {
	if len(b) == 0 {
		return nil
	}
	s := sha256.Sum256(b)
	h := hex.EncodeToString(s[:])
	return &h
}

// hop-by-hop and credential headers: never forwarded upstream (or back)
var dropped = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true, "Te": true,
	"Trailer": true, "Transfer-Encoding": true, "Upgrade": true, "Authorization": true, "Cookie": true,
	"X-Agent-Key": true, "Host": true, "Content-Length": true,
}

func forwardable(name string) bool {
	return !dropped[http.CanonicalHeaderKey(name)] && !strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Provenza-")
}

// pathProblem mirrors the server's rule: no "." / ".." segments, no encoded separators.
func pathProblem(path string) string {
	if !strings.HasPrefix(path, "/") {
		return "the path must start with /"
	}
	for _, seg := range strings.Split(path, "/") {
		dec, err := url.PathUnescape(seg)
		if err != nil || dec == "." || dec == ".." || strings.ContainsAny(dec, "/\\") {
			return "the path has a '.' / '..' segment or an encoded separator"
		}
	}
	return ""
}

func prefixAllows(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if p == "/" || path == p || strings.HasPrefix(path, strings.TrimRight(p, "/")+"/") {
			return true
		}
	}
	return false
}

// Proxy serves agents.
type Proxy struct {
	cfg      *Config
	srv      *server
	upstream *http.Client
	log      *slog.Logger

	mu     sync.RWMutex
	routes map[string]Route
	loaded bool
}

// New makes a proxy; Start loads the routes before it serves.
func New(cfg *Config, proxyKey string, logger *slog.Logger) *Proxy {
	if logger == nil {
		logger = slog.Default()
	}
	return &Proxy{cfg: cfg, srv: newServer(cfg.ServerURL, proxyKey, cfg.ServerTimeout.Duration), log: logger,
		upstream: &http.Client{Timeout: cfg.UpstreamTimeout.Duration,
			// a redirect goes back to the agent: following it here would carry the credential elsewhere
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Refresh loads the route table (and server-held secrets) once.
func (p *Proxy) Refresh(ctx context.Context) (time.Duration, error) {
	routes, every, err := p.srv.config(ctx)
	if err != nil {
		return time.Minute, err
	}
	m := make(map[string]Route, len(routes))
	for _, r := range routes {
		m[r.Slug] = r
	}
	p.mu.Lock()
	p.routes, p.loaded = m, true
	p.mu.Unlock()
	return every, nil
}

// Start loads the routes and keeps them fresh until ctx ends. The first load
// must succeed: without the table there is nothing it may forward.
func (p *Proxy) Start(ctx context.Context) error {
	every, err := p.Refresh(ctx)
	if err != nil {
		return err
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(every):
				next, err := p.Refresh(ctx)
				if err != nil {
					p.log.Warn("provenza proxy: route refresh failed; keeping the last table", "err", err)
				}
				every = next
			}
		}
	}()
	return nil
}

func (p *Proxy) route(slug string) (Route, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	r, ok := p.routes[slug]
	return r, ok && p.loaded
}

// refuse answers the agent: an OpenAI-style error body, never the request's content.
func refuse(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Provenza-Refused", "1")
	w.Header().Set("X-Should-Retry", "false")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// /<route>/<path>, on the raw (escaped) path: what is checked is what is sent
	raw := r.URL.EscapedPath()
	slug, rest, _ := strings.Cut(strings.TrimPrefix(raw, "/"), "/")
	path := "/" + rest
	route, ok := p.route(slug)
	if !ok {
		refuse(w, http.StatusNotFound, "provenza_unknown_route", "no such egress route: "+slug)
		return
	}
	if !contains(route.Methods, r.Method) {
		refuse(w, http.StatusMethodNotAllowed, "provenza_method", r.Method+" is not allowed on this route")
		return
	}
	if problem := pathProblem(path); problem != "" || !prefixAllows(path, route.PathPrefixes) {
		refuse(w, http.StatusForbidden, "provenza_path", "the path is outside this route")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, route.MaxBodyBytes+1))
	if err != nil {
		refuse(w, http.StatusBadRequest, "provenza_body", "could not read the request body")
		return
	}
	if int64(len(body)) > route.MaxBodyBytes {
		refuse(w, http.StatusRequestEntityTooLarge, "provenza_body_too_large", "the body is larger than this route allows")
		return
	}
	var query *string
	if r.URL.RawQuery != "" {
		query = sha256Hex([]byte(r.URL.RawQuery))
	}
	d := Descriptor{Route: slug, Method: r.Method, Path: path, QuerySHA256: query, BodySHA256: sha256Hex(body),
		BodyBytes: int64(len(body))}

	ctx := r.Context()
	checkID := r.Header.Get("X-Provenza-Check-Id")
	if checkID == "" { // mediated: check on the agent's behalf with its key
		key := r.Header.Get("X-Agent-Key")
		if key == "" {
			refuse(w, http.StatusUnauthorized, "provenza_agent_key_required",
				"send the agent's key (X-Agent-Key), or a check id (X-Provenza-Check-Id)")
			return
		}
		chk, err := p.srv.check(ctx, key, d)
		if err != nil {
			p.serverFailure(w, err)
			return
		}
		checkID = chk.CheckID
	}
	red, err := p.srv.redeem(ctx, checkID, d) // also records a refused check
	if err != nil {
		p.serverFailure(w, err)
		return
	}
	if !red.Allowed {
		refuse(w, http.StatusForbidden, "provenza_denied", fmt.Sprintf("Refused by Provenza: %s", red.Reason))
		return
	}
	p.forward(w, r, route, path, body, checkID)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (p *Proxy) serverFailure(w http.ResponseWriter, err error) {
	var se *serverError
	switch {
	case errors.As(err, &se) && se.Status == http.StatusUnauthorized:
		refuse(w, http.StatusUnauthorized, "provenza_unauthorized", "the agent key was not accepted")
	case errors.As(err, &se):
		refuse(w, http.StatusForbidden, "provenza_refused", fmt.Sprintf("Refused by Provenza: %v", se.Detail))
	default: // fail-closed
		p.log.Warn("provenza proxy: server unreachable; request not sent", "err", err)
		refuse(w, http.StatusServiceUnavailable, "provenza_unavailable", "Provenza is unreachable; the request was not sent")
	}
}

type hashingReader struct {
	r io.Reader
	h hash.Hash
	n int64
}

func (h *hashingReader) Read(b []byte) (int, error) {
	n, err := h.r.Read(b)
	h.h.Write(b[:n])
	h.n += int64(n)
	return n, err
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, route Route, path string, body []byte, checkID string) {
	target := strings.TrimRight(route.UpstreamURL, "/") + path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	started := time.Now()
	report := func(status int, h *string, n int64, errCode string) {
		// the agent's request may be over; the record must still be written
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), p.cfg.ServerTimeout.Duration)
		defer cancel()
		if err := p.srv.complete(ctx, checkID, status, h, n, errCode, time.Since(started)); err != nil {
			p.log.Error("provenza proxy: could not record a forwarded request (open redemption)", "check", short(checkID),
				"err", err)
		}
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, target, strings.NewReader(string(body)))
	if err != nil {
		report(0, nil, 0, "proxy.bad_upstream_url")
		refuse(w, http.StatusBadGateway, "provenza_upstream", "bad upstream URL")
		return
	}
	for k, vs := range r.Header {
		if forwardable(k) {
			for _, v := range vs {
				out.Header.Add(k, v)
			}
		}
	}
	switch route.CredentialSource {
	case "server":
		if route.Secret != "" {
			out.Header.Set(route.AuthHeader, route.Secret)
		}
	case "local":
		header, value, err := p.cfg.localSecret(route.Slug, route.AuthHeader)
		if err != nil {
			p.log.Error("provenza proxy: local credential", "route", route.Slug, "err", err)
			report(0, nil, 0, "proxy.local_credential_missing")
			refuse(w, http.StatusBadGateway, "provenza_credential", "this route's credential is not configured on the proxy")
			return
		}
		out.Header.Set(header, value)
	}
	resp, err := p.upstream.Do(out)
	if err != nil {
		report(0, nil, 0, "upstream.unreachable")
		refuse(w, http.StatusBadGateway, "provenza_upstream", "the upstream could not be reached")
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		if forwardable(k) || http.CanonicalHeaderKey(k) == "Content-Length" {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
	}
	w.WriteHeader(resp.StatusCode)
	hr := &hashingReader{r: resp.Body, h: sha256.New()}
	_, copyErr := io.Copy(w, hr) // streamed: no size limit on what the agent receives, only hashed
	sum := hex.EncodeToString(hr.h.Sum(nil))
	var h *string
	if hr.n > 0 {
		h = &sum
	}
	code := ""
	if copyErr != nil {
		code = "proxy.response_interrupted"
	}
	report(resp.StatusCode, h, hr.n, code)
}

// short: enough of a check id to find it in the logs, never all of it.
func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
