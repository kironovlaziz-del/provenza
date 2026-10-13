// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

import (
	"io"
	"net/http"
	"strings"
)

// RelayPrefix: with relay_provenza on, /_provenza/api/v1/... is passed to the
// Provenza server unchanged. An agent locked down to this proxy alone (its
// network allows nothing else: docs/egress-lockdown.md) still reaches Provenza
// - PROVENZA_URL=http://<proxy>/_provenza - and nothing else. The relay is a
// pipe to the one configured server: the request chooses only the path under
// /api/v1/, and it authenticates itself (the agent's key and signatures); the
// proxy's own key is never added.
const RelayPrefix = "/_provenza"

const relayMaxBody = 16 << 20

var relayRequestHeaders = []string{"Content-Type", "Accept", "Authorization", "X-Agent-Key", "User-Agent",
	"Mcp-Protocol-Version", "Mcp-Method", "Mcp-Name", "Origin"}

var relayResponseHeaders = []string{"Content-Type", "Retry-After", "Www-Authenticate", "Cache-Control",
	"X-Should-Retry", "Mcp-Protocol-Version"}

func (p *Proxy) relay(w http.ResponseWriter, r *http.Request, raw string) {
	path := strings.TrimPrefix(raw, RelayPrefix)
	if !strings.HasPrefix(path, "/api/v1/") || pathProblem(path) != "" {
		refuse(w, http.StatusForbidden, "provenza_relay_path", "only /_provenza/api/v1/... is relayed to Provenza")
		return
	}
	if r.ContentLength > relayMaxBody {
		refuse(w, http.StatusRequestEntityTooLarge, "provenza_body_too_large", "the body is too large to relay")
		return
	}
	target := p.cfg.ServerURL + path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, http.MaxBytesReader(w, r.Body, relayMaxBody))
	if err != nil {
		refuse(w, http.StatusBadRequest, "provenza_relay", "could not build the request")
		return
	}
	req.ContentLength = r.ContentLength
	for _, h := range relayRequestHeaders {
		if v := r.Header.Values(h); len(v) > 0 {
			req.Header[http.CanonicalHeaderKey(h)] = v
		}
	}
	resp, err := p.relayClient.Do(req)
	if err != nil {
		refuse(w, http.StatusServiceUnavailable, "provenza_unavailable", "Provenza could not be reached")
		return
	}
	defer resp.Body.Close()
	for _, h := range relayResponseHeaders {
		if v := resp.Header.Values(h); len(v) > 0 {
			w.Header()[http.CanonicalHeaderKey(h)] = v
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
