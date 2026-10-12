// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package provenza

// Requests through the Provenza egress proxy in SDK mode (docs/pvp/spec.md, 5.5):
// the agent checks the request itself and sends the check id; the proxy redeems
// it and refuses anything other than exactly the checked request.
//
//	chk, err := agent.ProxyCheck(ctx, "stripe", "POST", "/v1/charges", "", body)
//	req, _ := http.NewRequest("POST", "http://127.0.0.1:8443/stripe/v1/charges", bytes.NewReader(body))
//	for k, v := range chk.ProxyHeaders() { req.Header.Set(k, v) }
//
// path and query are exactly what goes on the wire (percent-encoding kept), body
// the exact bytes: the proxy hashes what it receives.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// ProxyHeader is the header the egress proxy redeems.
const ProxyHeader = "X-Provenza-Check-Id"

// ProxyDescriptor is the checked input of a proxy request - hashes only, as the proxy computes it.
func ProxyDescriptor(route, method, path string, query string, body []byte) (map[string]any, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, errors.New("provenza: path must start with /")
	}
	if strings.Contains(path, "?") {
		return nil, errors.New("provenza: pass the query string as query, not in path")
	}
	return map[string]any{"route": route, "method": strings.ToUpper(method), "path": path,
		"query_sha256": hashOrNull([]byte(query)), "body_sha256": hashOrNull(body), "body_bytes": len(body)}, nil
}

func hashOrNull(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ProxyCheck checks a request to send through the egress proxy (SDK mode). Send
// it with chk.ProxyHeaders(); the proxy records it - do not Record it.
func (a *Agent) ProxyCheck(ctx context.Context, route, method, path, query string, body []byte) (*Check, error) {
	input, err := ProxyDescriptor(route, method, path, query, body)
	if err != nil {
		return nil, err
	}
	return a.check(ctx, "proxy."+route, input, callOptions{actionType: "proxy"})
}

// ProxyHeaders returns the header the egress proxy redeems for this check.
func (c *Check) ProxyHeaders() map[string]string { return map[string]string{ProxyHeader: c.CheckID} }
