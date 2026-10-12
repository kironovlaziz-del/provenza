// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package provenza

// HTTP to a Provenza server:
//
//	network error, timeout, HTTP 5xx  -> *UnavailableError (fail-closed: nothing ran)
//	HTTP 4xx                          -> *RequestError
//
// Redirects are not followed: the agent key is never re-sent elsewhere.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const apiPrefix = "/api/v1"

type client struct {
	serverURL string
	apiKey    string
	http      *http.Client
}

func newClient(serverURL, apiKey string, timeout time.Duration, hc *http.Client) (*client, error) {
	if !strings.HasPrefix(serverURL, "https://") && !strings.HasPrefix(serverURL, "http://") {
		return nil, &ConfigError{"ServerURL must start with https:// (or http:// for a local server)"}
	}
	c := http.Client{Timeout: timeout}
	if hc != nil {
		c = *hc // a copy: the caller's client is not changed
		if c.Timeout == 0 {
			c.Timeout = timeout
		}
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client{serverURL: strings.TrimRight(serverURL, "/"), apiKey: apiKey, http: &c}, nil
}

func (c *client) do(ctx context.Context, method, path string, body any, authenticated bool) (map[string]any, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.serverURL+apiPrefix+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "provenza-go")
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		if c.apiKey == "" {
			return nil, &RequestError{Status: 401, Detail: "this agent has no API key", Path: path}
		}
		req.Header.Set("X-Agent-Key", c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		return nil, &UnavailableError{fmt.Sprintf("%s: %v", path, err)}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, &UnavailableError{fmt.Sprintf("%s: %v", path, err)}
	}
	if resp.StatusCode >= 500 || (resp.StatusCode >= 300 && resp.StatusCode < 400) {
		return nil, &UnavailableError{fmt.Sprintf("%s: HTTP %d", path, resp.StatusCode)}
	}
	var out map[string]any
	if len(bytes.TrimSpace(raw)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&out); err != nil && resp.StatusCode < 400 {
			return nil, &UnavailableError{path + ": the server answered with something that is not a JSON object"}
		}
	}
	if resp.StatusCode >= 400 {
		var detail any = strings.TrimSpace(string(raw))
		if d, ok := out["detail"]; ok {
			detail = d
		}
		return nil, &RequestError{Status: resp.StatusCode, Detail: detail, Path: path}
	}
	return out, nil
}

func (c *client) post(ctx context.Context, path string, body any, authenticated bool) (map[string]any, error) {
	return c.do(ctx, http.MethodPost, path, body, authenticated)
}

// helpers for reading JSON answers

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func optInt(m map[string]any, k string) *int64 {
	if n, ok := m[k].(json.Number); ok {
		if v, err := n.Int64(); err == nil {
			return &v
		}
	}
	return nil
}
