// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

// Package client talks to Provenza's sensor API with the sensor's key.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/config"
)

const apiPrefix = "/api/v1/egress-sensor"

type Client struct {
	base string
	key  string
	http *http.Client
}

func New(s config.Settings) (*Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // the sensor talks to Provenza directly
	if s.CAFile != "" {
		pem, err := os.ReadFile(s.CAFile)
		if err != nil {
			return nil, err
		}
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no certificates", s.CAFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &Client{
		base: strings.TrimRight(s.ProvenzaURL, "/"),
		key:  s.Key,
		http: &http.Client{Timeout: 20 * time.Second, Transport: tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

// ErrUnauthorized: the key was revoked or is wrong. The sensor keeps the
// policy it has.
var ErrUnauthorized = errors.New("Provenza refused the sensor key (revoked?)")

func (c *Client) do(ctx context.Context, method, path string, body any, hdr map[string]string) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+apiPrefix+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Sensor-Key", c.key)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		resp.Body.Close()
		return nil, ErrUnauthorized
	}
	return resp, nil
}

// Policy fetches the policy; (nil, nil) when it is still `version`.
func (c *Client) Policy(ctx context.Context, version string) (*config.Policy, error) {
	hdr := map[string]string{}
	if version != "" {
		hdr["If-None-Match"] = `"` + version + `"`
	}
	resp, err := c.do(ctx, http.MethodGet, "/config", nil, hdr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("policy: HTTP %d", resp.StatusCode)
	}
	var p config.Policy
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := p.Check(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (c *Client) post(ctx context.Context, path string, body any) error {
	resp, err := c.do(ctx, http.MethodPost, path, body, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	return nil
}

// Heartbeat is what the sensor reports about itself.
type Heartbeat struct {
	Hostname      string           `json:"hostname"`
	Version       string           `json:"version"`
	Kernel        string           `json:"kernel"`
	ConfigVersion *string          `json:"config_version,omitempty"`
	Enforcing     bool             `json:"enforcing"`
	Hooks         []string         `json:"hooks,omitempty"`
	Workloads     []WorkloadReport `json:"workloads,omitempty"`
	Warnings      []string         `json:"warnings,omitempty"`
	Errors        []string         `json:"errors,omitempty"`
	DroppedEvents uint64           `json:"dropped_events"`
}

type WorkloadReport struct {
	ID        uint32 `json:"id"`
	Cgroups   int    `json:"cgroups"`
	Processes int    `json:"processes"`
	// A nil slice serializes as null, which the backend rejects for a
	// List[str]; omit it, and the schema's default_factory fills it.
	Privileged []string `json:"privileged,omitempty"`
}

func (c *Client) Heartbeat(ctx context.Context, h Heartbeat) error {
	return c.post(ctx, "/heartbeat", h)
}

// Violation as the API takes it.
type Violation struct {
	WorkloadID uint32  `json:"workload_id"`
	Action     string  `json:"action"`
	Kind       string  `json:"kind"`
	Protocol   string  `json:"protocol"`
	DstIP      *string `json:"dst_ip,omitempty"`
	DstPort    *int    `json:"dst_port,omitempty"`
	DstName    *string `json:"dst_name,omitempty"`
	Comm       *string `json:"comm,omitempty"`
	Cgroup     *string `json:"cgroup,omitempty"`
	Isolated   bool    `json:"isolated"`
	Count      uint64  `json:"count"`
}

func (c *Client) Violations(ctx context.Context, vs []Violation) error {
	for len(vs) > 0 {
		n := len(vs)
		if n > 500 {
			n = 500
		}
		if err := c.post(ctx, "/violations", map[string]any{"events": vs[:n]}); err != nil {
			return err
		}
		vs = vs[n:]
	}
	return nil
}

// ---------------------------------------------------------------- cache

// SavePolicy keeps the last policy on disk (0600), so the sensor enforces it
// after a restart even when Provenza cannot be reached.
func SavePolicy(dir string, p *config.Policy) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".policy.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "policy.json"))
}

func LoadPolicy(dir string) (*config.Policy, error) {
	b, err := os.ReadFile(filepath.Join(dir, "policy.json"))
	if err != nil {
		return nil, err
	}
	var p config.Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, p.Check()
}
