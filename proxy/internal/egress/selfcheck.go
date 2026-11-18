// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

// The egress self-check of an agent's host (docs/egress-lockdown.md), as the
// SDKs run it (provenza.egress_check, sdk/go/egress_check.go): Provenza names
// targets on the internet and a beacon on itself, this host tries each
// directly - a TCP connect; an HTTP GET for the beacon, through any proxy the
// environment configures - and reports what it reached, signed with the
// agent's key. Provenza's verdict: "confined" when nothing was reached, "open"
// otherwise. `provenza-proxy connect` runs it once the client is connected,
// agent mode at start-up and once a day, so Protection coverage shows whether
// the agent can only go through Provenza without anyone running it by hand.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

// SelfcheckInterval: how often agent mode checks again (a check older than 30
// days no longer counts in Protection coverage).
const SelfcheckInterval = 24 * time.Hour

// SelfcheckAPIs: where Provenza's API is for this agent - its server, and, when
// agent mode's upstream is a local egress proxy, that proxy's relay (a confined
// host may reach Provenza only through it; relay_provenza must be on).
func SelfcheckAPIs(id *AgentIdentity, upstream string) []string {
	var out []string
	if s := strings.TrimRight(id.Server, "/"); s != "" {
		out = append(out, s+"/api/v1")
	}
	if u := strings.TrimRight(upstream, "/"); u != "" && !strings.HasSuffix(u, "/api/v1") && keyMayTravel(u) {
		out = append(out, u+"/_provenza/api/v1")
	}
	return out
}

// keyMayTravel: the agent's API key goes in the clear only to this machine.
func keyMayTravel(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	h := u.Hostname()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return u.Scheme == "http" && ip != nil && ip.IsLoopback()
}

// Selfcheck runs one egress self-check and returns Provenza's verdict.
// timeout: for each target and the beacon. client: for Provenza's API (nil:
// a default one).
func (id *AgentIdentity) Selfcheck(ctx context.Context, apis []string, timeout time.Duration, client *http.Client) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	var started struct {
		CheckID   int64    `json:"check_id"`
		Targets   []string `json:"targets"`
		BeaconURL string   `json:"beacon_url"`
	}
	api, err := id.firstAPI(ctx, client, apis, &started)
	if err != nil {
		return "", err
	}
	if started.CheckID < 1 {
		return "", errors.New("Provenza did not start an egress check")
	}
	results := make([]map[string]any, len(started.Targets))
	var wg sync.WaitGroup
	for i, t := range started.Targets {
		wg.Add(1)
		go func(i int, t string) {
			defer wg.Done()
			results[i] = map[string]any{"target": t, "reachable": directConnect(ctx, t, timeout)}
		}(i, t)
	}
	wg.Wait()
	beacon := beaconReached(ctx, started.BeaconURL, timeout)
	sig, pq, err := id.signSelfcheck(started.CheckID, results, beacon)
	if err != nil {
		return "", err
	}
	report := map[string]any{"results": results, "beacon_reached": beacon, "signature": sig}
	if pq != "" {
		report["pq_signature"] = pq
	}
	var verdict struct {
		Verdict string `json:"verdict"`
	}
	if err := id.apiPost(ctx, client, fmt.Sprintf("%s/agents/egress-check/%d/report", api, started.CheckID),
		report, &verdict); err != nil {
		return "", err
	}
	return verdict.Verdict, nil
}

// firstAPI starts the check at the first of apis that answers; a refusal from
// Provenza is final, only an unreachable address moves on to the next.
func (id *AgentIdentity) firstAPI(ctx context.Context, client *http.Client, apis []string, out any) (string, error) {
	if len(apis) == 0 {
		return "", errors.New("the identity names no Provenza server")
	}
	var last error
	for _, api := range apis {
		err := id.apiPost(ctx, client, api+"/agents/egress-check", map[string]any{}, out)
		if err == nil {
			return api, nil
		}
		last = err
		var refused *apiRefusal
		if errors.As(err, &refused) && refused.status != http.StatusNotFound && refused.status != http.StatusBadGateway {
			return "", err // Provenza answered: another address would answer the same
		}
	}
	return "", last
}

type apiRefusal struct {
	status int
	detail string
}

func (e *apiRefusal) Error() string {
	return fmt.Sprintf("Provenza refused (HTTP %d): %s", e.status, e.detail)
}

func (id *AgentIdentity) apiPost(ctx context.Context, client *http.Client, endpoint string, in, out any) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Key", id.APIKey)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Provenza is not reachable at %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		detail := strings.TrimSpace(string(data))
		if len(detail) > 200 {
			detail = detail[:200]
		}
		return &apiRefusal{status: resp.StatusCode, detail: detail}
	}
	return json.Unmarshal(data, out)
}

// signSelfcheck: what the server verifies (egress_check.signed_payload) - the
// results sorted by target - signed with the agent's key; both halves for a
// hybrid key.
func (id *AgentIdentity) signSelfcheck(checkID int64, results []map[string]any, beacon bool) (string, string, error) {
	sorted := make([]any, len(results))
	idx := make([]int, len(results))
	for i := range idx {
		idx[i] = i
	}
	// a stable insertion sort: a handful of targets
	for i := 1; i < len(idx); i++ {
		for j := i; j > 0 && results[idx[j]]["target"].(string) < results[idx[j-1]]["target"].(string); j-- {
			idx[j], idx[j-1] = idx[j-1], idx[j]
		}
	}
	for i, j := range idx {
		sorted[i] = map[string]any{"target": results[j]["target"], "reachable": results[j]["reachable"]}
	}
	payload := map[string]any{"type": "egress.report", "agent_id": id.AgentID, "check_id": checkID,
		"results": sorted, "beacon_reached": beacon}
	msg, err := canon.Bytes(payload)
	if err != nil {
		return "", "", err
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(id.key, msg))
	if id.pqKey == nil {
		return sig, "", nil
	}
	pq, err := id.pqKey.Sign(nil, msg, nil)
	if err != nil {
		return "", "", err
	}
	return sig, base64.StdEncoding.EncodeToString(pq), nil
}

func directConnect(ctx context.Context, target string, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func beaconReached(ctx context.Context, url string, timeout time.Duration) bool {
	if url == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	// through any proxy the environment configures, as any HTTP client of the host would go
	client := &http.Client{Transport: http.DefaultTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusNoContent
}
