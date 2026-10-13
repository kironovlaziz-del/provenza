// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package provenza

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"
)

// EgressSelfcheck tells whether this host is confined to the Provenza egress
// proxy. The server names targets on the internet and a beacon on itself; this
// host tries each directly (a TCP connect; an HTTP GET for the beacon, through
// any proxy the environment configures) and reports what it reached, signed.
// The result is the server's verdict: "confined" or "open". Run it at start-up
// and periodically; see docs/egress-lockdown.md.
func (a *Agent) EgressSelfcheck(ctx context.Context, timeout time.Duration) (map[string]any, error) {
	c, err := a.connected()
	if err != nil {
		return nil, err
	}
	started, err := c.post(ctx, "/agents/egress-check", map[string]any{}, true)
	if err != nil {
		return nil, err
	}
	var targets []string
	if list, ok := started["targets"].([]any); ok {
		for _, t := range list {
			if s, ok := t.(string); ok {
				targets = append(targets, s)
			}
		}
	}
	results := make([]map[string]any, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t string) {
			defer wg.Done()
			results[i] = map[string]any{"target": t, "reachable": egressConnect(ctx, t, timeout)}
		}(i, t)
	}
	wg.Wait()
	beaconReached := egressBeacon(ctx, str(started, "beacon_url"), timeout)
	checkID := optInt(started, "check_id")
	if checkID == nil {
		return nil, fmt.Errorf("provenza: the server did not start an egress check")
	}
	sig, pq, err := a.identity.Keys.Sign(egressPayload(a.AgentID(), *checkID, results, beaconReached))
	if err != nil {
		return nil, err
	}
	body := map[string]any{"results": results, "beacon_reached": beaconReached, "signature": sig}
	if pq != "" {
		body["pq_signature"] = pq
	}
	return c.post(ctx, fmt.Sprintf("/agents/egress-check/%d/report", *checkID), body, true)
}

func egressConnect(ctx context.Context, target string, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func egressBeacon(ctx context.Context, url string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusNoContent
}

// egressPayload is what the server verifies: the results sorted by target.
func egressPayload(agentID any, checkID int64, results []map[string]any, beaconReached bool) map[string]any {
	sorted := make([]any, len(results))
	idx := make([]int, len(results))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(x, y int) bool { return results[idx[x]]["target"].(string) < results[idx[y]]["target"].(string) })
	for i, j := range idx {
		sorted[i] = map[string]any{"target": results[j]["target"], "reachable": results[j]["reachable"]}
	}
	return map[string]any{"type": "egress.report", "agent_id": agentID, "check_id": checkID, "results": sorted,
		"beacon_reached": beaconReached}
}
