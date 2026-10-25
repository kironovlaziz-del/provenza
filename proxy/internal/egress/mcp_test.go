// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

// fakeMCP: an MCP server of either era, behind a credential.
type fakeMCP struct {
	mu      sync.Mutex
	srv     *httptest.Server
	legacy  bool
	desc    string // the tool's description (change it: drift)
	calls   []map[string]any
	callHdr []http.Header
	headers []http.Header
}

func newFakeMCP(t *testing.T, legacy bool) *fakeMCP {
	f := &fakeMCP{legacy: legacy, desc: "Look up an order"}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.headers = append(f.headers, r.Header.Clone())
		if r.Header.Get("Authorization") != "Bearer mcp-secret" {
			w.WriteHeader(401)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var msg map[string]any
		_ = json.Unmarshal(raw, &msg)
		method, _ := msg["method"].(string)
		reply := func(result any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": msg["id"], "result": result})
		}
		if f.legacy {
			switch method {
			case "server/discover":
				w.WriteHeader(404)
				return
			case "initialize":
				w.Header().Set("Mcp-Session-Id", "sess-1")
				reply(map[string]any{"protocolVersion": "2025-06-18", "serverInfo": map[string]any{"name": "legacy"}})
				return
			case "notifications/initialized":
				w.WriteHeader(202)
				return
			}
			if r.Header.Get("Mcp-Session-Id") != "sess-1" {
				w.WriteHeader(400)
				return
			}
		} else if method == "server/discover" {
			reply(map[string]any{"supportedVersions": []string{mcpModern},
				"_meta": map[string]any{"io.modelcontextprotocol/serverInfo": map[string]any{"name": "modern"}}})
			return
		}
		switch method {
		case "tools/list":
			reply(map[string]any{"tools": []any{map[string]any{"name": "lookup", "description": f.desc,
				"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
					"region": map[string]any{"type": "string", "x-mcp-header": "Region"}}}}}})
		case "tools/call":
			f.calls, f.callHdr = append(f.calls, msg), append(f.callHdr, r.Header.Clone())
			w.Header().Set("Content-Type", "text/event-stream")
			b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": msg["id"],
				"result": map[string]any{"content": []any{map[string]any{"type": "text", "text": "order 7: shipped"}}}})
			_, _ = io.WriteString(w, "event: message\ndata: "+string(b)+"\n\n")
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func mcpSetup(t *testing.T, f *fakeMCP, decision string) (*fakeProvenza, *httptest.Server, *[]map[string]any) {
	up := newUpstream(t, ok)
	fake, _, front := setup(t, up, nil)
	var syncs []map[string]any
	p := front.Config.Handler.(*Proxy)
	p.mu.Lock()
	p.mcpServers = map[string]MCPServer{"orders": {ID: "11", Slug: "orders", URL: f.srv.URL + "/mcp", Protocol: "auto",
		AuthHeader: "Authorization", CredentialSource: "sealed", TimeoutSeconds: 5}}
	p.mu.Unlock()
	fake.mu.Lock()
	fake.sealed = []sealedObject{{object: "mcp_server", id: 11, upstream: origin(f.srv.URL), value: "Bearer mcp-secret"}}
	fake.plans = map[string]func(map[string]any) map[string]any{"mcp": func(b map[string]any) map[string]any {
		if decision != "allowed" {
			return map[string]any{"decision": "refused", "result": textResult("Refused by Provenza (action #4): no")}
		}
		args, _ := canon.Of(b["arguments"])
		sha, _ := canon.SHA256(args)
		return map[string]any{"decision": "allowed", "check_id": "chk_mcp_" + strings.Repeat("z", 12), "agent_id": 5,
			"chain_id": nil, "action_type": "tool_call", "tool_name": b["name"], "input_sha256": sha, "approval": nil,
			"arguments": b["arguments"], "upstream_name": "lookup", "pinned_digest": b["live_digest"],
			"input_schema": map[string]any{"type": "object", "properties": map[string]any{
				"region": map[string]any{"type": "string", "x-mcp-header": "Region"}}},
			"server":     map[string]any{"id": 11, "protocol": "auto"},
			"credential": map[string]any{"object": "mcp_server", "id": 11, "source": "sealed", "header": "Authorization"}}
	}}
	fake.mu.Unlock()
	if err := p.refreshCredentials(context.Background()); err != nil {
		t.Fatal(err)
	}
	return fake, front, &syncs
}

func mcpCall(t *testing.T, front string, body string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", front+"/_mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+agentKey)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func TestAnMCPToolCallGoesToTheServerWithItsSealedCredential(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		f := newFakeMCP(t, legacy)
		fake, front, _ := mcpSetup(t, f, "allowed")
		body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"orders.lookup","arguments":{"region":"eu"},
			"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
		status, out := mcpCall(t, front.URL, body, map[string]string{"MCP-Protocol-Version": mcpModern,
			"Mcp-Method": "tools/call", "Mcp-Name": "orders.lookup"})
		result, _ := out["result"].(map[string]any)
		if status != 200 || result == nil || result["resultType"] != "complete" {
			t.Fatalf("legacy=%v: %d %v", legacy, status, out)
		}
		text := result["content"].([]any)[0].(map[string]any)["text"]
		if text != "order 7: shipped" {
			t.Fatalf("legacy=%v: result %v", legacy, result)
		}
		f.mu.Lock()
		call := f.calls[len(f.calls)-1]
		last := f.callHdr[len(f.callHdr)-1]
		f.mu.Unlock()
		if call["params"].(map[string]any)["name"] != "lookup" {
			t.Fatalf("upstream call %v", call)
		}
		if !legacy && (last.Get("Mcp-Param-Region") != "eu" || last.Get("Mcp-Name") != "lookup") {
			t.Fatalf("modern headers %v", last)
		}
		fake.mu.Lock()
		planned := fake.planned[len(fake.planned)-1]
		done := fake.completed[len(fake.completed)-1]
		fake.mu.Unlock()
		if planned["live_digest"] == nil || planned["live_error"] != nil {
			t.Fatalf("planned %v", planned)
		}
		if b, _ := json.Marshal(done); strings.Contains(string(b), "shipped") {
			t.Fatalf("the server got the tool's output: %s", b)
		}
	}
}

func TestAnMCPCallTheServerRefusedIsItsToolResult(t *testing.T) {
	f := newFakeMCP(t, false)
	_, front, _ := mcpSetup(t, f, "denied")
	status, out := mcpCall(t, front.URL, `{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"orders.lookup",
		"arguments":{}}}`, nil)
	result, _ := out["result"].(map[string]any)
	if status != 200 || result["isError"] != true || len(f.calls) != 0 {
		t.Fatalf("%d %v, upstream calls %d", status, out, len(f.calls))
	}
	// a modern request whose headers do not match its body
	status, out = mcpCall(t, front.URL, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"orders.lookup",
		"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`, map[string]string{
		"MCP-Protocol-Version": mcpModern, "Mcp-Method": "tools/call", "Mcp-Name": "other"})
	if status != 400 || out["error"].(map[string]any)["code"] != float64(headerMismatch) {
		t.Fatalf("%d %v", status, out)
	}
}

func TestTheProxySyncsTheServersItServes(t *testing.T) {
	f := newFakeMCP(t, true)
	fake, front, _ := mcpSetup(t, f, "allowed")
	p := front.Config.Handler.(*Proxy)
	p.syncMCP(context.Background())
	fake.mu.Lock()
	got := fake.mcpSyncs[len(fake.mcpSyncs)-1]
	fake.mu.Unlock()
	tools, _ := got["tools"].([]any)
	if got["server_id"] != float64(11) || len(tools) != 1 || got["detected_version"] != "2025-06-18" || got["error"] != nil {
		t.Fatalf("reported %v", got)
	}
	// without its credential: an error is reported, nothing reaches the MCP server
	p.mu.Lock()
	p.creds = map[credKey]openedCredential{}
	p.mu.Unlock()
	p.credMu.Lock()
	p.lastMiss = map[credKey]time.Time{{"mcp_server", "11"}: p.now()}
	p.credMu.Unlock()
	p.syncMCP(context.Background())
	fake.mu.Lock()
	defer fake.mu.Unlock()
	missing := false
	for _, r := range fake.mcpSyncs {
		if e, _ := r["error"].(string); strings.HasPrefix(e, "proxy.sealed_credential_missing") {
			missing = true
		}
	}
	if !missing {
		t.Fatalf("reported %v", fake.mcpSyncs)
	}
}
