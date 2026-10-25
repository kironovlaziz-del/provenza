// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

// The server's HTTP tool gateway and this proxy build the same request
// (sdk/testdata/trust-vectors.json "http_tools", from backend/app/pvp/http_tools.py).
func TestToolRequestsAreBuiltAsTheServerBuildsThem(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "sdk", "testdata", "trust-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := canon.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := doc.(map[string]any)["http_tools"].([]any)
	if len(list) == 0 {
		t.Fatal("no http_tools vectors")
	}
	for i, v := range list {
		c := v.(map[string]any)
		def := c["definition"].(map[string]any)
		args := c["arguments"].(map[string]any)
		if d, err := manifestDigest(def); err != nil || d != c["digest"] {
			t.Fatalf("#%d digest %s, want %s (%v)", i, d, c["digest"], err)
		}
		problems := argumentProblems(def["input_schema"], args, def["url"].(string))
		if refused := c["refused"] == true; refused != (len(problems) > 0) {
			t.Fatalf("#%d refused %v, problems %v", i, refused, problems)
		}
		if len(problems) > 0 {
			continue
		}
		target, body, err := buildRequest(def["method"].(string), def["url"].(string), args)
		if err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		u, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		if u.EscapedPath() != c["path"] {
			t.Fatalf("#%d path %s, want %s", i, u.EscapedPath(), c["path"])
		}
		var got [][2]string
		for k, vs := range u.Query() {
			for _, v := range vs {
				got = append(got, [2]string{k, v})
			}
		}
		sort.Slice(got, func(a, b int) bool { return got[a][0]+"\x00"+got[a][1] < got[b][0]+"\x00"+got[b][1] })
		var want [][2]string
		for _, p := range c["query"].([]any) {
			pair := p.([]any)
			want = append(want, [2]string{pair[0].(string), pair[1].(string)})
		}
		if len(got) != len(want) {
			t.Fatalf("#%d query %v, want %v", i, got, want)
		}
		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("#%d query %v, want %v", i, got, want)
			}
		}
		if c["body"] == nil {
			if body != nil {
				t.Fatalf("#%d body %s, want none", i, body)
			}
			continue
		}
		parsed, err := canon.Parse(body)
		if err != nil || !sameJSON(parsed, c["body"]) {
			t.Fatalf("#%d body %s, want %v (%v)", i, body, c["body"], err)
		}
	}
}

func toolPlan(up *upstream, f *fakeProvenza, decision string) func(map[string]any) map[string]any {
	return func(body map[string]any) map[string]any {
		if decision != "allowed" {
			return map[string]any{"decision": decision, "reason": "no", "action_id": 9}
		}
		def := map[string]any{"name": "crm.set_tier", "method": "PATCH", "url": up.srv.URL + "/customers/{id}",
			"input_schema": map[string]any{"type": "object", "required": []any{"id"}}, "description": "Set a tier"}
		parsed, _ := canon.Of(def)
		digest, _ := manifestDigest(parsed)
		args, _ := canon.Of(body["input"])
		sha, _ := canon.SHA256(args)
		return map[string]any{"decision": "allowed", "reason": "ok", "check_id": "chk_tool_" + strings.Repeat("x", 12),
			"agent_id": 5, "chain_id": nil, "action_type": "tool_call", "tool_name": "crm.set_tier",
			"input_sha256": sha, "approval": nil, "arguments": body["input"], "definition": def, "digest": digest,
			"permit": "permit.token", "timeout_seconds": 5, "max_response_bytes": 1000,
			"credential": map[string]any{"object": "http_tool", "id": 4, "source": "sealed", "header": "Authorization"}}
	}
}

func callTool(t *testing.T, front string, body string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("POST", front+"/_tools/call", strings.NewReader(body))
	req.Header.Set("X-Agent-Key", agentKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%d %s", resp.StatusCode, raw)
	}
	return out
}

func TestAnHTTPToolIsCalledThroughTheProxyWithItsSealedCredential(t *testing.T) {
	up := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"customer":{"tier":"gold"}}`)
	})
	fake, _, front := setup(t, up, nil)
	fake.mu.Lock()
	fake.plans = map[string]func(map[string]any) map[string]any{"http-tools": toolPlan(up, fake, "allowed")}
	fake.sealed = []sealedObject{{object: "http_tool", id: 4, upstream: origin(up.srv.URL), value: "Bearer crm"}}
	fake.mu.Unlock()

	out := callTool(t, front.URL, `{"agent_id":5,"tool_name":"crm.set_tier","input":{"id":"c/42","tier":"gold"},
		"nonce":"n0123456789abcdef","issued_at":1,"signature":"sig"}`)
	if out["decision"] != "allowed" || out["status"] != float64(200) {
		t.Fatalf("answer %v", out)
	}
	if b, _ := json.Marshal(out["body"]); string(b) != `{"customer":{"tier":"gold"}}` {
		t.Fatalf("body %s", b)
	}
	got := up.got[len(up.got)-1]
	if got.Method != "PATCH" || got.URL.EscapedPath() != "/customers/c%2F42" || got.Header.Get("Authorization") != "Bearer crm" ||
		got.Header.Get("Provenza-Permit") != "permit.token" || got.Header.Get("X-Agent-Key") != "" {
		t.Fatalf("upstream %s %s %v", got.Method, got.URL, got.Header)
	}
	var sent map[string]any
	_ = json.Unmarshal([]byte(up.body[len(up.body)-1]), &sent)
	if sent["id"] != "c/42" || sent["tier"] != "gold" {
		t.Fatalf("sent %v", sent)
	}
	// recorded: metadata only, with the proxy's receipt for exactly this action
	fake.mu.Lock()
	done := fake.completed[len(fake.completed)-1]
	fake.mu.Unlock()
	output := done["output"].(map[string]any)
	if output["status"] != float64(200) || output["response_bytes"] != float64(28) || done["receipt"] == nil {
		t.Fatalf("completed %v", done)
	}
	st := done["receipt"].(map[string]any)["statement"].(map[string]any)
	if st["action_type"] != "tool_call" || st["tool_name"] != "crm.set_tier" || st["decision"] != "allowed" {
		t.Fatalf("receipt %v", st)
	}
	if fake.planned[len(fake.planned)-1]["tool_name"] != "crm.set_tier" {
		t.Fatalf("planned %v", fake.planned)
	}
}

func TestAToolPlanTheServerRefusedIsAnsweredAsTheGatewayAnswers(t *testing.T) {
	up := newUpstream(t, ok)
	fake, _, front := setup(t, up, nil)
	fake.mu.Lock()
	fake.plans = map[string]func(map[string]any) map[string]any{"http-tools": toolPlan(up, fake, "denied")}
	fake.mu.Unlock()
	out := callTool(t, front.URL, `{"agent_id":5,"tool_name":"crm.set_tier","input":{"id":1},"nonce":"n0123456789abcdef",
		"issued_at":1,"signature":"s"}`)
	if out["decision"] != "denied" || out["action_id"] != float64(9) || len(up.got) != 0 {
		t.Fatalf("answer %v, upstream calls %d", out, len(up.got))
	}
}

func TestAToolDefinitionThatIsNotThePinnedOneIsNotSent(t *testing.T) {
	up := newUpstream(t, ok)
	fake, _, front := setup(t, up, nil)
	plan := toolPlan(up, fake, "allowed")
	fake.mu.Lock()
	fake.plans = map[string]func(map[string]any) map[string]any{"http-tools": func(b map[string]any) map[string]any {
		m := plan(b)
		m["definition"].(map[string]any)["url"] = "https://elsewhere.example/{id}" // the digest no longer holds
		return m
	}}
	fake.mu.Unlock()
	out := callTool(t, front.URL, `{"agent_id":5,"tool_name":"crm.set_tier","input":{"id":1},"nonce":"n0123456789abcdef",
		"issued_at":1,"signature":"s"}`)
	fake.mu.Lock()
	done := fake.completed[len(fake.completed)-1]
	fake.mu.Unlock()
	if out["decision"] != "denied" || len(up.got) != 0 || done["enforcement"] == nil {
		t.Fatalf("answer %v, upstream %d, completed %v", out, len(up.got), done)
	}
}
