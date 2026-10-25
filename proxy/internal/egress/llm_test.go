// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
)

// The messages' hash is the one the server's LLM gateway records.
func TestMessagesAreHashedAsTheGatewayHashesThem(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "sdk", "testdata", "trust-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := canon.Parse(raw)
	list, _ := doc.(map[string]any)["llm_messages"].([]any)
	if len(list) == 0 {
		t.Fatal("no llm_messages vectors")
	}
	for i, v := range list {
		c := v.(map[string]any)
		got, err := canon.SHA256(asSent(c["messages"].([]any)))
		if err != nil || got != c["messages_sha256"] {
			t.Fatalf("#%d %s, want %s (%v)", i, got, c["messages_sha256"], err)
		}
	}
}

func llmPlan(up *upstream, ptype string) func(map[string]any) map[string]any {
	return func(meta map[string]any) map[string]any {
		model := meta["model"].(string)
		if model == "nope" {
			return map[string]any{"decision": "refused", "status": 403, "error": map[string]any{
				"message": "Model 'nope' is not allowed (action #3)", "type": "permission_error", "code": "model_not_allowed"}}
		}
		input := map[string]any{"model": model, "provider": "fake", "messages": meta["messages"],
			"messages_sha256": meta["messages_sha256"], "max_tokens": 64}
		parsed, _ := canon.Of(input)
		sha, _ := canon.SHA256(parsed)
		return map[string]any{"decision": "allowed", "check_id": "chk_llm_" + strings.Repeat("y", 12), "agent_id": 5,
			"chain_id": nil, "action_type": "model_call", "tool_name": "llm." + model, "input_sha256": sha,
			"approval": nil, "input": input, "model": model, "upstream_model": "real-" + model, "max_tokens": 64,
			"self_hosted_only": false,
			"provider":         map[string]any{"id": 8, "type": ptype, "base_url": up.srv.URL + "/v1", "name": "fake"},
			"credential":       map[string]any{"object": "provider", "id": 8, "source": "sealed", "header": "Authorization"}}
	}
}

func chat(t *testing.T, front string, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", front+"/_llm/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+agentKey)
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
	return resp.StatusCode, out
}

func TestAChatCompletionGoesToTheProviderWithTheSealedKeyAndOnlyMetadataToTheServer(t *testing.T) {
	for _, ptype := range []string{"openai", "anthropic"} {
		up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if strings.HasSuffix(r.URL.Path, "/messages") {
				_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"hi there"}],"stop_reason":"end_turn",
					"usage":{"input_tokens":5,"output_tokens":2}}`)
				return
			}
			_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"hi there"},"finish_reason":"stop"}],
				"usage":{"prompt_tokens":5,"completion_tokens":2}}`)
		})
		fake, _, front := setup(t, up, nil)
		fake.mu.Lock()
		fake.plans = map[string]func(map[string]any) map[string]any{"llm": llmPlan(up, ptype)}
		fake.sealed = []sealedObject{{object: "provider", id: 8, upstream: origin(up.srv.URL), value: "sk-sealed"}}
		fake.mu.Unlock()

		status, out := chat(t, front.URL, `{"model":"gpt-x","messages":[{"role":"system","content":"brief"},
			{"role":"user","content":"secret prompt"}],"max_tokens":100}`)
		if status != 200 {
			t.Fatalf("%s: %d %v", ptype, status, out)
		}
		msg := out["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)
		if msg["content"] != "hi there" || out["usage"].(map[string]any)["total_tokens"] != float64(7) {
			t.Fatalf("%s: answer %v", ptype, out)
		}
		got := up.got[len(up.got)-1]
		sent := up.body[len(up.body)-1]
		if ptype == "openai" && (got.URL.Path != "/v1/chat/completions" || got.Header.Get("Authorization") != "Bearer sk-sealed") {
			t.Fatalf("openai upstream %s %v", got.URL, got.Header)
		}
		if ptype == "anthropic" && (got.URL.Path != "/v1/messages" || got.Header.Get("X-Api-Key") != "sk-sealed" ||
			!strings.Contains(sent, `"system":"brief"`)) {
			t.Fatalf("anthropic upstream %s %v %s", got.URL, got.Header, sent)
		}
		if !strings.Contains(sent, `"model":"real-gpt-x"`) || !strings.Contains(sent, `"max_tokens":64`) {
			t.Fatalf("%s: sent %s", ptype, sent)
		}
		fake.mu.Lock()
		planned, _ := json.Marshal(fake.planned[len(fake.planned)-1])
		done := fake.completed[len(fake.completed)-1]
		fake.mu.Unlock()
		if strings.Contains(string(planned), "secret prompt") || strings.Contains(string(planned), "brief") {
			t.Fatalf("the server got content: %s", planned)
		}
		if o := done["output"].(map[string]any); o["finish_reason"] != "stop" || o["completion_tokens"] != float64(2) {
			t.Fatalf("%s: completed %v", ptype, done)
		}
		if b, _ := json.Marshal(done); strings.Contains(string(b), "hi there") {
			t.Fatalf("the server got the answer: %s", b)
		}
	}
}

func TestARefusedChatIsTheGatewaysOpenAIError(t *testing.T) {
	up := newUpstream(t, ok)
	fake, _, front := setup(t, up, nil)
	fake.mu.Lock()
	fake.plans = map[string]func(map[string]any) map[string]any{"llm": llmPlan(up, "openai")}
	fake.mu.Unlock()
	status, out := chat(t, front.URL, `{"model":"nope","messages":[{"role":"user","content":"x"}]}`)
	if status != 403 || out["error"].(map[string]any)["code"] != "model_not_allowed" || len(up.got) != 0 {
		t.Fatalf("%d %v", status, out)
	}
	status, out = chat(t, front.URL, `{"model":"","messages":[]}`)
	if status != 400 {
		t.Fatalf("%d %v", status, out)
	}
}

func TestTheKeyGoesOnlyToTheSealedProvider(t *testing.T) {
	up := newUpstream(t, ok)
	other := newUpstream(t, ok)
	fake, _, front := setup(t, up, nil)
	fake.mu.Lock()
	fake.plans = map[string]func(map[string]any) map[string]any{"llm": llmPlan(other, "openai")} // the server repointed it
	fake.sealed = []sealedObject{{object: "provider", id: 8, upstream: origin(up.srv.URL), value: "sk-sealed"}}
	fake.mu.Unlock()
	status, _ := chat(t, front.URL, `{"model":"gpt-x","messages":[{"role":"user","content":"x"}]}`)
	if status != http.StatusBadGateway || len(other.got) != 0 {
		t.Fatalf("%d, calls to the other host %d", status, len(other.got))
	}
}
