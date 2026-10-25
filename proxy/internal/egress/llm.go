// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

// LLM calls through the proxy (backend/app/services/gateway_service.py and
// gateway_adapters.py; act.go). An agent points its OpenAI client at
// http://<proxy>/_llm/v1 with its own key; the proxy sends the server only
// what the LLM gateway records - the model, the messages' count and hash, the
// requested max_tokens - and the server decides as its gateway does (rights,
// policies, routes, connections, providers allowed, self-hosted only, the rate
// limit, the kill switch). The proxy then calls the provider with the
// connection's key sealed to it and answers in the OpenAI shape. The messages
// and the answer never reach the server.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
	"github.com/kironovlaziz-del/provenza/proxy/internal/policy"
)

var defaultBase = map[string]string{
	"openai":    "https://api.openai.com/v1",
	"groq":      "https://api.groq.com/openai/v1",
	"anthropic": "https://api.anthropic.com/v1",
}

// gatewayError answers in the OpenAI error shape.
func gatewayError(w http.ResponseWriter, status int, code, message, kind string) {
	w.Header().Set("X-Provenza-Refused", "1")
	writeJSON(w, status, map[string]any{"error": map[string]any{"message": message, "type": kind, "code": code}})
}

func (p *Proxy) serveLLM(w http.ResponseWriter, r *http.Request) {
	switch r.URL.EscapedPath() {
	case "/_llm/v1/models":
		p.llmModels(w, r)
	case "/_llm/v1/chat/completions":
		p.llmChat(w, r)
	default:
		gatewayError(w, http.StatusNotFound, "not_found", "Only /v1/chat/completions and /v1/models are served.",
			"invalid_request_error")
	}
}

func agentKeyOf(r *http.Request) string {
	if k := r.Header.Get("X-Agent-Key"); k != "" {
		return k
	}
	if b, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return strings.TrimSpace(b)
	}
	return ""
}

// llmModels: the gateway's model list for the agent, from the server.
func (p *Proxy) llmModels(w http.ResponseWriter, r *http.Request) {
	key := agentKeyOf(r)
	if key == "" {
		gatewayError(w, http.StatusUnauthorized, "agent_key_required", "Send the agent's key.", "invalid_request_error")
		return
	}
	raw, err := p.srv.callRaw(r.Context(), http.MethodGet, "/gateway/v1/models", nil, map[string]string{"X-Agent-Key": key})
	if err != nil {
		p.serverFailure(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

// asSent: the messages as the client wrote them, fields it set to null left
// out - what the gateway hashes (gateway_service._as_sent).
func asSent(messages []any) []any {
	out := make([]any, 0, len(messages))
	for _, m := range messages {
		msg, _ := m.(map[string]any)
		c := map[string]any{}
		for k, v := range msg {
			if v != nil {
				c[k] = v
			}
		}
		out = append(out, c)
	}
	return out
}

func (p *Proxy) llmChat(w http.ResponseWriter, r *http.Request) {
	key, raw, ok := readAgentRequest(w, r)
	if !ok {
		return
	}
	parsed, _ := canon.Parse(raw)
	body, _ := parsed.(map[string]any)
	model, _ := body["model"].(string)
	messages, _ := body["messages"].([]any)
	if model == "" || len(model) > 200 || len(messages) == 0 || len(messages) > 500 {
		gatewayError(w, http.StatusBadRequest, "invalid_request", "model and 1-500 messages are required.",
			"invalid_request_error")
		return
	}
	for _, m := range messages {
		msg, _ := m.(map[string]any)
		role, _ := msg["role"].(string)
		switch role {
		case "system", "developer", "user", "assistant", "tool", "function":
		default:
			gatewayError(w, http.StatusBadRequest, "invalid_request", "every message needs a valid role.",
				"invalid_request_error")
			return
		}
	}
	sha, err := canon.SHA256(asSent(messages))
	if err != nil {
		gatewayError(w, http.StatusBadRequest, "invalid_request", "the messages cannot be hashed.", "invalid_request_error")
		return
	}
	meta := map[string]any{"model": model, "messages": len(messages), "messages_sha256": sha,
		"stream": body["stream"] == true}
	for _, k := range []string{"max_tokens", "max_completion_tokens"} {
		if n, ok := body[k].(json.Number); ok {
			if _, has := meta["max_tokens"]; !has {
				meta["max_tokens"] = n
			}
		}
	}
	if c := r.Header.Get("X-Provenza-Chain-Id"); c != "" {
		n, err := strconv.ParseInt(c, 10, 64)
		if err != nil || n < 1 || n > 1<<31-1 {
			gatewayError(w, http.StatusBadRequest, "invalid_chain_id", "X-Provenza-Chain-Id must be a positive integer.",
				"invalid_request_error")
			return
		}
		meta["chain_id"] = n
	}
	metaRaw, _ := json.Marshal(meta)
	ctx := r.Context()
	plan, err := p.srv.plan(ctx, "llm", key, metaRaw)
	if err != nil {
		p.serverFailure(w, err)
		return
	}
	if plan["decision"] != policy.Allowed {
		status, _ := strconv.Atoi(fmt.Sprint(plan["status"]))
		if status < 400 {
			status = http.StatusForbidden
		}
		w.Header().Set("X-Provenza-Refused", "1")
		writeJSON(w, status, map[string]any{"error": plan["error"]})
		return
	}
	chk := checkOf(plan)
	a := &action{plan: plan, check: chk, started: time.Now(), fields: map[string]any{"check_id": chk.CheckID,
		"agent_id": chk.AgentID, "chain_id": chk.ChainID, "action_type": "model_call", "tool_name": chk.Tool,
		"input_sha256": chk.InputSHA, "agent_signature": "not_presented", "policy": nil}}
	markSigned(ctx, a.fields, chk)
	input, _ := plan["input"].(map[string]any)
	if input["messages_sha256"] != sha || input["model"] != model || "llm."+model != chk.Tool {
		p.refuseAction(w, ctx, a, policy.Denied, "the planned call is not this request")
		return
	}
	if !p.judged(w, ctx, a, input) {
		return
	}
	prov, _ := plan["provider"].(map[string]any)
	ptype, _ := prov["type"].(string)
	base, _ := prov["base_url"].(string)
	if p.enf.enforcing() && !p.signedConnection(prov, model, plan) {
		p.refuseAction(w, ctx, a, policy.Denied, "the AI connection or its route is not in the signed policy as configured")
		return
	}
	if base == "" {
		base = defaultBase[ptype]
	}
	if base == "" {
		id := p.done(ctx, a, map[string]any{"provider_error": "the connection has no base_url"})
		gatewayError(w, http.StatusBadGateway, "provider_error", fmt.Sprintf("The connection needs a base_url (action #%d).", id),
			"api_error")
		return
	}
	cred, _ := plan["credential"].(map[string]any)
	_, apiKey, ok := p.credentialFor(ctx, cred, base)
	if !ok {
		id := p.done(ctx, a, map[string]any{"provider_error": "the connection's key is not sealed to this proxy for its address"})
		gatewayError(w, http.StatusBadGateway, "provider_error",
			fmt.Sprintf("The connection's key is not sealed to this proxy for its address (action #%d).", id), "api_error")
		return
	}
	params := map[string]any{"max_tokens": plan["max_tokens"]}
	for _, k := range []string{"temperature", "top_p", "stop"} {
		if v, ok := body[k]; ok && v != nil {
			params[k] = v
		}
	}
	upstreamModel, _ := plan["upstream_model"].(string)
	client := p.upstream
	if plan["self_hosted_only"] == true {
		client = p.internalOnly()
	}
	text, finish, usage, err := chatCall(ctx, client, ptype, apiKey, base, upstreamModel, messages, params)
	if err != nil {
		msg := err.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
		p.done(ctx, a, map[string]any{"provider_error": msg})
		gatewayError(w, http.StatusBadGateway, "provider_error", msg, "api_error")
		return
	}
	respSHA, _ := canon.SHA256(map[string]any{"content": text})
	output := map[string]any{"finish_reason": finish, "prompt_tokens": usage["prompt_tokens"],
		"completion_tokens": usage["completion_tokens"], "response_sha256": respSHA}
	actionID := p.done(ctx, a, output)
	var total any
	if pt, ok := usage["prompt_tokens"].(int64); ok {
		ct, _ := usage["completion_tokens"].(int64)
		total = pt + ct
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": fmt.Sprintf("chatcmpl-pvz-a%d", actionID), "object": "chat.completion", "created": time.Now().Unix(),
		"model":   model,
		"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": text}, "finish_reason": finish}},
		"usage": map[string]any{"prompt_tokens": usage["prompt_tokens"], "completion_tokens": usage["completion_tokens"],
			"total_tokens": total},
		"provenza": map[string]any{"action_id": actionID, "via": "egress_proxy"},
	})
}

// signedConnection: the route of the model and its connection as the signed
// policy states them (a release signed before connections were in the bundle
// states only the route).
func (p *Proxy) signedConnection(prov map[string]any, model string, plan map[string]any) bool {
	rel := p.enf.current()
	if rel == nil {
		return false
	}
	id := fmt.Sprint(prov["id"])
	gw, _ := rel.Bundle["gateway"].(map[string]any)
	routes, _ := gw["routes"].(map[string]any)
	routed := false
	for _, v := range routes {
		r, _ := v.(map[string]any)
		up := r["upstream_model"]
		if up == nil {
			up = model
		}
		if r["enabled"] == true && fmt.Sprint(r["provider_id"]) == id && up == plan["upstream_model"] {
			routed = true
		}
	}
	if !routed {
		return false
	}
	providers, has := rel.Bundle["ai_providers"].(map[string]any)
	if !has {
		return true
	}
	signed, _ := providers[id].(map[string]any)
	return signed != nil && signed["type"] == prov["type"] && signed["base_url"] == prov["base_url"] &&
		signed["status"] == "active"
}

// internalOnly: a client that reaches only non-global addresses - the
// organization allows self-hosted AI providers only.
func (p *Proxy) internalOnly() *http.Client {
	d := &net.Dialer{Timeout: 30 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil || !internalIP(ip) {
			return errors.New("the organization allows only self-hosted AI providers: this address is public")
		}
		return nil
	}}
	tr := &http.Transport{DialContext: d.DialContext, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 10 * time.Second}
	return &http.Client{Transport: tr, Timeout: p.upstream.Timeout, CheckRedirect: p.upstream.CheckRedirect}
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func internalIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || cgnat.Contains(ip)
}

func textOf(content any) string {
	switch c := content.(type) {
	case nil:
		return ""
	case string:
		return c
	case []any:
		var b strings.Builder
		for _, part := range c {
			m, _ := part.(map[string]any)
			if m == nil {
				continue
			}
			if t, ok := m["type"]; ok && t != "text" {
				continue
			}
			if s, ok := m["text"].(string); ok {
				b.WriteString(s)
			}
		}
		return b.String()
	}
	s, _ := canon.Text(content)
	return s
}

func postJSON(ctx context.Context, client *http.Client, url string, headers map[string]string, body any) (map[string]any, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("Network error calling provider: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Network error calling provider: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("Provider returned %s", errorDetail(resp.StatusCode, data))
	}
	v, err := canon.Parse(data)
	m, _ := v.(map[string]any)
	if err != nil || m == nil {
		return nil, errors.New("Provider returned a non-JSON response.")
	}
	return m, nil
}

func tokens(v any) any {
	if n, ok := v.(json.Number); ok {
		if i, err := n.Int64(); err == nil {
			return i
		}
	}
	return nil
}

// chatCall: gateway_adapters.chat - OpenAI-compatible, Anthropic Messages, or a custom endpoint.
func chatCall(ctx context.Context, client *http.Client, ptype, apiKey, base, model string, messages []any,
	params map[string]any) (string, string, map[string]any, error) {
	usage := map[string]any{"prompt_tokens": nil, "completion_tokens": nil}
	base = strings.TrimRight(base, "/")
	switch ptype {
	case "openai", "groq", "azure_openai":
		headers := map[string]string{}
		if apiKey != "" {
			if ptype == "azure_openai" {
				headers["api-key"] = apiKey
			} else {
				headers["Authorization"] = "Bearer " + apiKey
			}
		}
		msgs := make([]any, 0, len(messages))
		for _, m := range messages {
			src, _ := m.(map[string]any)
			c := map[string]any{}
			for _, k := range []string{"role", "content", "name", "tool_call_id"} {
				if v, ok := src[k]; ok && v != nil {
					c[k] = v
				}
			}
			msgs = append(msgs, c)
		}
		body := map[string]any{"model": model, "messages": msgs}
		for k, v := range params {
			body[k] = v
		}
		data, err := postJSON(ctx, client, base+"/chat/completions", headers, body)
		if err != nil {
			return "", "", usage, err
		}
		choices, _ := data["choices"].([]any)
		if len(choices) == 0 {
			return "", "", usage, errors.New("Unexpected response shape from provider.")
		}
		choice, _ := choices[0].(map[string]any)
		msg, _ := choice["message"].(map[string]any)
		if msg == nil {
			return "", "", usage, errors.New("Unexpected response shape from provider.")
		}
		finish, _ := choice["finish_reason"].(string)
		if finish == "" {
			finish = "stop"
		}
		u, _ := data["usage"].(map[string]any)
		usage["prompt_tokens"], usage["completion_tokens"] = tokens(u["prompt_tokens"]), tokens(u["completion_tokens"])
		return textOf(msg["content"]), finish, usage, nil
	case "anthropic":
		var system []string
		var conv []map[string]any
		for _, m := range messages {
			src, _ := m.(map[string]any)
			role, _ := src["role"].(string)
			if role == "system" || role == "developer" {
				system = append(system, textOf(src["content"]))
				continue
			}
			r := "user"
			if role == "assistant" {
				r = "assistant"
			}
			text := textOf(src["content"])
			if role == "tool" || role == "function" {
				text = "[tool output]\n" + text
			}
			if n := len(conv); n > 0 && conv[n-1]["role"] == r {
				conv[n-1]["content"] = conv[n-1]["content"].(string) + "\n\n" + text
			} else {
				conv = append(conv, map[string]any{"role": r, "content": text})
			}
		}
		maxTokens := params["max_tokens"]
		if maxTokens == nil {
			maxTokens = 1024
		}
		body := map[string]any{"model": model, "messages": conv, "max_tokens": maxTokens}
		if len(system) > 0 {
			body["system"] = strings.Join(system, "\n\n")
		}
		if stop, ok := params["stop"]; ok {
			if s, isStr := stop.(string); isStr {
				body["stop_sequences"] = []any{s}
			} else {
				body["stop_sequences"] = stop
			}
		}
		for _, k := range []string{"temperature", "top_p"} {
			if v, ok := params[k]; ok {
				body[k] = v
			}
		}
		headers := map[string]string{"anthropic-version": "2023-06-01"}
		if apiKey != "" {
			headers["x-api-key"] = apiKey
		}
		data, err := postJSON(ctx, client, base+"/messages", headers, body)
		if err != nil {
			return "", "", usage, err
		}
		var b strings.Builder
		parts, _ := data["content"].([]any)
		for _, part := range parts {
			m, _ := part.(map[string]any)
			if s, ok := m["text"].(string); ok {
				b.WriteString(s)
			}
		}
		finish := map[string]string{"end_turn": "stop", "max_tokens": "length", "stop_sequence": "stop"}[fmt.Sprint(data["stop_reason"])]
		if finish == "" {
			finish = "stop"
		}
		u, _ := data["usage"].(map[string]any)
		usage["prompt_tokens"], usage["completion_tokens"] = tokens(u["input_tokens"]), tokens(u["output_tokens"])
		return b.String(), finish, usage, nil
	}
	// custom: {"prompt", "messages", "model", ...} -> {"response"|"text"}
	var lines []string
	for _, m := range messages {
		src, _ := m.(map[string]any)
		lines = append(lines, fmt.Sprintf("%v: %s", src["role"], textOf(src["content"])))
	}
	body := map[string]any{"prompt": strings.Join(lines, "\n\n"), "messages": messages, "model": model}
	for k, v := range params {
		body[k] = v
	}
	headers := map[string]string{}
	if apiKey != "" {
		headers["Authorization"] = "Bearer " + apiKey
	}
	data, err := postJSON(ctx, client, base, headers, body)
	if err != nil {
		return "", "", usage, err
	}
	for _, k := range []string{"response", "text"} {
		if v, ok := data[k]; ok {
			if s, isStr := v.(string); isStr {
				return s, "stop", usage, nil
			}
			s, _ := canon.Text(v)
			return s, "stop", usage, nil
		}
	}
	s, _ := canon.Text(data)
	return s, "stop", usage, nil
}
