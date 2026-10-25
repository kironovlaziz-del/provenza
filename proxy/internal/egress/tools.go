// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

// HTTP tools through the proxy (backend/app/pvp/http_tools.py; act.go). The
// agent sends what it would send to /http-tools/call - its signed request
// for the tool - to /_tools/call. The server judges it as its HTTP tool
// gateway does and answers with the tool's pinned definition; the proxy
// checks that the definition is the pinned one (and, enforcing, the signed
// one), builds the request from it and the arguments itself - the server
// does not say where it goes - adds the credential sealed to it and records
// the call: status and response hash. The agent gets the gateway's answer.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
	"github.com/kironovlaziz-del/provenza/proxy/internal/policy"
)

var placeholderRe = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]{0,63})\}`)

var bodyMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true}

// manifestDigest: the server's manifest_digest (sorted keys, no whitespace,
// characters as they are).
func manifestDigest(v any) (string, error) {
	s, err := canon.UnicodeText(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:]), nil
}

func placeholders(rawURL string) []string {
	head, _, _ := strings.Cut(rawURL, "?")
	var out []string
	for _, m := range placeholderRe.FindAllStringSubmatch(head, -1) {
		out = append(out, m[1])
	}
	return out
}

func isInteger(v any) bool {
	n, ok := v.(json.Number)
	return ok && !strings.ContainsAny(string(n), ".eE")
}

func typeOK(v any, expected any) bool {
	var names []any
	if l, ok := expected.([]any); ok {
		names = l
	} else {
		names = []any{expected}
	}
	for _, n := range names {
		name, _ := n.(string)
		switch name {
		case "string":
			if _, ok := v.(string); ok {
				return true
			}
		case "integer":
			if isInteger(v) {
				return true
			}
		case "number":
			if _, ok := v.(json.Number); ok {
				return true
			}
		case "boolean":
			if _, ok := v.(bool); ok {
				return true
			}
		case "object":
			if _, ok := v.(map[string]any); ok {
				return true
			}
		case "array":
			if _, ok := v.([]any); ok {
				return true
			}
		case "null":
			if v == nil {
				return true
			}
		default:
			return true // a type this check does not know: not refused here
		}
	}
	return false
}

func sameJSON(a, b any) bool {
	x, err1 := canon.Text(a)
	y, err2 := canon.Text(b)
	if err1 != nil || err2 != nil {
		return false
	}
	if x == y {
		return true
	}
	n, ok1 := a.(json.Number)
	m, ok2 := b.(json.Number)
	if ok1 && ok2 {
		f, e1 := n.Float64()
		g, e2 := m.Float64()
		return e1 == nil && e2 == nil && f == g
	}
	return false
}

// argumentProblems: the server's argument_problems - the input schema's top
// level and the path placeholders.
func argumentProblems(schema any, args map[string]any, rawURL string) []string {
	var problems []string
	if s, ok := schema.(map[string]any); ok {
		props, _ := s["properties"].(map[string]any)
		if req, ok := s["required"].([]any); ok {
			for _, n := range req {
				name, _ := n.(string)
				if _, ok := args[name]; !ok {
					problems = append(problems, fmt.Sprintf("missing argument '%s'", name))
				}
			}
		}
		if s["additionalProperties"] == false {
			keys := make([]string, 0, len(args))
			for k := range args {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if _, ok := props[k]; !ok {
					problems = append(problems, fmt.Sprintf("unexpected argument '%s'", k))
				}
			}
		}
		for name, sub := range props {
			v, present := args[name]
			sm, _ := sub.(map[string]any)
			if !present || sm == nil {
				continue
			}
			if t, ok := sm["type"]; ok && !typeOK(v, t) {
				problems = append(problems, fmt.Sprintf("argument '%s' is not of type %v", name, t))
			}
			if enum, ok := sm["enum"].([]any); ok {
				found := false
				for _, e := range enum {
					if sameJSON(e, v) {
						found = true
						break
					}
				}
				if !found {
					problems = append(problems, fmt.Sprintf("argument '%s' is not one of the allowed values", name))
				}
			}
		}
	}
	for _, name := range placeholders(rawURL) {
		v := args[name]
		str, isStr := v.(string)
		if isStr && (str == "" || str == "." || str == "..") || (!isStr && !isInteger(v)) {
			problems = append(problems, fmt.Sprintf("path argument '%s' must be a non-empty string or an integer", name))
		}
	}
	return problems
}

// pyQuote: Python's urllib.parse.quote(s, safe=""): everything but A-Z a-z 0-9 _ . - ~ percent-encoded.
func pyQuote(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// scalarText: a query value as the server's client writes it.
func scalarText(v any) (string, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return "true", true
		}
		return "false", true
	case string:
		return x, true
	case json.Number:
		s, err := canon.Text(x)
		return s, err == nil
	}
	return "", false
}

// buildRequest: the server's build_request - the URL with each path
// placeholder as one encoded segment, the arguments as the JSON body (body
// methods) or the query (GET, DELETE).
func buildRequest(method, rawURL string, args map[string]any) (string, []byte, error) {
	used := map[string]bool{}
	for _, n := range placeholders(rawURL) {
		used[n] = true
	}
	head, tail, hasQuery := strings.Cut(rawURL, "?")
	var fail error
	head = placeholderRe.ReplaceAllStringFunc(head, func(m string) string {
		name := m[1 : len(m)-1]
		s, ok := scalarText(args[name])
		if !ok {
			fail = fmt.Errorf("path argument '%s' cannot be written", name)
		}
		return pyQuote(s)
	})
	if fail != nil {
		return "", nil, fail
	}
	target := head
	if hasQuery {
		target += "?" + tail
	}
	if bodyMethods[method] {
		text, err := canon.UnicodeText(any(args))
		return target, []byte(text), err
	}
	q := url.Values{}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if used[k] {
			continue
		}
		v := args[k]
		if s, ok := scalarText(v); ok {
			q.Add(k, s)
			continue
		}
		list, ok := v.([]any)
		if !ok {
			return "", nil, fmt.Errorf("argument '%s' cannot go in a query string", k)
		}
		for _, item := range list {
			s, ok := scalarText(item)
			if _, isBool := item.(bool); !ok || isBool {
				return "", nil, fmt.Errorf("argument '%s' cannot go in a query string", k)
			}
			q.Add(k, s)
		}
	}
	if len(q) > 0 {
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		target += sep + q.Encode()
	}
	return target, nil, nil
}

func (p *Proxy) serveTool(w http.ResponseWriter, r *http.Request) {
	key, body, ok := readAgentRequest(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	a := p.planned(w, r, "http-tools", key, body)
	if a == nil {
		return
	}
	def, _ := a.plan["definition"].(map[string]any)
	args, _ := a.plan["arguments"].(map[string]any)
	digest, _ := a.plan["digest"].(string)
	name, _ := def["name"].(string)
	method, _ := def["method"].(string)
	rawURL, _ := def["url"].(string)
	if got, err := manifestDigest(def); err != nil || got != digest || name != a.check.Tool || args == nil {
		p.refuseAction(w, ctx, a, policy.Denied, "the tool's definition is not the one pinned")
		return
	}
	a.check.ToolDigest = &digest // checked against the definition just above
	if !p.judged(w, ctx, a, args) {
		return
	}
	if p.enf.enforcing() {
		signed, ok := p.signedRow("http_tools", "name", name)
		if !ok || signed["digest"] != digest {
			p.refuseAction(w, ctx, a, policy.Denied, "HTTP tool '"+name+"' is not in the signed policy as pinned")
			return
		}
	}
	if problems := argumentProblems(def["input_schema"], args, rawURL); len(problems) > 0 {
		p.refuseAction(w, ctx, a, policy.Denied, "arguments refused: "+strings.Join(problems, "; "))
		return
	}
	target, payload, err := buildRequest(method, rawURL, args)
	if err != nil {
		p.refuseAction(w, ctx, a, policy.Denied, "arguments refused: "+err.Error())
		return
	}
	cred, _ := a.plan["credential"].(map[string]any)
	header, value, ok := p.credentialFor(ctx, cred, target)
	if !ok {
		id := p.done(ctx, a, map[string]any{"status": 0, "error": "proxy.sealed_credential_missing"})
		writeJSON(w, http.StatusOK, map[string]any{"decision": policy.Allowed, "action_id": id,
			"error": "the tool's credential is not sealed to this proxy for its address"})
		return
	}
	out, status := p.sendTool(ctx, a, method, target, payload, header, value)
	out["action_id"] = p.done(ctx, a, status)
	writeJSON(w, http.StatusOK, out)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func number(v any, def int64) int64 {
	if n, err := strconv.ParseInt(fmt.Sprint(v), 10, 64); err == nil && n > 0 {
		return n
	}
	return def
}

// sendTool sends the call: the agent's answer, and what is recorded (metadata).
func (p *Proxy) sendTool(ctx context.Context, a *action, method, target string, payload []byte, header,
	value string) (map[string]any, map[string]any) {
	answer := map[string]any{"decision": policy.Allowed, "reason": a.check.Reason}
	timeout := time.Duration(number(a.plan["timeout_seconds"], 30)) * time.Second
	limit := number(a.plan["max_response_bytes"], 1<<20)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(cctx, method, target, reader)
	if err != nil {
		answer["error"] = "bad request URL"
		return answer, map[string]any{"status": 0, "error": "proxy.bad_upstream_url"}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "provenza-egress-proxy")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		if permit, _ := a.plan["permit"].(string); permit != "" {
			req.Header.Set("Provenza-Permit", permit)
		}
	}
	if header != "" && value != "" {
		req.Header.Set(header, value)
	}
	resp, err := p.upstream.Do(req)
	if err != nil {
		answer["error"] = "the tool could not be reached"
		return answer, map[string]any{"status": 0, "error": "upstream.unreachable"}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	sum := sha256.Sum256(raw)
	status := map[string]any{"status": resp.StatusCode, "response_sha256": hex.EncodeToString(sum[:]),
		"response_bytes": len(raw)}
	answer["status"] = resp.StatusCode
	switch {
	case int64(len(raw)) > limit:
		answer["withheld"] = []string{"response_too_large"}
		status["error"] = "proxy.response_too_large"
		delete(status, "response_sha256")
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		answer["error"] = fmt.Sprintf("HTTP %d (redirects are not followed)", resp.StatusCode)
	case resp.StatusCode >= 400:
		answer["error"] = errorDetail(resp.StatusCode, raw)
	case len(raw) == 0:
		answer["body"] = nil
	case strings.Contains(resp.Header.Get("Content-Type"), "json"):
		if json.Valid(raw) {
			answer["body"] = json.RawMessage(raw)
		} else {
			answer["withheld"] = []string{"invalid_json"}
		}
	case utf8.Valid(raw):
		answer["body"] = map[string]any{"text": string(raw)}
	default:
		answer["withheld"] = []string{"binary_response"}
	}
	return answer, status
}

// errorDetail: the JSON error message of a refused call, never the raw page.
func errorDetail(code int, raw []byte) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) == nil {
		for _, k := range []string{"detail", "message", "error"} {
			switch v := m[k].(type) {
			case string:
				return fmt.Sprintf("HTTP %d: %.300s", code, v)
			case map[string]any:
				if s, ok := v["message"].(string); ok {
					return fmt.Sprintf("HTTP %d: %.300s", code, s)
				}
			}
		}
	}
	return fmt.Sprintf("HTTP %d", code)
}
