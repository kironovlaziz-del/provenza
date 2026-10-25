// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

// MCP through the proxy (backend/app/pvp/mcp_gateway.py, mcp_client.py;
// act.go). An MCP server whose credential is sealed to the proxies is
// reachable only from them, so the proxy does for it what the server's MCP
// gateway does for the others:
//
//   - it syncs the server's tools (every refresh) and reports them
//     (POST /egress-proxy/mcp/sync): new tools wait for an administrator's
//     approval, a changed one drifts - exactly as an admin's sync;
//   - agents connect their MCP client to http://<proxy>/_mcp. Everything is
//     relayed to the server's MCP endpoint (it lists the approved tools),
//     except tools/call for such a server: the proxy fetches the live
//     definition itself, has the server decide (POST /egress-proxy/mcp/plan),
//     calls the tool with the credential and records the call (metadata).
//
// Streamable HTTP, both protocol eras (2026-07-28 stateless; the
// initialize-based 2025 revisions with sessions), JSON or SSE answers.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
	"github.com/kironovlaziz-del/provenza/proxy/internal/policy"
)

const (
	mcpModern       = "2026-07-28"
	mcpMaxTools     = 1000
	mcpMaxPages     = 20
	mcpMaxResponse  = 8 << 20
	mcpLiveTTL      = 60 * time.Second
	mcpSessionTTL   = 300 * time.Second
	metaVersion     = "io.modelcontextprotocol/protocolVersion"
	chainMeta       = "provenza/chain_id"
	headerMismatch  = -32020
	unsupportedVers = -32022
)

var (
	mcpLegacy      = []string{"2025-11-25", "2025-06-18", "2025-03-26"}
	mcpClientInfo  = map[string]any{"name": "provenza-egress-proxy", "version": "1"}
	definitionKeys = []string{"name", "title", "description", "inputSchema", "outputSchema", "annotations"}
	toolNameRe     = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	headerSafeRe   = regexp.MustCompile(`^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$`)
	headerTokenRe  = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+$`)
	mcpIDs         atomic.Int64
)

// MCPServer: one the server's configuration says this proxy serves.
type MCPServer struct {
	ID               json.Number `json:"id"`
	Slug             string      `json:"slug"`
	URL              string      `json:"url"`
	Protocol         string      `json:"protocol"`
	AuthHeader       string      `json:"auth_header"`
	CredentialSource string      `json:"credential_source"`
	TimeoutSeconds   int64       `json:"timeout_seconds"`
}

func isLegacy(v string) bool {
	for _, l := range mcpLegacy {
		if l == v {
			return true
		}
	}
	return false
}

// definitionOf: what an agent's model reads about a tool - all of it is pinned.
func definitionOf(tool map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range definitionKeys {
		if v, ok := tool[k]; ok {
			out[k] = v
		}
	}
	return out
}

func mcpHeaderValue(v any) string {
	var text string
	switch x := v.(type) {
	case bool:
		text = "false"
		if x {
			text = "true"
		}
	case string:
		text = x
	default:
		text, _ = canon.Text(v)
	}
	if headerSafeRe.MatchString(text) && !(strings.HasPrefix(text, "=?base64?") && strings.HasSuffix(text, "?=")) {
		return text
	}
	return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(text)) + "?="
}

// paramHeaders: Mcp-Param-* for properties marked x-mcp-header (mcp_client.param_headers).
func paramHeaders(schema any, args any, out map[string]string) {
	s, _ := schema.(map[string]any)
	v, _ := args.(map[string]any)
	if s == nil || v == nil {
		return
	}
	props, _ := s["properties"].(map[string]any)
	for key, sub := range props {
		sm, _ := sub.(map[string]any)
		val, present := v[key]
		if sm == nil || !present {
			continue
		}
		if name, ok := sm["x-mcp-header"].(string); ok && headerTokenRe.MatchString(name) && val != nil {
			switch val.(type) {
			case string, bool:
				out["Mcp-Param-"+name] = mcpHeaderValue(val)
			case json.Number:
				if isInteger(val) {
					out["Mcp-Param-"+name] = mcpHeaderValue(val)
				}
			}
		}
		paramHeaders(sub, val, out)
	}
}

type mcpSession struct {
	id, version string
	expires     time.Time
}

// mcpUpstream speaks to one MCP server with its credential.
type mcpUpstream struct {
	client      *http.Client
	url         string
	protocol    string
	auth        map[string]string
	version     string
	serverInfo  any
	sessions    *sync.Map // server id -> mcpSession
	serverID    string
	timeout     time.Duration
	lastSession *mcpSession
}

type mcpError struct {
	Code, Message string
}

func (e *mcpError) Error() string { return e.Code + ": " + e.Message }

func upErr(code, format string, a ...any) error {
	return &mcpError{Code: code, Message: fmt.Sprintf(format, a...)}
}

func (u *mcpUpstream) post(ctx context.Context, body map[string]any, headers map[string]string) (int, http.Header, map[string]any, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, nil, nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, u.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, u.url, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, nil, upErr("upstream.unreachable", "%v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range u.auth {
		req.Header.Set(k, v)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		if errors.Is(cctx.Err(), context.DeadlineExceeded) {
			return 0, nil, nil, upErr("upstream.timeout", "%v", err)
		}
		return 0, nil, nil, upErr("upstream.unreachable", "%v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, mcpMaxResponse+1))
	if err != nil {
		return 0, nil, nil, upErr("upstream.unreachable", "%v", err)
	}
	if len(data) > mcpMaxResponse {
		return 0, nil, nil, upErr("upstream.response_too_large", "")
	}
	id, hasID := body["id"]
	if !hasID {
		return resp.StatusCode, resp.Header, nil, nil
	}
	return resp.StatusCode, resp.Header, parseRPC(resp.Header.Get("Content-Type"), data, id), nil
}

var sseSplit = regexp.MustCompile(`\r?\n\r?\n`)
var lineSplit = regexp.MustCompile(`\r?\n`)

// parseRPC: the JSON-RPC response to id from a JSON body or an SSE stream.
func parseRPC(ctype string, raw []byte, id any) map[string]any {
	var msgs []any
	if strings.Contains(ctype, "text/event-stream") {
		for _, event := range sseSplit.Split(string(raw), -1) {
			var data []string
			for _, line := range lineSplit.Split(event, -1) {
				if strings.HasPrefix(line, "data:") {
					data = append(data, strings.TrimLeft(line[5:], " \t"))
				}
			}
			if len(data) > 0 {
				if v, err := canon.Parse([]byte(strings.Join(data, "\n"))); err == nil {
					msgs = append(msgs, v)
				}
			}
		}
	} else if strings.TrimSpace(string(raw)) != "" {
		v, err := canon.Parse(raw)
		if err != nil {
			return nil
		}
		if l, ok := v.([]any); ok {
			msgs = l
		} else {
			msgs = []any{v}
		}
	}
	want := fmt.Sprint(id)
	for _, m := range msgs {
		msg, _ := m.(map[string]any)
		if msg == nil || fmt.Sprint(msg["id"]) != want {
			continue
		}
		if _, ok := msg["result"]; ok {
			return msg
		}
		if _, ok := msg["error"]; ok {
			return msg
		}
	}
	return nil
}

func (u *mcpUpstream) modernBody(method string, params map[string]any) map[string]any {
	p := map[string]any{}
	for k, v := range params {
		p[k] = v
	}
	p["_meta"] = map[string]any{metaVersion: mcpModern, "io.modelcontextprotocol/clientInfo": mcpClientInfo,
		"io.modelcontextprotocol/clientCapabilities": map[string]any{}}
	return map[string]any{"jsonrpc": "2.0", "id": mcpIDs.Add(1), "method": method, "params": p}
}

func (u *mcpUpstream) modern(ctx context.Context, method string, params map[string]any, extra map[string]string) (int, map[string]any, error) {
	headers := map[string]string{"MCP-Protocol-Version": mcpModern, "Mcp-Method": method}
	for k, v := range extra {
		headers[k] = v
	}
	if name, ok := params["name"]; ok && (method == "tools/call" || method == "prompts/get") {
		headers["Mcp-Name"] = mcpHeaderValue(name)
	}
	status, _, msg, err := u.post(ctx, u.modernBody(method, params), headers)
	return status, msg, err
}

func (u *mcpUpstream) legacySession(ctx context.Context, fresh bool) (mcpSession, error) {
	if v, ok := u.sessions.Load(u.serverID); ok && !fresh {
		s := v.(mcpSession)
		if time.Now().Before(s.expires) {
			return s, nil
		}
	}
	asked := mcpLegacy[0]
	if isLegacy(u.version) {
		asked = u.version
	}
	body := map[string]any{"jsonrpc": "2.0", "id": mcpIDs.Add(1), "method": "initialize",
		"params": map[string]any{"protocolVersion": asked, "capabilities": map[string]any{}, "clientInfo": mcpClientInfo}}
	status, headers, msg, err := u.post(ctx, body, nil)
	if err != nil {
		return mcpSession{}, err
	}
	result, _ := msg["result"].(map[string]any)
	if status != 200 || result == nil {
		return mcpSession{}, upErr("upstream.initialize_failed", "HTTP %d", status)
	}
	version, _ := result["protocolVersion"].(string)
	if !isLegacy(version) {
		return mcpSession{}, upErr("upstream.unsupported_version", "server answered %q", version)
	}
	s := mcpSession{id: headers.Get("Mcp-Session-Id"), version: version, expires: time.Now().Add(mcpSessionTTL)}
	h := map[string]string{}
	if version != "2025-03-26" {
		h["MCP-Protocol-Version"] = version
	}
	if s.id != "" {
		h["Mcp-Session-Id"] = s.id
	}
	_, _, _, _ = u.post(ctx, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, h)
	u.sessions.Store(u.serverID, s)
	u.serverInfo = result["serverInfo"]
	return s, nil
}

func (u *mcpUpstream) legacy(ctx context.Context, method string, params map[string]any) (int, map[string]any, error) {
	var status int
	var msg map[string]any
	for attempt := 0; attempt < 2; attempt++ {
		s, err := u.legacySession(ctx, attempt == 1)
		if err != nil {
			return 0, nil, err
		}
		h := map[string]string{}
		if s.version != "2025-03-26" {
			h["MCP-Protocol-Version"] = s.version
		}
		if s.id != "" {
			h["Mcp-Session-Id"] = s.id
		}
		body := map[string]any{"jsonrpc": "2.0", "id": mcpIDs.Add(1), "method": method}
		if params != nil {
			body["params"] = params
		}
		status, _, msg, err = u.post(ctx, body, h)
		if err != nil {
			return 0, nil, err
		}
		if status == 404 && s.id != "" && attempt == 0 {
			continue // the server dropped the session: initialize again, once
		}
		break
	}
	return status, msg, nil
}

// detect: the protocol version to use with this server.
func (u *mcpUpstream) detect(ctx context.Context) (string, error) {
	u.serverInfo = nil
	if isLegacy(u.protocol) {
		s, err := u.legacySession(ctx, true)
		u.version = s.version
		return u.version, err
	}
	if u.protocol == "auto" || u.protocol == mcpModern || u.protocol == "" {
		status, msg, err := u.modern(ctx, "server/discover", nil, nil)
		if err != nil {
			return "", err
		}
		if result, ok := msg["result"].(map[string]any); status == 200 && ok {
			versions, _ := result["supportedVersions"].([]any)
			supported := len(versions) == 0
			for _, v := range versions {
				if v == mcpModern {
					supported = true
				}
			}
			if supported {
				if meta, ok := result["_meta"].(map[string]any); ok {
					u.serverInfo = meta["io.modelcontextprotocol/serverInfo"]
				}
				u.version = mcpModern
				return mcpModern, nil
			}
		}
		e, _ := msg["error"].(map[string]any)
		if code := fmt.Sprint(e["code"]); code == fmt.Sprint(headerMismatch) || code == fmt.Sprint(unsupportedVers) {
			data, _ := e["data"].(map[string]any)
			list, _ := data["supported"].([]any)
			modernOK, legacy := false, ""
			for _, v := range list {
				s, _ := v.(string)
				if s == mcpModern {
					modernOK = true
				}
			}
			for _, l := range mcpLegacy {
				for _, v := range list {
					if v == l && legacy == "" {
						legacy = l
					}
				}
			}
			if !modernOK && legacy == "" {
				return "", upErr("upstream.unsupported_version", "server supports %v", list)
			}
			if !modernOK {
				u.protocol = legacy
				return u.detect(ctx)
			}
			return "", upErr("upstream.refused", "%v", e["message"])
		}
		if u.protocol == mcpModern {
			return "", upErr("upstream.not_modern", "HTTP %d", status)
		}
	}
	s, err := u.legacySession(ctx, true)
	u.version = s.version
	return u.version, err
}

func (u *mcpUpstream) request(ctx context.Context, method string, params map[string]any, extra map[string]string) (map[string]any, error) {
	if u.version == "" {
		if _, err := u.detect(ctx); err != nil {
			return nil, err
		}
	}
	var status int
	var msg map[string]any
	var err error
	if u.version == mcpModern {
		status, msg, err = u.modern(ctx, method, params, extra)
	} else {
		status, msg, err = u.legacy(ctx, method, params)
	}
	if err != nil {
		return nil, err
	}
	if msg == nil {
		return nil, upErr("upstream.bad_response", "HTTP %d, no JSON-RPC response", status)
	}
	if e, ok := msg["error"].(map[string]any); ok {
		return nil, upErr("upstream.error", "%v: %.200v", e["code"], e["message"])
	}
	result, ok := msg["result"].(map[string]any)
	if !ok {
		return nil, upErr("upstream.bad_response", "result is not an object")
	}
	return result, nil
}

func (u *mcpUpstream) listTools(ctx context.Context) ([]map[string]any, error) {
	var tools []map[string]any
	var cursor any
	for page := 0; page < mcpMaxPages; page++ {
		params := map[string]any{}
		if cursor != nil && cursor != "" {
			params["cursor"] = cursor
		}
		result, err := u.request(ctx, "tools/list", params, nil)
		if err != nil {
			return nil, err
		}
		list, ok := result["tools"].([]any)
		if !ok {
			return nil, upErr("upstream.bad_response", "tools is not a list")
		}
		for _, t := range list {
			if m, ok := t.(map[string]any); ok {
				tools = append(tools, m)
			}
		}
		if len(tools) > mcpMaxTools {
			return nil, upErr("upstream.too_many_tools", "more than %d", mcpMaxTools)
		}
		cursor = result["nextCursor"]
		if cursor == nil || cursor == "" {
			return tools, nil
		}
	}
	return nil, upErr("upstream.too_many_pages", "")
}

func (u *mcpUpstream) callTool(ctx context.Context, name string, args map[string]any, schema any) (map[string]any, error) {
	extra := map[string]string{}
	paramHeaders(schema, args, extra)
	return u.request(ctx, "tools/call", map[string]any{"name": name, "arguments": args}, extra)
}

// ---------------------------------------------------------------- the proxy's side

type mcpLive struct {
	expires time.Time
	tools   map[string]map[string]any // name -> definition
}

func (p *Proxy) mcpServer(slug string) (MCPServer, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	s, ok := p.mcpServers[slug]
	return s, ok
}

// mcpUpstreamFor: a client for the server with its credential - only for
// the origin it was sealed for. ok false: no credential that may be used.
func (p *Proxy) mcpUpstreamFor(ctx context.Context, s MCPServer, protocol string) (*mcpUpstream, bool) {
	cred := map[string]any{"object": "mcp_server", "id": s.ID.String(), "source": s.CredentialSource,
		"header": s.AuthHeader}
	header, value, ok := p.credentialFor(ctx, cred, s.URL)
	if !ok {
		return nil, false
	}
	auth := map[string]string{}
	if header != "" && value != "" {
		auth[header] = value
	}
	timeout := time.Duration(s.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if protocol == "" {
		protocol = s.Protocol
	}
	v := ""
	if protocol == mcpModern || isLegacy(protocol) {
		v = protocol
	}
	return &mcpUpstream{client: p.upstream, url: s.URL, protocol: protocol, auth: auth, version: v,
		sessions: &p.mcpSessions, serverID: s.ID.String(), timeout: timeout}, true
}

// liveDefinition: the tool's definition as the server serves it now (cached a minute).
func (p *Proxy) liveDefinition(ctx context.Context, s MCPServer, name string) (map[string]any, error) {
	p.mu.RLock()
	live, ok := p.mcpLive[s.Slug]
	p.mu.RUnlock()
	if !ok || time.Now().After(live.expires) {
		up, ok := p.mcpUpstreamFor(ctx, s, "")
		if !ok {
			return nil, upErr("proxy.sealed_credential_missing", "the server's credential is not sealed to this proxy")
		}
		tools, err := up.listTools(ctx)
		if err != nil {
			return nil, err
		}
		live = mcpLive{expires: time.Now().Add(mcpLiveTTL), tools: map[string]map[string]any{}}
		for _, t := range tools {
			if n, ok := t["name"].(string); ok {
				live.tools[n] = definitionOf(t)
			}
		}
		p.mu.Lock()
		p.mcpLive[s.Slug] = live
		p.mu.Unlock()
	}
	d, ok := live.tools[name]
	if !ok {
		return nil, upErr("upstream.tool_missing", "")
	}
	return d, nil
}

// syncMCP reports each served server's tools (as an admin's sync would).
func (p *Proxy) syncMCP(ctx context.Context) {
	p.mu.RLock()
	servers := make([]MCPServer, 0, len(p.mcpServers))
	for _, s := range p.mcpServers {
		servers = append(servers, s)
	}
	p.mu.RUnlock()
	quiet := context.WithValue(ctx, noFetch{}, true)
	for _, s := range servers {
		body := map[string]any{"server_id": s.ID}
		up, ok := p.mcpUpstreamFor(quiet, s, "")
		if !ok {
			body["error"] = "proxy.sealed_credential_missing: the server's credential is not sealed to this proxy"
		} else {
			up.version = "" // detect again: it may be another server now
			version, err := up.detect(ctx)
			var tools []map[string]any
			if err == nil {
				tools, err = up.listTools(ctx)
			}
			if err != nil {
				body["error"] = err.Error()
			} else {
				body["tools"], body["detected_version"], body["server_info"] = tools, version, up.serverInfo
				live := mcpLive{expires: time.Now().Add(mcpLiveTTL), tools: map[string]map[string]any{}}
				for _, t := range tools {
					if n, ok := t["name"].(string); ok {
						live.tools[n] = definitionOf(t)
					}
				}
				p.mu.Lock()
				p.mcpLive[s.Slug] = live
				p.mu.Unlock()
			}
		}
		if err := p.srv.call(ctx, http.MethodPost, "/egress-proxy/mcp/sync", body, p.srv.asProxy(), nil); err != nil {
			p.log.Warn("provenza proxy: MCP sync report", "server", s.Slug, "err", err)
		}
	}
}

func rpcError(w http.ResponseWriter, status int, id any, code int, message string, data any) {
	e := map[string]any{"code": code, "message": message}
	if data != nil {
		e["data"] = data
	}
	body := map[string]any{"jsonrpc": "2.0", "error": e}
	if id != nil {
		body["id"] = id
	}
	writeJSON(w, status, body)
}

func rpcResult(w http.ResponseWriter, id any, result map[string]any, modern bool) {
	if modern {
		r := map[string]any{"resultType": "complete"}
		for k, v := range result {
			r[k] = v
		}
		result = r
	}
	writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func textResult(text string) map[string]any {
	return map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}, "isError": true}
}

func decodeHeader(v string) (string, bool) {
	if strings.HasPrefix(v, "=?base64?") && strings.HasSuffix(v, "?=") {
		raw, err := base64.StdEncoding.DecodeString(v[9 : len(v)-2])
		return string(raw), err == nil
	}
	return v, true
}

func (p *Proxy) serveMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	key := agentKeyOf(r)
	if key == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		rpcError(w, http.StatusUnauthorized, nil, -32001, "send the agent's key (X-Agent-Key or Bearer)", nil)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxAgentBody+1))
	if err != nil || len(raw) > maxAgentBody {
		rpcError(w, http.StatusRequestEntityTooLarge, nil, -32600, "the request is too large", nil)
		return
	}
	v, err := canon.Parse(raw)
	body, _ := v.(map[string]any)
	if err != nil || body == nil {
		p.relayMCP(w, r, key, raw)
		return
	}
	params, _ := body["params"].(map[string]any)
	name, _ := params["name"].(string)
	slug, tool, _ := strings.Cut(name, ".")
	server, ours := p.mcpServer(slug)
	if body["method"] != "tools/call" || !ours || tool == "" || body["id"] == nil {
		p.relayMCP(w, r, key, raw) // everything else is the server's MCP endpoint
		return
	}
	p.mcpToolCall(w, r, key, body, params, server, name, tool)
}

// relayMCP passes the request to the server's MCP endpoint as it came.
func (p *Proxy) relayMCP(w http.ResponseWriter, r *http.Request, key string, raw []byte) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, p.srv.base+"/api/v1/mcp", bytes.NewReader(raw))
	if err != nil {
		rpcError(w, http.StatusBadGateway, nil, -32603, "the request could not be relayed", nil)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", r.Header.Get("Accept"))
	req.Header.Set("X-Agent-Key", key)
	for _, h := range []string{"MCP-Protocol-Version", "Mcp-Method", "Mcp-Name", "Mcp-Session-Id"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	for k, vs := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "mcp-param-") {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
	}
	resp, err := p.srv.http.Do(req)
	if err != nil {
		rpcError(w, http.StatusServiceUnavailable, nil, -32603, "Provenza is unreachable; nothing was called", nil)
		return
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(out)
}

func (p *Proxy) mcpToolCall(w http.ResponseWriter, r *http.Request, key string, body, params map[string]any,
	server MCPServer, name, upstreamName string) {
	ctx := r.Context()
	id := body["id"]
	meta, _ := params["_meta"].(map[string]any)
	_, modern := meta[metaVersion]
	if modern {
		if meta[metaVersion] != r.Header.Get("MCP-Protocol-Version") {
			rpcError(w, http.StatusBadRequest, id, headerMismatch, "Header mismatch: MCP-Protocol-Version", nil)
			return
		}
		if meta[metaVersion] != mcpModern {
			rpcError(w, http.StatusBadRequest, id, unsupportedVers, "Unsupported protocol version",
				map[string]any{"supported": append([]string{mcpModern}, mcpLegacy...), "requested": meta[metaVersion]})
			return
		}
		if r.Header.Get("Mcp-Method") != "tools/call" {
			rpcError(w, http.StatusBadRequest, id, headerMismatch, "Header mismatch: Mcp-Method", nil)
			return
		}
		if n, ok := decodeHeader(r.Header.Get("Mcp-Name")); !ok || n != name {
			rpcError(w, http.StatusBadRequest, id, headerMismatch, "Header mismatch: Mcp-Name", nil)
			return
		}
	}
	args, ok := params["arguments"].(map[string]any)
	if _, present := params["arguments"]; !present {
		args, ok = map[string]any{}, true
	}
	if !ok {
		rpcError(w, http.StatusOK, id, -32602, "Invalid params: name must be a string and arguments an object", nil)
		return
	}
	plan := map[string]any{"name": name, "arguments": args}
	if c, ok := meta[chainMeta]; ok {
		plan["chain_id"] = c
	}
	def, err := p.liveDefinition(ctx, server, upstreamName)
	if err != nil {
		code := "upstream.error"
		var me *mcpError
		if errors.As(err, &me) {
			code = me.Code
		}
		plan["live_error"] = code
	} else {
		d, err := manifestDigest(def)
		if err != nil {
			plan["live_error"] = "proxy.digest"
		} else {
			plan["live_digest"] = d
		}
	}
	planRaw, _ := json.Marshal(plan)
	m, err := p.srv.plan(ctx, "mcp", key, planRaw)
	if err != nil {
		var se *serverError
		if errors.As(err, &se) {
			rpcError(w, http.StatusOK, id, -32000, "Refused by Provenza", se.Detail)
			return
		}
		rpcError(w, http.StatusServiceUnavailable, id, -32603, "Provenza is unreachable; the tool was not called", nil)
		return
	}
	switch m["decision"] {
	case "error":
		e, _ := m["error"].(map[string]any)
		code := -32602
		fmt.Sscan(fmt.Sprint(e["code"]), &code)
		rpcError(w, http.StatusOK, id, code, fmt.Sprint(e["message"]), nil)
		return
	case "refused":
		res, _ := m["result"].(map[string]any)
		rpcResult(w, id, res, modern)
		return
	case policy.Allowed:
	default:
		rpcResult(w, id, textResult("Refused by Provenza"), modern)
		return
	}
	chk := checkOf(m)
	a := &action{plan: m, check: chk, started: time.Now(), fields: map[string]any{"check_id": chk.CheckID,
		"agent_id": chk.AgentID, "chain_id": chk.ChainID, "action_type": "tool_call", "tool_name": chk.Tool,
		"input_sha256": chk.InputSHA, "agent_signature": "not_presented", "policy": nil}}
	markSigned(ctx, a.fields, chk)
	if d, ok := plan["live_digest"].(string); ok {
		chk.ToolDigest = &d // what this proxy hashed from the upstream
	}
	planned, _ := m["arguments"].(map[string]any)
	if chk.Tool != name || m["upstream_name"] != upstreamName || planned == nil {
		p.refuseMCP(w, ctx, a, id, modern, policy.Denied, "the planned call is not this request")
		return
	}
	if p.enf.enforcing() {
		if !p.judgedQuiet(ctx, a, planned) {
			p.answerRefused(w, a, id, modern)
			return
		}
		signed, ok := p.signedRow("mcp_servers", "slug", server.Slug)
		if !ok || signed["url"] != server.URL || signed["auth_header"] != server.AuthHeader {
			p.refuseMCP(w, ctx, a, id, modern, policy.Denied, "MCP server '"+server.Slug+"' is not in the signed policy as configured")
			return
		}
	}
	srvPlan, _ := m["server"].(map[string]any)
	protocol, _ := srvPlan["protocol"].(string)
	up, ok := p.mcpUpstreamFor(ctx, server, protocol)
	if !ok {
		aid := p.done(ctx, a, map[string]any{"upstream_error": "proxy.sealed_credential_missing"})
		rpcResult(w, id, textResult(fmt.Sprintf("The tool could not be reached (action #%d): its credential is not sealed to this proxy", aid)), modern)
		return
	}
	result, err := up.callTool(ctx, upstreamName, planned, m["input_schema"])
	var output map[string]any
	if err != nil {
		code := "upstream.error"
		var me *mcpError
		if errors.As(err, &me) {
			code = me.Code
		}
		output = map[string]any{"upstream_error": code}
		aid := p.done(ctx, a, output)
		rpcResult(w, id, textResult(fmt.Sprintf("The tool could not be reached (action #%d): %s", aid, code)), modern)
		return
	}
	answer := map[string]any{"content": result["content"]}
	if answer["content"] == nil {
		answer["content"] = []any{}
	}
	for _, k := range []string{"structuredContent", "isError"} {
		if v, ok := result[k]; ok {
			answer[k] = v
		}
	}
	sha, _ := canon.SHA256(answer)
	output = map[string]any{"response_sha256": sha, "is_error": result["isError"] == true}
	p.done(ctx, a, output)
	rpcResult(w, id, answer, modern)
}

// judgedQuiet: judged without answering (the MCP answer is a tool result).
func (p *Proxy) judgedQuiet(ctx context.Context, a *action, input any) bool {
	sha, err := canon.SHA256(input)
	if err != nil || sha != a.check.InputSHA {
		a.refusal = [2]string{policy.Denied, "the planned input is not the checked one"}
		p.recordRefusal(ctx, a)
		return false
	}
	signed, fp := signedFor(ctx, a.check)
	if p.enf.strict() && !signed {
		a.refusal = [2]string{policy.Denied, "enforce mode: the agent's signed request is not this action's"}
		p.recordRefusal(ctx, a)
		return false
	}
	actionType, _ := a.fields["action_type"].(string)
	verdict, why, release := p.judge(a.check, actionType, a.check.Tool, input, sha, signed, fp)
	a.fields["policy"] = release
	if verdict != policy.Allowed {
		if verdict != policy.PendingApproval {
			verdict = policy.Denied
		}
		a.refusal = [2]string{verdict, why}
		p.recordRefusal(ctx, a)
		return false
	}
	return true
}

func (p *Proxy) refuseMCP(w http.ResponseWriter, ctx context.Context, a *action, id any, modern bool, verdict, why string) {
	a.refusal = [2]string{verdict, why}
	p.recordRefusal(ctx, a)
	p.answerRefused(w, a, id, modern)
}

func (p *Proxy) answerRefused(w http.ResponseWriter, a *action, id any, modern bool) {
	rpcResult(w, id, textResult(fmt.Sprintf("Refused by the signed policy at the egress proxy (action #%d): %s",
		a.actionID, a.refusal[1])), modern)
}
