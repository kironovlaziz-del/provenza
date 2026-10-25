// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

// Package egress is the Provenza egress proxy: agents reach external APIs only
// through it, and it holds the credentials (docs/pvp/spec.md, 5.5).
//
//	agent ──HTTP──► 127.0.0.1:8443/<route>/<path>
//	   mediated  X-Agent-Key: the proxy checks for that agent (/egress-proxy/check)
//	   SDK       X-Provenza-Check-Id: the agent already holds a check
//	──► redeem (the exact request, hashes only) ──► upstream from the route table,
//	    credential injected ──► response streamed back ──► complete (status, hash)
//
// What reaches the upstream is decided by the server and the route table, never
// by the request: the upstream host, the credential, the methods and path
// prefixes. The agent's own credentials and Provenza headers are never forwarded.
// The credential is opened here: sealed to this proxy's key (sealed.go), or
// from its own configuration - the server holds none it could read.
package egress

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kironovlaziz-del/provenza/proxy/internal/canon"
	"github.com/kironovlaziz-del/provenza/proxy/internal/policy"
	"github.com/kironovlaziz-del/provenza/proxy/internal/trust"
)

// Descriptor is the request as checked and redeemed: hashes only, never content.
type Descriptor struct {
	Route       string  `json:"route"`
	Method      string  `json:"method"`
	Path        string  `json:"path"`
	QuerySHA256 *string `json:"query_sha256"`
	BodySHA256  *string `json:"body_sha256"`
	BodyBytes   int64   `json:"body_bytes"`
}

func sha256Hex(b []byte) *string {
	if len(b) == 0 {
		return nil
	}
	s := sha256.Sum256(b)
	h := hex.EncodeToString(s[:])
	return &h
}

// hop-by-hop and credential headers: never forwarded upstream (or back)
var dropped = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true, "Te": true,
	"Trailer": true, "Transfer-Encoding": true, "Upgrade": true, "Authorization": true, "Cookie": true,
	"X-Agent-Key": true, "Host": true, "Content-Length": true,
}

func forwardable(name string) bool {
	return !dropped[http.CanonicalHeaderKey(name)] && !strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Provenza-")
}

// pathProblem mirrors the server's rule: no "." / ".." segments, no encoded separators.
func pathProblem(path string) string {
	if !strings.HasPrefix(path, "/") {
		return "the path must start with /"
	}
	for _, seg := range strings.Split(path, "/") {
		dec, err := url.PathUnescape(seg)
		if err != nil || dec == "." || dec == ".." || strings.ContainsAny(dec, "/\\") {
			return "the path has a '.' / '..' segment or an encoded separator"
		}
	}
	return ""
}

func prefixAllows(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if p == "/" || path == p || strings.HasPrefix(path, strings.TrimRight(p, "/")+"/") {
			return true
		}
	}
	return false
}

// Proxy serves agents.
type Proxy struct {
	cfg      *Config
	srv      *server
	upstream *http.Client
	// relayClient carries /_provenza/... to the server (relay.go); nil when relay_provenza is off
	relayClient *http.Client
	log         *slog.Logger
	// wit signs receipts with the proxy's own key (witness.go); nil when the
	// server does not take a key (an older server)
	wit *witness
	// enf judges by the signed policy this proxy verified (enforce.go)
	enf *enforcer
	now func() time.Time

	// opener opens the credentials sealed to this proxy (sealed.go); reg is
	// what the server answered when the keys were registered
	opener *opener
	reg    *registration

	mu     sync.RWMutex
	routes map[string]Route
	loaded bool
	creds  map[credKey]openedCredential // opened credentials, in memory only
	// the MCP servers and A2A peers whose credential the proxies hold (mcp.go, a2a.go)
	mcpServers  map[string]MCPServer
	mcpLive     map[string]mcpLive
	mcpSessions sync.Map
	a2aPeers    map[string]A2APeer
	// lastMiss: a credential missing on a request fetches the envelopes again
	// at once (one just sealed) - for each object at most every few seconds
	credMu   sync.Mutex
	lastMiss map[credKey]time.Time
	// the SHA-256 of each envelope last fetched, "<object>:<id>" (killswitch.go compares them),
	// and those an administrator of the signed policy vouched for
	envelopes map[string]string
	vouched   map[string]bool

	// the local kill switch and what was done while Provenza was unreachable
	// (killswitch.go, offline.go)
	ks      *killSwitch
	offline *offlineLog
	probeMu sync.Mutex
	probed  time.Time
}

// New makes a proxy; Start loads the routes before it serves.
func New(cfg *Config, proxyKey string, logger *slog.Logger) *Proxy {
	if logger == nil {
		logger = slog.Default()
	}
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	srv := newServer(cfg.ServerURL, proxyKey, cfg.ServerTimeout.Duration)
	if cfg.Policy.Mode == "enforce" {
		srv.mode = "enforce"
	}
	p := &Proxy{cfg: cfg, srv: srv, log: logger,
		enf: newEnforcer(cfg.Policy, cfg.StateDir), now: time.Now,
		ks: newKillSwitch(cfg.StateDir), offline: newOfflineLog(cfg.StateDir),
		// a redirect goes back to the agent: following it here would carry the credential elsewhere
		upstream: &http.Client{Timeout: cfg.UpstreamTimeout.Duration, CheckRedirect: noRedirect}}
	if cfg.RelayProvenza {
		p.relayClient = &http.Client{Timeout: cfg.UpstreamTimeout.Duration, CheckRedirect: noRedirect}
	}
	return p
}

// Refresh loads the route table once (it carries no credentials).
func (p *Proxy) Refresh(ctx context.Context) (time.Duration, error) {
	cfg, every, err := p.srv.config(ctx)
	if err != nil {
		return time.Minute, err
	}
	m := make(map[string]Route, len(cfg.Routes))
	for _, r := range cfg.Routes {
		m[r.Slug] = r
	}
	servers := make(map[string]MCPServer, len(cfg.MCPServers))
	for _, s := range cfg.MCPServers {
		servers[s.Slug] = s
	}
	peers := make(map[string]A2APeer, len(cfg.A2APeers))
	for _, a := range cfg.A2APeers {
		peers[a.Slug] = a
	}
	p.mu.Lock()
	p.routes, p.loaded, p.mcpServers, p.a2aPeers = m, true, servers, peers
	if p.mcpLive == nil {
		p.mcpLive = map[string]mcpLive{}
	}
	p.mu.Unlock()
	return every, nil
}

// startRetry: how long a proxy that cannot reach the server at start keeps trying.
const startRetry = 30 * time.Second

// Start loads the routes and keeps them fresh until ctx ends. The first load
// must succeed (a network failure is retried for startRetry): without the
// table there is nothing it may forward. It also loads (or makes) the
// proxy's own key and registers it, and - with policy.mode "enforce" - the
// signed policy.

func (p *Proxy) Start(ctx context.Context) error {
	every, err := p.Refresh(ctx)
	// On a proxy host the sensor holds the proxy's connections until it has
	// checked the proxy's binary (docs/pvp/edge.md, section 5): the first
	// contact may be refused for a moment. A network failure is retried briefly.
	var se *serverError
	for wait, until := 100*time.Millisecond, time.Now().Add(startRetry); err != nil && !errors.As(err, &se) &&
		time.Now().Before(until); wait = min(2*wait, 2*time.Second) {
		p.log.Info("provenza proxy: the server is not reachable yet; retrying", "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		every, err = p.Refresh(ctx)
	}
	if err != nil {
		return err
	}
	if err := p.ks.load(); err != nil {
		return err
	}
	if engaged, why := p.ks.engagedNow(); engaged {
		p.log.Error("provenza proxy: LOCAL KILL SWITCH engaged before the restart - every request is refused "+
			"until administrators lift it", "reason", why)
	}
	w, err := newWitness(p.cfg.StateDir, p.cfg.SigningKeyFile)
	if err != nil {
		return fmt.Errorf("the proxy's key and receipt log (%s): %w", p.cfg.StateDir, err)
	}
	op, err := newOpener(w.key)
	if err != nil {
		return err
	}
	stmt, err := keyStatement(op.publicKey())
	if err != nil {
		return err
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(w.key, stmt))
	switch reg, err := p.srv.registerKey(ctx, w.publicKey(), op.publicKey(), sig); {
	case err == nil:
		p.wit, p.opener, p.reg = w, op, reg
		p.log.Info("provenza proxy: keys registered", "proxy_id", reg.ProxyID.String(),
			"key_fingerprint", fingerprint(w.key.Public().(ed25519.PublicKey)), "encryption_key_fingerprint",
			fingerprint(op.pub))
		if err := p.refreshCredentials(ctx); err != nil {
			p.log.Warn("provenza proxy: sealed credentials", "err", err)
		}
		go p.syncUpstreams(ctx)
	case errors.As(err, &se) && se.Status == http.StatusNotFound:
		p.log.Warn("provenza proxy: the server takes no proxy key; requests are recorded without the proxy's receipts")
	default:
		return fmt.Errorf("registering the proxy's key: %w", err)
	}
	if p.enf.enforcing() {
		if err := p.enf.load(); err != nil {
			return err
		}
		if err := p.enf.refresh(ctx, p.srv); err != nil {
			p.log.Warn("provenza proxy: signed policy", "err", err)
		}
		if p.enf.current() == nil {
			p.log.Warn("provenza proxy: no signed policy verified yet; every request is refused until one is")
		}
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(every):
				next, err := p.Refresh(ctx)
				if err != nil {
					p.log.Warn("provenza proxy: route refresh failed; keeping the last table", "err", err)
				}
				if p.opener != nil {
					if err := p.refreshCredentials(ctx); err != nil {
						p.log.Warn("provenza proxy: sealed credentials refresh failed; keeping the last ones", "err", err)
					}
					p.syncUpstreams(ctx)
				}
				if p.enf.enforcing() {
					if err := p.enf.refresh(ctx, p.srv); err != nil {
						p.log.Warn("provenza proxy: signed policy refresh", "err", err)
					}
				}
				every = next
			}
		}
	}()
	go p.guard(ctx)
	return nil
}

// fingerprint: as Provenza shows a key (SHA256:<unpadded base64>), to
// compare in its UI with what this host printed.
func fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// refreshCredentials opens the envelopes sealed to this proxy. One that does
// not open, or names another context, is left out (and logged): its object
// then has no credential here and its requests are refused. With
// policy.mode "enforce" an envelope is opened only when an administrator of
// the signed manifest this proxy verified signed it (trust.VerifySealed): the
// server cannot slip in a credential of its own choosing.
func (p *Proxy) refreshCredentials(ctx context.Context) error {
	list, err := p.srv.credentials(ctx)
	if err != nil {
		return err
	}
	m := make(map[credKey]openedCredential, len(list))
	digests := make(map[string]string, len(list))
	vouched := make(map[string]bool, len(list))
	for _, c := range list {
		sum, err := canon.SHA256(c.Envelope)
		if err == nil {
			digests[c.Object+":"+c.ObjectID] = sum
		}
		id, err := strconv.ParseInt(c.ObjectID, 10, 64)
		if err != nil {
			continue
		}
		want := map[string]any{"org_id": p.reg.OrgID, "object": c.Object, "object_id": id, "proxy_id": p.reg.ProxyID}
		value, upstream, err := p.opener.open(c.Envelope, want)
		if err != nil {
			p.log.Warn("provenza proxy: a sealed credential was refused", "object", c.Object, "id", c.ObjectID,
				"err", err)
			continue
		}
		if p.enf.enforcing() {
			rel := p.enf.current()
			if rel == nil {
				continue // no signed manifest to know the sealers by: nothing opens
			}
			if _, err := trust.VerifySealed(c.Sealer, rel.Manifest, trust.SealedWant{OrgID: p.reg.OrgID,
				Object: c.Object, ObjectID: id, ProxyID: p.reg.ProxyID, Upstream: upstream, EnvelopeSHA256: sum}); err != nil {
				p.log.Warn("provenza proxy: a sealed credential no administrator of the signed policy vouched for "+
					"was refused (countersign it under Egress)", "object", c.Object, "id", c.ObjectID, "err", err)
				continue
			}
			vouched[c.Object+":"+c.ObjectID] = true
		}
		m[credKey{c.Object, c.ObjectID}] = openedCredential{Value: value, Upstream: upstream}
	}
	p.mu.Lock()
	fresh := false
	for k := range m {
		if _, had := p.creds[k]; !had && (k.Object == "mcp_server" || k.Object == "a2a_peer") {
			fresh = true
		}
	}
	p.creds, p.envelopes, p.vouched = m, digests, vouched
	p.mu.Unlock()
	if fresh && p.reg != nil {
		// an MCP server's or a peer's credential was just sealed to this proxy: sync now, not at the next refresh
		go p.syncUpstreams(context.WithoutCancel(ctx))
	}
	return nil
}

// syncUpstreams: the MCP servers' tools and the A2A peers' cards this proxy serves.
func (p *Proxy) syncUpstreams(ctx context.Context) {
	p.syncMCP(ctx)
	p.syncA2A(ctx)
}

// credential: the sealed credential of an object, for a request to target -
// only if target is on the origin it was sealed for.
func (p *Proxy) credential(ctx context.Context, object, id, target string) (string, bool) {
	want := origin(target)
	get := func() (string, bool) {
		p.mu.RLock()
		defer p.mu.RUnlock()
		c, ok := p.creds[credKey{object, id}]
		if !ok || want == "" || c.Upstream != want {
			return "", false
		}
		return c.Value, true
	}
	if v, ok := get(); ok || p.opener == nil || ctx.Value(noFetch{}) != nil {
		return v, ok
	}
	p.credMu.Lock()
	k := credKey{object, id}
	again := p.now().Sub(p.lastMiss[k]) >= 5*time.Second
	if again {
		if p.lastMiss == nil {
			p.lastMiss = map[credKey]time.Time{}
		}
		p.lastMiss[k] = p.now()
	}
	p.credMu.Unlock()
	if !again {
		return "", false
	}
	if err := p.refreshCredentials(ctx); err != nil {
		p.log.Warn("provenza proxy: sealed credentials", "err", err)
		return "", false
	}
	return get()
}

// noFetch marks a context whose credential lookups do not fetch the envelopes
// again on a miss (the periodic MCP sync: only requests do).
type noFetch struct{}

// sealedSource: "server" is what releases signed before sealing call it.
func sealedSource(s string) bool { return s == "sealed" || s == "server" }

func (p *Proxy) route(slug string) (Route, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	r, ok := p.routes[slug]
	return r, ok && p.loaded
}

// refuse answers the agent: an OpenAI-style error body, never the request's content.
func refuse(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Provenza-Refused", "1")
	w.Header().Set("X-Should-Retry", "false")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// /<route>/<path>, on the raw (escaped) path: what is checked is what is sent
	raw := r.URL.EscapedPath()
	relay := raw == RelayPrefix || strings.HasPrefix(raw, RelayPrefix+"/")
	if engaged, why := p.ks.engagedNow(); engaged && !relay {
		refuse(w, http.StatusServiceUnavailable, "provenza_kill_switch", "this proxy is stopped by its local kill "+
			"switch ("+why+"); administrators lift it after the reconciliation (Egress -> Proxies)")
		return
	}
	// the gateways' protocols (act.go): no route slug starts with "_"
	if handler, ok := p.adapter(raw); ok {
		if r, ok = p.signedAdapterRequest(w, r); ok {
			handler(w, r)
		}
		return
	}
	if relay {
		if p.relayClient == nil {
			refuse(w, http.StatusNotFound, "provenza_relay_off", "this proxy does not relay to Provenza (relay_provenza)")
			return
		}
		p.relay(w, r, raw)
		return
	}
	slug, rest, _ := strings.Cut(strings.TrimPrefix(raw, "/"), "/")
	path := "/" + rest
	route, ok := p.route(slug)
	if !ok {
		refuse(w, http.StatusNotFound, "provenza_unknown_route", "no such egress route: "+slug)
		return
	}
	if !contains(route.Methods, r.Method) {
		refuse(w, http.StatusMethodNotAllowed, "provenza_method", r.Method+" is not allowed on this route")
		return
	}
	if problem := pathProblem(path); problem != "" || !prefixAllows(path, route.PathPrefixes) {
		refuse(w, http.StatusForbidden, "provenza_path", "the path is outside this route")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, route.MaxBodyBytes+1))
	if err != nil {
		refuse(w, http.StatusBadRequest, "provenza_body", "could not read the request body")
		return
	}
	if int64(len(body)) > route.MaxBodyBytes {
		refuse(w, http.StatusRequestEntityTooLarge, "provenza_body_too_large", "the body is larger than this route allows")
		return
	}
	var query *string
	if r.URL.RawQuery != "" {
		query = sha256Hex([]byte(r.URL.RawQuery))
	}
	d := Descriptor{Route: slug, Method: r.Method, Path: path, QuerySHA256: query, BodySHA256: sha256Hex(body),
		BodyBytes: int64(len(body))}

	ctx := r.Context()
	dmap, err := canon.Of(d)
	if err != nil {
		refuse(w, http.StatusBadRequest, "provenza_body", "the request cannot be described")
		return
	}
	inputSHA, _ := canon.SHA256(dmap)
	tool := "proxy." + slug
	checkID := r.Header.Get("X-Provenza-Check-Id")
	signedHeader := r.Header.Get("X-Provenza-Request")
	strict := p.enf.strict()
	agentSignature := "not_presented"
	var fingerprint *string
	var chk *checkResult
	if checkID == "" { // mediated: check on the agent's behalf with its key
		key := r.Header.Get("X-Agent-Key")
		if signedHeader != "" && key == "" {
			// the agent could not reach Provenza for a check (offline.go)
			p.serveOffline(w, r, route, path, body, d, dmap, inputSHA, signedHeader)
			return
		}
		if key == "" {
			refuse(w, http.StatusUnauthorized, "provenza_agent_key_required",
				"send the agent's key (X-Agent-Key), or a check id (X-Provenza-Check-Id)")
			return
		}
		if strict && signedHeader == "" {
			refuse(w, http.StatusUnauthorized, "provenza_agent_signature_required",
				"this proxy takes only requests the agent signed (X-Provenza-Request; the proxy's agent mode "+
					"signs for clients that cannot)")
			return
		}
		// with the agent's signed request (agent mode): the server verifies it too - the check is the agent's own
		if chk, err = p.srv.check(ctx, key, d, signedHeader); err != nil {
			if signedHeader != "" && errors.Is(err, errUnavailable) {
				p.serveOffline(w, r, route, path, body, d, dmap, inputSHA, signedHeader)
				return
			}
			p.serverFailure(w, err)
			return
		}
		checkID = chk.CheckID
		chk.Tool, chk.InputSHA = tool, inputSHA
		if signedHeader != "" {
			sr, err := trust.ParseSignedRequest(signedHeader)
			var fp string
			if err == nil {
				fp, err = sr.Verify("proxy", tool, inputSHA, p.enf.nonces, p.now())
			}
			if err != nil {
				refuse(w, http.StatusUnauthorized, "provenza_agent_signature", "the agent's signed request: "+err.Error())
				return
			}
			if !sameNumber(sr.Payload["agent_id"], chk.AgentID) {
				refuse(w, http.StatusForbidden, "provenza_mismatch", "the check is not the signed request's")
				return
			}
			agentSignature, fingerprint = "verified", &fp
		}
	} else {
		if signedHeader == "" && strict {
			refuse(w, http.StatusUnauthorized, "provenza_agent_signature_required",
				"this proxy takes only requests the agent signed (X-Provenza-Request)")
			return
		}
		if chk, err = p.srv.checkInfo(ctx, checkID); err != nil {
			p.serverFailure(w, err)
			return
		}
		if signedHeader != "" && chk.Tool == tool && chk.InputSHA == inputSHA {
			sr, err := trust.ParseSignedRequest(signedHeader)
			var fp string
			if err == nil {
				fp, err = sr.Verify("proxy", tool, inputSHA, p.enf.nonces, p.now())
			}
			if err != nil {
				refuse(w, http.StatusUnauthorized, "provenza_agent_signature", "the agent's signed request: "+err.Error())
				return
			}
			if !sameNumber(sr.Payload["agent_id"], chk.AgentID) || !sameNumber(sr.Payload["chain_id"], chk.ChainID) {
				refuse(w, http.StatusForbidden, "provenza_mismatch", "the check is not the signed request's")
				return
			}
			agentSignature, fingerprint = "verified", &fp
		}
	}
	// what the receipt names (the server records the same, app/pvp/witness.py)
	fields := map[string]any{"check_id": checkID, "agent_id": chk.AgentID, "chain_id": chk.ChainID,
		"action_type": "proxy", "tool_name": tool, "input_sha256": inputSHA, "agent_signature": agentSignature,
		"policy": nil}
	matches := chk.Tool == tool && chk.InputSHA == inputSHA // otherwise the server burns the check at redeem
	if p.enf.enforcing() && matches {
		verdict, why, release := p.judge(chk, "proxy", tool, dmap, inputSHA, agentSignature == "verified", fingerprint)
		fields["policy"] = release
		if verdict != policy.Allowed {
			p.refuseUnderPolicy(w, ctx, checkID, d, fields, verdict, why)
			return
		}
		if signed, ok := p.signedRoute(release, slug, route); ok {
			route = signed
		} else {
			p.refuseUnderPolicy(w, ctx, checkID, d, fields, policy.Denied,
				"egress route '"+slug+"' is not in the signed policy")
			return
		}
	}
	red, err := p.srv.redeem(ctx, checkID, d, nil) // also records a refused check
	if err != nil {
		p.serverFailure(w, err)
		return
	}
	if !red.Allowed {
		refuse(w, http.StatusForbidden, "provenza_denied", fmt.Sprintf("Refused by Provenza: %s", red.Reason))
		return
	}
	if !matches {
		fields = nil // the server accepted it, so it is the checked request after all; no receipt to vouch for it
	}
	p.forward(w, r, route, path, body, checkID, fields, p.recordOnline(checkID))
}

// recorder: what records the outcome of a forwarded request (online: the
// server, offline: this proxy's offline log).
type recorder func(ctx context.Context, status int, respHash *string, respBytes int64, errCode string,
	d time.Duration, receipt map[string]any)

func (p *Proxy) recordOnline(checkID string) recorder {
	return func(ctx context.Context, status int, h *string, n int64, errCode string, d time.Duration,
		receipt map[string]any) {
		if err := p.srv.complete(ctx, checkID, status, h, n, errCode, d, receipt); err != nil {
			p.log.Error("provenza proxy: could not record a forwarded request (open redemption)", "check",
				short(checkID), "err", err)
		}
	}
}

// sameNumber: two parsed JSON values that are the same number (or both null).
func sameNumber(a, b any) bool {
	x, err1 := canon.Text(a)
	y, err2 := canon.Text(b)
	return err1 == nil && err2 == nil && x == y
}

// judge: the signed policy's verdict on the request (the Go evaluator,
// internal/policy; a call it holds for approval passes with a human approval
// verified here). Returns the verdict, why, and the release judged by.
func (p *Proxy) judge(chk *checkResult, actionType, tool string, input any, inputSHA string, keyChecked bool,
	fingerprint *string) (string, string, map[string]any) {
	rel := p.enf.current()
	if rel == nil {
		return policy.Denied, "this proxy has not verified a signed policy release", nil
	}
	ref := map[string]any{"release": rel.Number, "bundle_sha256": rel.BundleSHA}
	agentID, err := strconv.ParseInt(fmt.Sprint(chk.AgentID), 10, 64)
	if err != nil {
		return policy.Denied, "the check names no agent", ref
	}
	dec := policy.Evaluate(&policy.Policy{Number: rel.Number, Bundle: rel.Bundle, Manifest: rel.Manifest},
		policy.Request{AgentID: agentID, ActionType: actionType, ToolName: tool, Input: input, KeyChecked: keyChecked,
			KeyFingerprint: fingerprint, ToolDigest: chk.ToolDigest}, float64(p.now().Unix()))
	if dec.Result == policy.PendingApproval && chk.Approval != nil {
		_, err := trust.VerifyApproval(chk.Approval, rel.Manifest, trust.Call{AgentID: chk.AgentID,
			ChainID: chk.ChainID, ActionType: actionType, ToolName: tool, InputSHA256: inputSHA})
		if err == nil {
			return policy.Allowed, "approved by a person", ref
		}
		p.log.Warn("provenza proxy: an approval did not verify", "check", short(chk.CheckID), "err", err)
	}
	return dec.Result, dec.Reason, ref
}

// signedRoute: the route as the signed policy states it - where the request
// goes is the release's, not the server's table. The credential is the
// server's (or this proxy's local one) as before.
func (p *Proxy) signedRoute(release map[string]any, slug string, live Route) (Route, bool) {
	rel := p.enf.current()
	if rel == nil || release == nil {
		return Route{}, false
	}
	routes, _ := rel.Bundle["egress_routes"].(map[string]any)
	for _, v := range routes {
		r, _ := v.(map[string]any)
		if s, _ := r["slug"].(string); s != slug || r["enabled"] != true {
			continue
		}
		out := live
		out.UpstreamURL, _ = r["upstream_url"].(string)
		out.CredentialSource, _ = r["credential_source"].(string)
		out.AuthHeader, _ = r["auth_header"].(string)
		out.Methods, out.PathPrefixes = stringList(r["methods"]), stringList(r["path_prefixes"])
		if n, err := strconv.ParseInt(fmt.Sprint(r["max_body_bytes"]), 10, 64); err == nil && n < out.MaxBodyBytes {
			out.MaxBodyBytes = n
		}
		// where the credential comes from is what was signed; the credential
		// itself is opened here (a sealed one) or read from this proxy's configuration
		return out, true
	}
	return Route{}, false
}

func stringList(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// refuseUnderPolicy: the proxy refuses on its own; the refusal is recorded
// through the check (redeem with the proxy's verdict and receipt).
func (p *Proxy) refuseUnderPolicy(w http.ResponseWriter, ctx context.Context, checkID string, d Descriptor,
	fields map[string]any, verdict, why string) {
	if verdict != policy.PendingApproval {
		verdict = policy.Denied
	}
	enforcement := map[string]any{"decision": verdict, "reason": why}
	if p.wit != nil {
		rf := map[string]any{"output_sha256": nullSHA, "decision": verdict}
		for k, v := range fields {
			rf[k] = v
		}
		if receipt, err := p.wit.sign(rf); err == nil {
			enforcement["receipt"] = receipt
		} else {
			p.log.Error("provenza proxy: could not sign a receipt", "err", err)
		}
	}
	if _, err := p.srv.redeem(ctx, checkID, d, enforcement); err != nil {
		p.log.Warn("provenza proxy: could not record a refusal", "check", short(checkID), "err", err)
	}
	refuse(w, http.StatusForbidden, "provenza_denied", "Refused by the signed policy: "+why)
}

// nullSHA: the server's content_hash(None).
var nullSHA = func() string { s, _ := canon.SHA256(nil); return s }()

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (p *Proxy) serverFailure(w http.ResponseWriter, err error) {
	var se *serverError
	switch {
	case errors.As(err, &se) && se.Status == http.StatusUnauthorized:
		refuse(w, http.StatusUnauthorized, "provenza_unauthorized", "the agent key was not accepted")
	case errors.As(err, &se):
		refuse(w, http.StatusForbidden, "provenza_refused", fmt.Sprintf("Refused by Provenza: %v", se.Detail))
	default: // fail-closed
		p.log.Warn("provenza proxy: server unreachable; request not sent", "err", err)
		refuse(w, http.StatusServiceUnavailable, "provenza_unavailable", "Provenza is unreachable; the request was not sent")
	}
}

type hashingReader struct {
	r io.Reader
	h hash.Hash
	n int64
}

func (h *hashingReader) Read(b []byte) (int, error) {
	n, err := h.r.Read(b)
	h.h.Write(b[:n])
	h.n += int64(n)
	return n, err
}

// forward sends the request upstream and records what happened; fields
// (nil: none) is what the proxy's receipt names besides the outcome.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, route Route, path string, body []byte, checkID string,
	fields map[string]any, record recorder) {
	target := strings.TrimRight(route.UpstreamURL, "/") + path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	started := time.Now()
	report := func(status int, h *string, n int64, errCode string) {
		// the agent's request may be over; the record must still be written
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), p.cfg.ServerTimeout.Duration)
		defer cancel()
		var receipt map[string]any
		if p.wit != nil && fields != nil {
			output := map[string]any{"status": status, "response_sha256": h, "response_bytes": n}
			if errCode != "" {
				output["error"] = errCode
			}
			out, err := canon.Of(output)
			sha := ""
			if err == nil {
				sha, err = canon.SHA256(out)
			}
			rf := map[string]any{"output_sha256": sha, "decision": policy.Allowed}
			for k, v := range fields {
				rf[k] = v
			}
			if err == nil {
				receipt, err = p.wit.sign(rf)
			}
			if err != nil {
				p.log.Error("provenza proxy: could not sign a receipt", "check", short(checkID), "err", err)
			}
		}
		record(ctx, status, h, n, errCode, time.Since(started), receipt)
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, target, strings.NewReader(string(body)))
	if err != nil {
		report(0, nil, 0, "proxy.bad_upstream_url")
		refuse(w, http.StatusBadGateway, "provenza_upstream", "bad upstream URL")
		return
	}
	for k, vs := range r.Header {
		if forwardable(k) {
			for _, v := range vs {
				out.Header.Add(k, v)
			}
		}
	}
	switch {
	case sealedSource(route.CredentialSource):
		value, ok := p.credential(r.Context(), "route", route.ID.String(), out.URL.String())
		if !ok {
			p.log.Error("provenza proxy: no sealed credential for this proxy and upstream", "route", route.Slug,
				"upstream", origin(out.URL.String()))
			report(0, nil, 0, "proxy.sealed_credential_missing")
			refuse(w, http.StatusBadGateway, "provenza_credential",
				"this route's credential is not sealed to this proxy for this upstream (Egress -> Routes)")
			return
		}
		out.Header.Set(route.AuthHeader, value)
	case route.CredentialSource == "local":
		header, value, err := p.cfg.localSecret(route.Slug, route.AuthHeader, out.URL.String())
		if err != nil {
			p.log.Error("provenza proxy: local credential", "route", route.Slug, "err", err)
			report(0, nil, 0, "proxy.local_credential_missing")
			refuse(w, http.StatusBadGateway, "provenza_credential", "this route's credential is not configured on the proxy")
			return
		}
		out.Header.Set(header, value)
	}
	resp, err := p.upstream.Do(out)
	if err != nil {
		report(0, nil, 0, "upstream.unreachable")
		refuse(w, http.StatusBadGateway, "provenza_upstream", "the upstream could not be reached")
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		if forwardable(k) || http.CanonicalHeaderKey(k) == "Content-Length" {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
	}
	w.WriteHeader(resp.StatusCode)
	hr := &hashingReader{r: resp.Body, h: sha256.New()}
	_, copyErr := io.Copy(w, hr) // streamed: no size limit on what the agent receives, only hashed
	sum := hex.EncodeToString(hr.h.Sum(nil))
	var h *string
	if hr.n > 0 {
		h = &sum
	}
	code := ""
	if copyErr != nil {
		code = "proxy.response_interrupted"
	}
	report(resp.StatusCode, h, hr.n, code)
}

// short: enough of a check id to find it in the logs, never all of it.
func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
