// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package provenza

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Mode of an agent.
type Mode string

const (
	Connected  Mode = "connected"  // every call is checked and recorded by the server
	Standalone Mode = "standalone" // no server: calls go to the local signed audit log
)

// RecordMode chooses when a result is sent to the server.
type RecordMode string

const (
	RecordSync       RecordMode = "sync"       // the record is on the server when the call returns
	RecordBackground RecordMode = "background" // one round-trip on the hot path; Flush waits for the rest
)

// RecordRetries are the pauses before the 2nd and 3rd record attempt (the check lives 5 minutes).
var RecordRetries = []time.Duration{200 * time.Millisecond, time.Second}

// Config of an agent. Empty fields fall back to PROVENZA_URL, PROVENZA_TOKEN,
// PROVENZA_IDENTITY, PROVENZA_MODE and PROVENZA_AGENT_NAME.
type Config struct {
	Name            string
	ServerURL       string
	EnrollmentToken string // used once; afterwards the identity file is enough
	IdentityPath    string
	Mode            Mode
	Hybrid          bool     // add an ML-DSA-65 key next to Ed25519
	AllowedTools    []string // standalone only
	AuditLogPath    string
	FailOpen        bool // run without the server's check when it is unreachable (logged locally)
	RecordMode      RecordMode
	Timeout         time.Duration // per request, default 10s
	HTTPClient      *http.Client
	Logger          *slog.Logger // where gaps and fail-open runs are reported (default slog.Default())
}

// Agent governs, records and signs an AI agent's actions.
type Agent struct {
	name       string
	mode       Mode
	identity   *Identity
	client     *client
	log        *AuditLog
	failOpen   bool
	recordMode RecordMode
	allowed    map[string]bool
	logger     *slog.Logger
	queue      chan func()
	pending    sync.WaitGroup
	startOnce  sync.Once
}

func env(v, key string) string {
	if v != "" {
		return v
	}
	return os.Getenv(key)
}

// New loads (or creates, or enrolls) the agent's identity.
func New(ctx context.Context, cfg Config) (*Agent, error) {
	name := env(cfg.Name, "PROVENZA_AGENT_NAME")
	if name == "" {
		name = "agent"
	}
	serverURL := env(cfg.ServerURL, "PROVENZA_URL")
	token := env(cfg.EnrollmentToken, "PROVENZA_TOKEN")
	mode := Mode(env(string(cfg.Mode), "PROVENZA_MODE"))
	if mode == "" {
		mode = Standalone
		if serverURL != "" {
			mode = Connected
		}
	}
	if mode != Connected && mode != Standalone {
		return nil, &ConfigError{"Mode must be connected or standalone"}
	}
	recordMode := cfg.RecordMode
	if recordMode == "" {
		recordMode = RecordSync
	}
	if recordMode != RecordSync && recordMode != RecordBackground {
		return nil, &ConfigError{"RecordMode must be sync or background"}
	}
	path := env(cfg.IdentityPath, "PROVENZA_IDENTITY")
	if path == "" {
		path = DefaultIdentityPath(name)
	}
	logPath := cfg.AuditLogPath
	if logPath == "" {
		logPath = strings.TrimSuffix(path, ".json") + ".audit.jsonl"
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	identity, err := LoadIdentity(path)
	if err != nil {
		return nil, err
	}
	a := &Agent{name: name, mode: mode, failOpen: cfg.FailOpen, recordMode: recordMode, logger: logger}
	if cfg.AllowedTools != nil {
		a.allowed = map[string]bool{}
		for _, t := range cfg.AllowedTools {
			a.allowed[t] = true
		}
	}

	if mode == Standalone {
		if identity == nil {
			keys, err := GenerateKeys(cfg.Hybrid)
			if err != nil {
				return nil, err
			}
			identity = &Identity{Keys: keys, Name: name}
			if err := SaveIdentity(identity, path); err != nil {
				return nil, err
			}
		}
	} else {
		if serverURL == "" && identity != nil {
			serverURL = identity.Server
		}
		serverURL = strings.TrimRight(serverURL, "/")
		if serverURL == "" {
			return nil, &ConfigError{"connected mode needs ServerURL (or PROVENZA_URL)"}
		}
		if identity != nil && identity.Server != "" && strings.TrimRight(identity.Server, "/") != serverURL {
			// never present this agent's key to a server it was not enrolled with
			return nil, &ConfigError{fmt.Sprintf("%s belongs to %s, not %s", path, identity.Server, serverURL)}
		}
		if identity == nil || identity.AgentID == nil {
			if token == "" {
				return nil, &ConfigError{"this agent is not enrolled: set EnrollmentToken (or PROVENZA_TOKEN), " +
					"issued in Provenza under Agents -> New agent"}
			}
			c, err := newClient(serverURL, "", timeout, cfg.HTTPClient)
			if err != nil {
				return nil, err
			}
			if identity, err = enroll(ctx, c, token, name, cfg.Hybrid); err != nil {
				return nil, err
			}
			if err := SaveIdentity(identity, path); err != nil {
				return nil, err
			}
		}
		if a.client, err = newClient(serverURL, identity.APIKey, timeout, cfg.HTTPClient); err != nil {
			return nil, err
		}
	}
	a.identity = identity
	a.log = &AuditLog{Path: logPath, keys: identity.Keys, agent: name}
	return a, nil
}

// Mode the agent runs in.
func (a *Agent) Mode() Mode { return a.mode }

// AgentID on the server (nil in standalone mode).
func (a *Agent) AgentID() *int64 { return a.identity.AgentID }

// Fingerprint of the agent's key - give it to whoever verifies its signatures.
func (a *Agent) Fingerprint() string { return a.identity.Keys.Fingerprint() }

// Identity of the agent.
func (a *Agent) Identity() *Identity { return a.identity }

// AuditLog is the local log (standalone mode, gaps, fail-open runs).
func (a *Agent) AuditLog() *AuditLog { return a.log }

// Credentials are the server URL and agent key, for clients of Provenza's gateways.
func (a *Agent) Credentials() (serverURL, apiKey string, err error) {
	if a.client == nil || a.client.apiKey == "" {
		return "", "", &ConfigError{"this needs a connected, enrolled agent"}
	}
	return a.client.serverURL, a.client.apiKey, nil
}

// --- chains ---------------------------------------------------------------------

type chainKey struct{}

// WithChain makes governed calls under ctx act within this delegation chain.
func WithChain(ctx context.Context, chainID int64) context.Context {
	return context.WithValue(ctx, chainKey{}, chainID)
}

func chainOf(ctx context.Context) *int64 {
	if id, ok := ctx.Value(chainKey{}).(int64); ok {
		return &id
	}
	return nil
}

// --- the protocol -----------------------------------------------------------------

// Check is the server's verdict for one proposed call, bound to it.
type Check struct {
	CheckID      string
	Decision     string // allowed | denied | pending_approval
	Reason       string
	Tool         string
	ActionType   string
	Input        any // the arguments as the server received them
	ChainID      *int64
	IncidentType string
	PolicyID     *int64
}

// Allowed tells whether the call may run.
func (c *Check) Allowed() bool { return c.Decision == "allowed" }

type callOptions struct {
	actionType string
	outputOf   func(any) any
	version    string
	digest     string
}

// Option adjusts one governed call.
type Option func(*callOptions)

// WithActionType sets the action type (default tool_call).
func WithActionType(t string) Option { return func(o *callOptions) { o.actionType = t } }

// WithOutput chooses what is recorded of a result (default: the result).
func WithOutput(f func(any) any) Option { return func(o *callOptions) { o.outputOf = f } }

// WithToolVersion reports the tool's version and manifest digest (Tool Registry pins).
func WithToolVersion(version, digest string) Option {
	return func(o *callOptions) { o.version, o.digest = version, digest }
}

func options(opts []Option) callOptions {
	o := callOptions{actionType: "tool_call"}
	for _, f := range opts {
		f(&o)
	}
	return o
}

// argsObject is the call's arguments as the server will receive them: a JSON object.
func argsObject(args any) (map[string]any, error) {
	if args == nil {
		return map[string]any{}, nil
	}
	v, err := toJSON(args)
	if err != nil {
		return nil, fmt.Errorf("provenza: tool arguments: %w", err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("provenza: tool arguments must be a JSON object (a map or a struct) - that is what policies inspect")
	}
	return m, nil
}

func asOutput(result any) any {
	if result == nil {
		return nil
	}
	v, err := toJSON(result)
	if err != nil {
		s := fmt.Sprint(result)
		if len(s) > 2000 {
			s = s[:2000]
		}
		return map[string]any{"repr": s}
	}
	if v == nil {
		return nil
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{"result": v}
}

func (a *Agent) connected() (*client, error) {
	if a.client == nil {
		return nil, &ConfigError{"this needs connected mode"}
	}
	return a.client, nil
}

func (a *Agent) check(ctx context.Context, tool string, input map[string]any, o callOptions) (*Check, error) {
	c, err := a.connected()
	if err != nil {
		return nil, err
	}
	chain := chainOf(ctx)
	body := map[string]any{"agent_id": a.AgentID(), "chain_id": chain, "action_type": o.actionType,
		"tool_name": tool, "input": input}
	if o.version != "" {
		body["tool_version"] = o.version
	}
	if o.digest != "" {
		body["tool_digest"] = o.digest
	}
	res, err := c.post(ctx, "/agents/actions/check", body, true)
	if err != nil {
		return nil, err
	}
	return &Check{CheckID: str(res, "check_id"), Decision: str(res, "decision"), Reason: str(res, "reason"), Tool: tool,
		ActionType: o.actionType, Input: input, ChainID: chain, IncidentType: str(res, "incident_type"),
		PolicyID: optInt(res, "policy_id")}, nil
}

// Check asks before doing something that is not governed through Call.
func (a *Agent) Check(ctx context.Context, tool string, args any, opts ...Option) (*Check, error) {
	input, err := argsObject(args)
	if err != nil {
		return nil, err
	}
	return a.check(ctx, tool, input, options(opts))
}

// Record records what was done under a check (once); it retries a server that is down.
func (a *Agent) Record(ctx context.Context, chk *Check, output any, duration time.Duration) (map[string]any, error) {
	c, err := a.connected()
	if err != nil {
		return nil, err
	}
	out := asOutput(output)
	inHash, err := ContentHash(chk.Input)
	if err != nil {
		return nil, err
	}
	outHash, err := ContentHash(out)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{"check_id": chk.CheckID, "agent_id": a.AgentID(), "chain_id": chk.ChainID,
		"action_type": chk.ActionType, "tool_name": chk.Tool, "input_sha256": inHash, "output_sha256": outHash}
	sig, pq, err := a.identity.Keys.Sign(payload)
	if err != nil {
		return nil, err
	}
	var dur *int64
	if duration > 0 {
		ms := duration.Milliseconds()
		dur = &ms
	}
	body := map[string]any{"agent_id": a.AgentID(), "chain_id": chk.ChainID, "action_type": chk.ActionType,
		"tool_name": chk.Tool, "input": chk.Input, "output": out, "duration_ms": dur, "check_id": chk.CheckID,
		"signature": sig, "pq_signature": nilIfEmpty(pq)}
	pauses := append([]time.Duration{0}, RecordRetries...)
	for attempt, pause := range pauses {
		if pause > 0 {
			select {
			case <-time.After(pause):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		res, err := c.post(ctx, "/agents/actions/record", body, true)
		if err == nil {
			return res, nil
		}
		var unavailable *UnavailableError
		var refused *RequestError
		if errors.As(err, &unavailable) && attempt < len(pauses)-1 {
			continue
		}
		if errors.As(err, &refused) && refused.Status == 409 && attempt > 0 {
			return map[string]any{"check_id": chk.CheckID, "note": "recorded by an earlier attempt"}, nil
		}
		return nil, err
	}
	return nil, errors.New("unreachable")
}

// Delegate hands a task and a subset of this agent's rights to another agent
// (signed, single-use nonce). Tools nil = the delegating agent's own tools.
func (a *Agent) Delegate(ctx context.Context, toAgentID int64, task string, capabilities, tools []string,
	expiresIn time.Duration) (map[string]any, error) {
	c, err := a.connected()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	caps := append([]string{}, capabilities...)
	sorted := append([]string{}, caps...)
	sort.Strings(sorted)
	var exp any
	if expiresIn > 0 {
		exp = int64(expiresIn / time.Second)
	}
	payload := map[string]any{"from_agent_id": a.AgentID(), "to_agent_id": toAgentID, "task": task,
		"delegated_capabilities": sorted, "chain_id": chainOf(ctx), "nonce": hex.EncodeToString(nonce),
		"issued_at": time.Now().Unix(), "expires_in": exp}
	var delegatedTools any
	if tools != nil {
		set := map[string]bool{}
		uniq := []string{}
		for _, t := range tools {
			if !set[t] {
				set[t] = true
				uniq = append(uniq, t)
			}
		}
		sort.Strings(uniq)
		payload["delegated_tools"] = uniq
		delegatedTools = tools
	}
	sig, pq, err := a.identity.Keys.Sign(payload)
	if err != nil {
		return nil, err
	}
	return c.post(ctx, fmt.Sprintf("/agents/%d/delegate", *a.AgentID()), map[string]any{
		"to_agent_id": toAgentID, "task": task, "delegated_capabilities": caps, "delegated_tools": delegatedTools,
		"chain_id": payload["chain_id"], "nonce": payload["nonce"], "issued_at": payload["issued_at"],
		"expires_in": exp, "signature": sig, "pq_signature": nilIfEmpty(pq)}, true)
}

// --- the governed path ------------------------------------------------------------

// Call governs one call: check, run fn only if allowed, record. args (a map or a
// struct) is what policies inspect. A refusal is a *DeniedError, the server
// unreachable an *UnavailableError - in both cases fn did not run.
func Call[T any](ctx context.Context, a *Agent, tool string, args any, fn func(context.Context) (T, error),
	opts ...Option) (T, error) {
	var zero T
	o := options(opts)
	input, err := argsObject(args)
	if err != nil {
		return zero, err
	}
	out := func(r any) any {
		if o.outputOf != nil {
			return asOutput(o.outputOf(r))
		}
		return asOutput(r)
	}

	if a.mode == Standalone {
		if a.allowed != nil && !a.allowed[tool] {
			reason := "not in this agent's AllowedTools (standalone)"
			if _, err := a.local(tool, o.actionType, input, nil, 0, "denied", reason); err != nil {
				return zero, err
			}
			return zero, &DeniedError{Tool: tool, Reason: reason, Decision: "denied"}
		}
		return runLocal(ctx, a, tool, o.actionType, input, fn, out, "recorded")
	}

	chk, err := a.check(ctx, tool, input, o)
	if err != nil {
		var unavailable *UnavailableError
		if errors.As(err, &unavailable) && a.failOpen {
			a.logger.Warn("provenza: server unreachable, running unchecked (FailOpen)", "tool", tool)
			return runLocal(ctx, a, tool, o.actionType, input, fn, out, "unchecked")
		}
		return zero, err
	}
	if !chk.Allowed() {
		res := a.tryRecord(ctx, chk, nil, 0)
		return zero, &DeniedError{Tool: tool, Reason: chk.Reason, Decision: chk.Decision,
			IncidentType: chk.IncidentType, CheckID: chk.CheckID, ActionID: optInt(res, "id")}
	}
	started := time.Now()
	result, err := fn(ctx)
	if err != nil {
		a.recordAfter(ctx, chk, map[string]any{"error": fmt.Sprintf("%T", err)}, time.Since(started))
		return result, err
	}
	a.recordAfter(ctx, chk, out(result), time.Since(started))
	return result, nil
}

func runLocal[T any](ctx context.Context, a *Agent, tool, actionType string, input map[string]any,
	fn func(context.Context) (T, error), out func(any) any, status string) (T, error) {
	started := time.Now()
	result, err := fn(ctx)
	var output any
	if err != nil {
		output = map[string]any{"error": fmt.Sprintf("%T", err)}
	} else {
		output = out(result)
	}
	if _, lerr := a.local(tool, actionType, input, output, time.Since(started), status, ""); lerr != nil && err == nil {
		err = lerr
	}
	return result, err
}

func (a *Agent) local(tool, actionType string, input, output any, d time.Duration, status, reason string) (map[string]any, error) {
	in, err := ContentHash(input)
	if err != nil {
		return nil, err
	}
	o, err := ContentHash(output)
	if err != nil {
		return nil, err
	}
	return a.log.Append(map[string]any{"status": status, "tool": tool, "action_type": actionType,
		"input_sha256": in, "output_sha256": o, "duration_ms": d.Milliseconds(), "reason": reason})
}

func (a *Agent) recordAfter(ctx context.Context, chk *Check, output any, d time.Duration) {
	if a.recordMode != RecordBackground {
		a.tryRecord(ctx, chk, output, d)
		return
	}
	a.startOnce.Do(func() {
		a.queue = make(chan func(), 1024)
		go func() { // one worker: records are sent in order
			for job := range a.queue {
				job()
			}
		}()
	})
	a.pending.Add(1)
	detached := context.WithoutCancel(ctx) // the call has returned; its context may be cancelled
	a.queue <- func() {
		defer a.pending.Done()
		a.tryRecord(detached, chk, output, d)
	}
}

// tryRecord records, or writes a signed gap to the local log when the server cannot.
func (a *Agent) tryRecord(ctx context.Context, chk *Check, output any, d time.Duration) map[string]any {
	res, err := a.Record(ctx, chk, output, d)
	if err == nil {
		return res
	}
	in, _ := ContentHash(chk.Input)
	out, _ := ContentHash(asOutput(output))
	reason := err.Error()
	if len(reason) > 200 {
		reason = reason[:200]
	}
	if _, lerr := a.log.Append(map[string]any{"status": "unrecorded", "tool": chk.Tool, "action_type": chk.ActionType,
		"check_id": chk.CheckID, "input_sha256": in, "output_sha256": out, "duration_ms": d.Milliseconds(),
		"reason": reason}); lerr != nil {
		a.logger.Error("provenza: could not write the gap to the local audit log", "tool", chk.Tool, "err", lerr)
	}
	a.logger.Warn("provenza: the call ran but could not be recorded on the server; the gap is in the local audit log",
		"tool", chk.Tool, "log", a.log.Path, "err", err)
	return nil
}

// Flush waits for background records.
func (a *Agent) Flush() { a.pending.Wait() }

// Close flushes background records.
func (a *Agent) Close() error {
	a.Flush()
	return nil
}
