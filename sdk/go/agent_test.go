// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package provenza

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fake is an in-memory Provenza that verifies signatures for real.
type fake struct {
	mu             sync.Mutex
	verdicts       map[string]string
	checks         map[string]map[string]any
	order          []string
	records        []map[string]any
	down           map[string]bool
	recordFailures int
	publicKey      string
	nonces         map[string]bool
	n              int
	srv            *httptest.Server
}

func newFake(t *testing.T) *fake {
	f := &fake{verdicts: map[string]string{}, checks: map[string]map[string]any{}, down: map[string]bool{},
		nonces: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fake) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if f.down[path] {
		reply(w, 503, map[string]any{"detail": "down"})
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	_ = dec.Decode(&body)
	switch {
	case path == "/agent-enrollment/challenge":
		reply(w, 200, map[string]any{"challenge": strings.Repeat("c", 32), "org_id": 1, "enrollment_id": 7, "name": nil,
			"require_hybrid": false})
		return
	case path == "/agent-enrollment/enroll":
		name, _ := body["name"].(string)
		statement := map[string]any{"type": "provenza.agent.enroll", "v": 1, "challenge": strings.Repeat("c", 32),
			"org_id": 1, "enrollment_id": 7, "public_key": body["public_key"], "pq_public_key": nil, "name": name}
		pub, _ := body["public_key"].(string)
		sig, _ := body["signature"].(string)
		if !verifySignatures(statement, sig, "", pub, "") {
			reply(w, 400, map[string]any{"detail": "bad enrollment signature"})
			return
		}
		f.publicKey = pub
		fp, _ := Fingerprint(pub, "")
		reply(w, 200, map[string]any{"agent_id": 42, "api_key": "pvz_agent_key", "name": name, "key_fingerprint": fp})
		return
	}
	if r.Header.Get("X-Agent-Key") != "pvz_agent_key" {
		reply(w, 401, map[string]any{"detail": "agent_identity.invalid_key"})
		return
	}
	switch {
	case path == "/agents/actions/check":
		// what the server verifies: the agent's signature over the request, a fresh nonce
		inHash, _ := ContentHash(body["input"])
		payload := map[string]any{"type": "action.request", "agent_id": body["agent_id"], "chain_id": body["chain_id"],
			"action_type": body["action_type"], "tool_name": body["tool_name"], "input_sha256": inHash,
			"tool_version": body["tool_version"], "tool_digest": body["tool_digest"], "nonce": body["nonce"],
			"issued_at": body["issued_at"]}
		sig, _ := body["signature"].(string)
		nonce, _ := body["nonce"].(string)
		if !verifySignatures(payload, sig, "", f.publicKey, "") || nonce == "" || f.nonces[nonce] {
			reply(w, 401, map[string]any{"detail": "action.invalid_signature"})
			return
		}
		f.nonces[nonce] = true
		f.n++
		token := fmt.Sprintf("chk_%040d", f.n)
		decision := f.verdicts[body["tool_name"].(string)]
		if decision == "" {
			decision = "allowed"
		}
		body["decision"] = decision
		f.checks[token] = body
		f.order = append(f.order, token)
		out := map[string]any{"decision": decision, "reason": "policy says " + decision, "check_id": token}
		if decision == "allowed" {
			out["permit"] = "permit-of-" + token
		}
		reply(w, 200, out)
	case path == "/http-tools/call":
		// the HTTP tool gateway: the same signed request; it checks, calls and records itself
		inHash, _ := ContentHash(body["input"])
		payload := map[string]any{"type": "action.request", "agent_id": body["agent_id"], "chain_id": body["chain_id"],
			"action_type": body["action_type"], "tool_name": body["tool_name"], "input_sha256": inHash,
			"tool_version": nil, "tool_digest": nil, "nonce": body["nonce"], "issued_at": body["issued_at"]}
		sig, _ := body["signature"].(string)
		if !verifySignatures(payload, sig, "", f.publicKey, "") {
			reply(w, 401, map[string]any{"detail": "action.invalid_signature"})
			return
		}
		decision := f.verdicts[body["tool_name"].(string)]
		if decision == "" {
			reply(w, 200, map[string]any{"decision": "allowed", "action_id": 9, "status": 200,
				"body": map[string]any{"echo": body["input"]}})
			return
		}
		reply(w, 200, map[string]any{"decision": decision, "reason": "policy says " + decision, "action_id": 10})
	case path == "/agents/actions/record":
		if f.recordFailures > 0 {
			f.recordFailures--
			reply(w, 503, map[string]any{"detail": "down"})
			return
		}
		token, _ := body["check_id"].(string)
		chk := f.checks[token]
		if chk == nil {
			reply(w, 404, map[string]any{"detail": "Unknown check_id"})
			return
		}
		if chk["used"] == true {
			reply(w, 409, map[string]any{"detail": "check_id already used"})
			return
		}
		inHash, _ := ContentHash(body["input"])
		outHash, _ := ContentHash(body["output"])
		payload := map[string]any{"check_id": token, "agent_id": body["agent_id"], "chain_id": body["chain_id"],
			"action_type": body["action_type"], "tool_name": body["tool_name"], "input_sha256": inHash, "output_sha256": outHash}
		sig, _ := body["signature"].(string)
		if !verifySignatures(payload, sig, "", f.publicKey, "") {
			reply(w, 400, map[string]any{"detail": "Invalid action signature"})
			return
		}
		chk["used"] = true
		f.records = append(f.records, body)
		reply(w, 200, map[string]any{"id": len(f.records), "policy_check_result": chk["decision"]})
	case strings.HasSuffix(path, "/delegate"):
		caps := []string{}
		for _, c := range body["delegated_capabilities"].([]any) {
			caps = append(caps, c.(string))
		}
		sort.Strings(caps)
		payload := map[string]any{"from_agent_id": 42, "to_agent_id": body["to_agent_id"], "task": body["task"],
			"delegated_capabilities": caps, "chain_id": body["chain_id"], "nonce": body["nonce"],
			"issued_at": body["issued_at"], "expires_in": body["expires_in"]}
		if tools, ok := body["delegated_tools"].([]any); ok {
			set := map[string]bool{}
			uniq := []string{}
			for _, t := range tools {
				if !set[t.(string)] {
					set[t.(string)] = true
					uniq = append(uniq, t.(string))
				}
			}
			sort.Strings(uniq)
			payload["delegated_tools"] = uniq
		}
		sig, _ := body["signature"].(string)
		reply(w, 200, map[string]any{"chain_id": 5, "verified": verifySignatures(payload, sig, "", f.publicKey, "")})
	default:
		reply(w, 404, map[string]any{"detail": "not found"})
	}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func connected(t *testing.T, f *fake, mutate ...func(*Config)) *Agent {
	t.Helper()
	cfg := Config{Name: "billing-bot", ServerURL: f.srv.URL, EnrollmentToken: "pvz_enr_" + strings.Repeat("x", 20),
		IdentityPath: filepath.Join(t.TempDir(), "id.json"), Logger: quiet()}
	for _, m := range mutate {
		m(&cfg)
	}
	a, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestEnrollsOnceIntoAPrivateSharedFormatFile(t *testing.T) {
	f := newFake(t)
	a := connected(t, f)
	if *a.AgentID() != 42 || f.publicKey != a.Identity().Keys.PublicKey {
		t.Fatal("not enrolled with the generated key")
	}
	idPath := filepath.Join(filepath.Dir(a.AuditLog().Path), "id.json")
	st, _ := os.Stat(idPath)
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	raw, _ := os.ReadFile(idPath)
	for _, k := range []string{"server", "agent_id", "api_key", "private_key", "public_key", "pq_private_key", "pq_public_key", "key_fingerprint"} {
		if !strings.Contains(string(raw), `"`+k+`"`) {
			t.Errorf("identity file lacks %s", k)
		}
	}
	again, err := New(context.Background(), Config{ServerURL: f.srv.URL, IdentityPath: idPath, Logger: quiet()})
	if err != nil || again.Fingerprint() != a.Fingerprint() {
		t.Fatalf("reload: %v", err)
	}
	_, err = New(context.Background(), Config{ServerURL: "https://evil.test", IdentityPath: idPath})
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) || !strings.Contains(err.Error(), "belongs to") {
		t.Fatalf("an identity must never go to another server: %v", err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(idPath, 0o644)
		if _, err := LoadIdentity(idPath); err == nil || !strings.Contains(err.Error(), "readable by other users") {
			t.Fatalf("a world-readable identity must be refused: %v", err)
		}
	}
}

func TestNotEnrolledWithoutAToken(t *testing.T) {
	_, err := New(context.Background(), Config{ServerURL: "https://p.test", IdentityPath: filepath.Join(t.TempDir(), "x.json")})
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("got %v", err)
	}
}

type query struct {
	Query string `json:"query"`
	Limit int    `json:"limit"`
}

func TestAllowedCallRunsAndIsRecordedSigned(t *testing.T) {
	f := newFake(t)
	a := connected(t, f)
	rows, err := Call(context.Background(), a, "db.read", query{Query: "select 1", Limit: 10},
		func(ctx context.Context) ([]int, error) { return []int{1, 2, 3}, nil })
	if err != nil || len(rows) != 3 {
		t.Fatal(rows, err)
	}
	chk := f.checks[f.order[0]]
	if chk["tool_name"] != "db.read" || chk["input"].(map[string]any)["query"] != "select 1" {
		t.Fatal(chk)
	}
	if len(f.records) != 1 { // the fake verified the signature
		t.Fatal("not recorded")
	}
}

func TestDeniedCallDoesNotRunAndIsRecorded(t *testing.T) {
	f := newFake(t)
	f.verdicts["stripe.charge"] = "denied"
	a := connected(t, f)
	ran := false
	_, err := Call(context.Background(), a, "stripe.charge", map[string]any{"amount": 100},
		func(ctx context.Context) (any, error) { ran = true; return nil, nil })
	var denied *DeniedError
	if !errors.As(err, &denied) || ran || denied.ActionID == nil || *denied.ActionID != 1 || denied.ApprovalRequired() {
		t.Fatalf("err=%v ran=%v", err, ran)
	}
	if f.records[0]["output"] != nil {
		t.Fatal("a refused attempt has no output")
	}
}

func TestPendingApprovalIsADenialOfItsOwnKind(t *testing.T) {
	f := newFake(t)
	f.verdicts["email.send"] = "pending_approval"
	a := connected(t, f)
	_, err := Call(context.Background(), a, "email.send", nil, func(ctx context.Context) (any, error) {
		t.Fatal("must not run")
		return nil, nil
	})
	var denied *DeniedError
	if !errors.As(err, &denied) || !denied.ApprovalRequired() {
		t.Fatal(err)
	}
}

func TestFailingToolIsRecordedByTypeOnly(t *testing.T) {
	f := newFake(t)
	a := connected(t, f)
	_, err := Call(context.Background(), a, "db.read", nil, func(ctx context.Context) (any, error) {
		return nil, errors.New("secret dsn")
	})
	if err == nil || f.records[0]["output"].(map[string]any)["error"] != "*errors.errorString" {
		t.Fatal(err, f.records)
	}
}

func TestFailClosedAndFailOpen(t *testing.T) {
	f := newFake(t)
	f.down["/agents/actions/check"] = true
	a := connected(t, f)
	ran := false
	_, err := Call(context.Background(), a, "db.read", nil, func(ctx context.Context) (any, error) { ran = true; return nil, nil })
	var unavailable *UnavailableError
	if !errors.As(err, &unavailable) || ran {
		t.Fatal("must fail closed")
	}
	open := connected(t, f, func(c *Config) { c.FailOpen = true })
	if v, err := Call(context.Background(), open, "db.read", nil, func(ctx context.Context) (int, error) { return 7, nil }); err != nil || v != 7 {
		t.Fatal(v, err)
	}
	entries, _ := open.AuditLog().Entries()
	if entries[len(entries)-1]["status"] != "unchecked" {
		t.Fatal(entries)
	}
}

func TestRecordRetriesAndALastingFailureIsASignedGap(t *testing.T) {
	saved := RecordRetries
	RecordRetries = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { RecordRetries = saved })
	f := newFake(t)
	a := connected(t, f)
	call := func() (map[string]any, error) {
		return Call(context.Background(), a, "db.read", nil, func(ctx context.Context) (map[string]any, error) {
			return map[string]any{"ok": true}, nil
		})
	}
	f.recordFailures = 2
	if _, err := call(); err != nil || len(f.records) != 1 {
		t.Fatal(err)
	}
	f.recordFailures = 3
	if r, err := call(); err != nil || r["ok"] != true { // the tool ran: its result stands
		t.Fatal(err)
	}
	entries, _ := a.AuditLog().Entries()
	if entries[len(entries)-1]["status"] != "unrecorded" {
		t.Fatal(entries)
	}
	if problems, _ := VerifyAuditLog(a.AuditLog().Path, a.Identity().Keys.PublicKey, ""); len(problems) != 0 {
		t.Fatal(problems)
	}
}

func TestArgumentsMustBeAJSONObject(t *testing.T) {
	f := newFake(t)
	a := connected(t, f)
	for _, bad := range []any{[]int{1, 2}, "text", map[string]any{"ch": make(chan int)}} {
		if _, err := Call(context.Background(), a, "db.read", bad, func(ctx context.Context) (any, error) { return nil, nil }); err == nil {
			t.Errorf("%T accepted", bad)
		}
	}
	if len(f.checks) != 0 {
		t.Fatal("nothing must reach the server")
	}
}

func TestChainsDelegationAndBackgroundRecords(t *testing.T) {
	f := newFake(t)
	a := connected(t, f, func(c *Config) { c.RecordMode = RecordBackground })
	read := func(ctx context.Context, i int) {
		if _, err := Call(ctx, a, "db.read", map[string]any{"i": i}, func(ctx context.Context) (int, error) { return i, nil }); err != nil {
			t.Fatal(err)
		}
	}
	read(WithChain(context.Background(), 9), 1)
	read(context.Background(), 2)
	a.Flush()
	if f.checks[f.order[0]]["chain_id"].(json.Number) != "9" || f.checks[f.order[1]]["chain_id"] != nil {
		t.Fatal("chain")
	}
	if len(f.records) != 2 || f.records[0]["output"].(map[string]any)["result"].(json.Number) != "1" {
		t.Fatal("background records in order", f.records)
	}
	res, err := a.Delegate(context.Background(), 7, "summarize", []string{"read"}, []string{"db.read", "db.read"}, 10*time.Minute)
	if err != nil || res["verified"] != true {
		t.Fatal(res, err)
	}
}

func TestGatewaySettings(t *testing.T) {
	f := newFake(t)
	a := connected(t, f)
	base, key, _ := LLMGateway(a)
	url, headers, _ := MCPConnection(a)
	if base != f.srv.URL+GatewayPath || key != "pvz_agent_key" || url != f.srv.URL+MCPPath ||
		headers["Authorization"] != "Bearer pvz_agent_key" {
		t.Fatal(base, key, url, headers)
	}
}

func TestStandaloneSignedLogAndTampering(t *testing.T) {
	dir := t.TempDir()
	a, err := New(context.Background(), Config{Name: "solo", IdentityPath: filepath.Join(dir, "solo.json"),
		AllowedTools: []string{"calc.add"}})
	if err != nil || a.Mode() != Standalone {
		t.Fatal(err)
	}
	if v, err := Call(context.Background(), a, "calc.add", map[string]int{"x": 1, "y": 2},
		func(ctx context.Context) (int, error) { return 3, nil }); err != nil || v != 3 {
		t.Fatal(v, err)
	}
	var denied *DeniedError
	if _, err := Call(context.Background(), a, "shell.run", map[string]string{"cmd": "rm -rf /"},
		func(ctx context.Context) (int, error) { return 0, nil }); !errors.As(err, &denied) {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(a.AuditLog().Path)
	if strings.Contains(string(raw), "rm -rf") {
		t.Fatal("content in the log")
	}
	if problems, _ := VerifyAuditLog(a.AuditLog().Path, a.Identity().Keys.PublicKey, ""); len(problems) != 0 {
		t.Fatal(problems)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	edited := strings.Replace(lines[0], `"tool":"calc.add"`, `"tool":"calc.sub"`, 1)
	_ = os.WriteFile(a.AuditLog().Path, []byte(edited+"\n"+lines[1]+"\n"), 0o600)
	problems, _ := VerifyAuditLog(a.AuditLog().Path, a.Identity().Keys.PublicKey, "")
	if len(problems) == 0 || !strings.HasPrefix(problems[0], "line 1") {
		t.Fatal(problems)
	}
}

func TestHybridKeysSignAndVerify(t *testing.T) {
	k, err := GenerateKeys(true)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"a": 1, "s": "é\U0001F600", "f": 1e-7}
	sig, pq, err := k.Sign(payload)
	if err != nil || pq == "" || !verifySignatures(payload, sig, pq, k.PublicKey, k.PQPublicKey) {
		t.Fatal(err)
	}
	payload["a"] = 2
	if verifySignatures(payload, sig, pq, k.PublicKey, k.PQPublicKey) {
		t.Fatal("a changed payload must not verify")
	}
}
