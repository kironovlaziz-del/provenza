# Provenza Go SDK

Governed, signed and auditable actions for AI agents in Go.

```bash
go get github.com/kironovlaziz-del/provenza/sdk/go@latest     # Go >= 1.27
```

It uses only the standard library: Ed25519 is `crypto/ed25519`, and the
post-quantum ML-DSA-65 is `crypto/mldsa` (Go 1.27).

```go
import provenza "github.com/kironovlaziz-del/provenza/sdk/go"

agent, err := provenza.New(ctx, provenza.Config{Name: "billing-bot"}) // PROVENZA_URL, PROVENZA_TOKEN

sales, err := provenza.Call(ctx, agent, "db.read", map[string]any{"quarter": "Q3"},
	func(ctx context.Context) ([]Sale, error) { return db.Sales(ctx, "Q3") })
```

It behaves the same as the Python and JS SDKs and speaks the same bytes:
an identity file, a signature or a local audit log made by one is accepted
by the others and by the server. The repository's tests check this against
the real server.

## What happens on a call

In **connected** mode (when `PROVENZA_URL` is set):

1. The server checks the call: the agent's rights, policies, the Tool
   Registry, behaviour, and the breaker.
2. The function runs only if the call is allowed. Otherwise:
   - a refusal returns a `*provenza.DeniedError`;
   - `err.ApprovalRequired()` tells you a human decision is pending.

   In both cases the attempt is recorded.
3. The result is recorded and signed with the agent's key.

The SDK **fails closed**: if the server cannot be reached, `Call` returns
an `*UnavailableError` and the function does not run. Set
`Config.FailOpen` to run it anyway and log it locally.

```go
var denied *provenza.DeniedError
if errors.As(err, &denied) { ... denied.Reason, denied.ActionID ... }
```

The arguments (a map or a struct) are what policies inspect, so they must
marshal to a JSON object.

In **standalone** mode (no server), calls go to a local, signed,
hash-chained audit log. Only hashes are written, never content. You can
restrict which tools run with `AllowedTools`. Check the log with
`provenza.VerifyAuditLog`.

## Identity

An admin issues a one-time enrollment token in Provenza (**Agents → New
agent**). The keys are generated on the agent's side and stored in
`~/.config/provenza/agents/<name>.json` (mode 600, the shared format). The
file is refused if other users can read it, and never sent to a server
other than the one it was enrolled with.

`Config.Hybrid` adds an ML-DSA-65 key. `agent.Fingerprint()` is the value
to give whoever verifies the agent's signatures.

## More

```go
ctx = provenza.WithChain(ctx, chainID)                          // act inside a delegation chain
agent.Delegate(ctx, otherID, "summarize Q3", []string{"read"}, []string{"db.read"}, 10*time.Minute)
chk, err := agent.Check(ctx, "files.delete", map[string]any{"path": p})   // ask by hand
_, err = agent.Record(ctx, chk, map[string]any{"deleted": true}, elapsed)
```

With `Config.RecordMode = provenza.RecordBackground`, a call returns after
one round-trip and the records follow in order; `agent.Flush()` waits for
them. Refusals are always recorded before `Call` returns.

If a call ran but could not be recorded on the server, its result still
stands. A signed gap is written to the local log, and a warning goes to
`Config.Logger` (default `slog.Default()`).

## Provenza's gateways

```go
base, key, _ := provenza.LLMGateway(agent)        // any OpenAI-compatible client
url, headers, _ := provenza.MCPConnection(agent)  // point any MCP client at Provenza
```

The gateways hold the provider and MCP server credentials, so the agent
never has them, and every call is enforced on the server.

## Egress proxy

Behind a Provenza egress proxy (`proxy/` in the repository), the agent can
send its key and let the proxy check each request. Or it can check a
request itself and send the check id:

```go
chk, err := agent.ProxyCheck(ctx, "stripe", "POST", "/v1/charges", "", body)
req, _ := http.NewRequestWithContext(ctx, "POST", "http://127.0.0.1:8443/stripe/v1/charges", bytes.NewReader(body))
for k, v := range chk.ProxyHeaders() {
	req.Header.Set(k, v)
}
```

`path`, `query` and `body` must be exactly what goes on the wire; the proxy
refuses any other request under that check, and records it itself.

## HTTP tools through Provenza

An API registered in Provenza (**Gateways → HTTP tools**) is called through
Provenza, and the agent never holds its key:

```go
out, err := agent.Invoke(ctx, "crm.set_tier", map[string]any{"id": "42", "tier": "gold"})   // *DeniedError on a refusal
```

## Egress self-check

Is this host confined to the Provenza egress proxy, its only way out? Run
the check at start-up and then periodically. With **Require confined egress**
on, an agent acts only while its latest check is `confined`. See
`docs/egress-lockdown.md`.

```go
out, err := agent.EgressSelfcheck(ctx, 3*time.Second)   // out["verdict"]: "confined" | "open"
```

## Permits for tools

An allowed check carries `chk.Permit`, signed by the organization. Send it
to the tool with the checked input as the JSON body. A tool built with the
Python or JS SDK verifies it and runs nothing without it:

```go
for k, v := range chk.PermitHeaders() {
	req.Header.Set(k, v)
}
```

## What this is, and what it is not

The SDK runs inside your agent's process. It is the agent's honest record
and cooperative enforcement: code in the same process could act around
it. Enforcement that does not depend on the agent's code comes from the
gateways.
