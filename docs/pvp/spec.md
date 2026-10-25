# PVP — Provenza Verification Protocol, version `pvp/1`

PVP is the single internal language of agent governance in Provenza. Every
inbound protocol is translated into PVP messages, the orchestrator understands
nothing else, and every outbound format is produced from PVP records.

```
 REST · MCP · Google A2A                    REST · MCP · A2A · TRACE export
          │                                              ▲
          ▼                                              │
   inbound adapter ──► Input Guard ──► PVP ──► orchestrator ──► executors
   (parse only)        (reject early)          (identity, nonce, rights,
                                                TTL, policy, check, audit)
```

- **Adapters** translate formats. They execute nothing, hold no credentials
  and keep no state.
- **Input Guard** runs before a request becomes a PVP message. If it refuses
  the request, the request never becomes a PVP message.
- **Orchestrator** is the only component that judges a message: identity,
  replay, rights, lifetime, policy, check issuance and audit.
- **Executors** are the only components that act. Today these are the LLM
  gateway and, from P4, the MCP gateway. Only executors hold credentials.

Reference implementation: `backend/app/pvp/model.py`.
JSON Schemas: [`schemas/`](schemas/), generated from that model and tested
against it. An SDK in any language validates against those files.

Status: P1 (this document and the model), P2 (the orchestrator,
`backend/app/pvp/orchestrator.py`, behind the REST endpoints), P3 (the
Input Guard, `backend/app/pvp/guard.py`), P4 (the MCP gateway, §5.1), P5
(the A2A gateway, §5.2) and P6 (receipts §3.4, the TRACE export §5.3) are
complete.

A schema says what is **well-formed** (types, sizes, formats). What is
**allowed** is decided by the orchestrator, which knows the agent: a signed
request without a nonce or `check_id`, a keyed agent that does not sign,
self-delegation. Each of these refusals keeps its own error code.

---

## 1. Conventions

Every message is a JSON object (RFC 8259) with two fixed members:

| member | value |
|---|---|
| `pvp`  | `"pvp/1"`: the protocol version. Any other value is refused |
| `type` | the message type; it selects the schema (see §3) |

Every message follows these rules:

1. **Unknown members are refused.** A field that one side signs and the
   other side silently drops is how signature-confusion bugs start. Adding
   a member requires a new protocol version.
2. **Integers are strict.** `5` is an id. `"5"`, `5.0` and `true` are not
   ids. Ids are positive 32-bit integers.
3. **Time is integer Unix seconds** (`0 … 2^53-1`). The only exception is
   inside an audit checkpoint (`checkpoint.issued_at`), because its signed
   statement defines its own format.
4. **Numbers in hashed data are finite.** Tool `input` and `output` may hold
   any JSON value except NaN and ±Infinity.
5. **Messages are immutable** once built: verifiers compare them as values.

Limits enforced by the schema include: names ≤ 100 characters, lists ≤ 200
items, task text ≤ 10 000 characters, delegation lifetime ≤ 30 days.
Request size and nesting depth are limited earlier, by the Input Guard (P3).

## 2. Canonical form and signatures

PVP does not sign messages. It signs each message's **signed payload**: a
fixed dict built from the message (§3). The signed bytes are

```
canonical_bytes(payload) = json.dumps(payload, sort_keys=True, separators=(",", ":"))
```

The result is sorted keys at every level, no whitespace, and non-ASCII
escaped as `\uXXXX`. The full rules are in
[agent-signing.md](../agent-signing.md). The signed payloads are exactly the
ones the REST endpoints have always verified. An agent that already signs
delegations and actions therefore produces valid PVP signatures without any
change, and `tests/test_pvp_model.py` checks this against the real
endpoints.

`input_sha256` and `output_sha256` are SHA-256 (lowercase hex) of the
canonical form of the value. `null` hashes as the text `null`.

**Schemes.**

| scheme | rule |
|---|---|
| `ed25519` | one Ed25519 signature (RFC 8032) |
| `ed25519+ml-dsa-65` | Ed25519 **and** ML-DSA-65 (FIPS 204) over the same bytes; both must verify (AND, never OR) |

A signature as evidence (`PVPSignature`) carries the key or keys that
verified it at the time the record was made, never "the agent's current
key". The key fingerprint is `SHA256:` followed by unpadded base64 of
SHA-256 over the raw Ed25519 key, followed for a hybrid key by the raw
ML-DSA-65 key.

**Never taken from a message:** the signer's public key, the agent's
capabilities, tools, models, depth limit, and the rights it holds in a
chain. The orchestrator reads all of these from its own records. A message
can only *ask*; it never *declares* what it is allowed to do.

## 3. Messages

| `type` | direction | purpose |
|---|---|---|
| `agent` | out | an agent's identity and registered rights (the ceiling) |
| `attestation` | out | where an agent proved it runs, and until when |
| `action.request` | in | "may I do this?" |
| `action.check` | out | the verdict, bound to the request by `input_sha256` |
| `action.record` | in | "I did this", signed, under a `check_id` |
| `action` | out | a recorded action (refused attempts are recorded too) |
| `delegation` | in | hand a task and a subset of rights to another agent |
| `checkpoint` | out | a signed Merkle root of the organization's audit log |
| `receipt` | out | action + check (+ audit proof, P6): verifiable offline |
| `query` | in | ask for evidence, in PVP form or as a TRACE export |
| `error` | out | a refusal with a stable dotted code |

The schemas in [`schemas/`](schemas/) are normative for field types and
limits. The notes below cover meaning and rules that a schema cannot
express.

### 3.1 `action.request` → `action.check`

`agent_id`, `chain_id` (absent = outside any chain), `action_type` (a token:
`tool_call`, `model_call`, `api_request`, …), `tool_name`, `input`, and the
optional `tool_version` / `tool_digest` that the agent's runtime reports
(compared with the Tool Registry pins, ASI04).

The request carries **no capabilities**. What the action needs comes from
the Tool Registry. What the agent holds is computed by the server.

Every agent has its own key: the server never generates one, and an agent
without a key cannot act (`agent.key_required`). An agent asking for itself
signs the request with `nonce`, `issued_at` and `signature` (plus
`pq_signature` for a hybrid key) over:

```json
{"type": "action.request", "agent_id": 3, "chain_id": null,
 "action_type": "tool_call", "tool_name": "db.read", "input_sha256": "<hex>",
 "tool_version": null, "tool_digest": null, "nonce": "…", "issued_at": 1760000000}
```

The freshness and replay rules are those of a delegation (§3.3): 300 s old
at most, 30 s in the future, `nonce` single-use per agent. A missing
signature is `action.signature_required`, a wrong one
`action.invalid_signature`, an old one `action.stale_request` and a repeated
nonce `action.replayed_request` (409). A Provenza gateway or the egress
proxy asks on the agent's behalf as a witness (`POST /egress-proxy/check`
with the proxy's key and the agent's key) and does not sign as the agent.

A tool the Tool Registry does not know is denied and added as `pending` for
an administrator to approve: the registry's default mode is `enforce`.

The answer is `action.check`: `decision` ∈ {`allowed`, `denied`,
`pending_approval`}, `reason`, `incident_type`, `policy_id`,
`required_capabilities`, and a `check_id` that

- is random, single-use and expires at `expires_at` (five minutes by
  default);
- is bound to `agent_id`, `chain_id`, `action_type`, `tool_name` and
  `input_sha256`. Recording any other action under it raises an
  `action_mismatch` incident.

A denied check is still issued, so the attempt can be recorded.

**Signed policy.** Once the organization has a signed policy release in
force ([edge.md](edge.md), §3.1), the decision is made twice - on the
working copy and on the release - and the stricter one is the answer: a
denial or approval requirement of either applies, and a refusal by the
release says so in `reason` ("signed policy (release #N): …"). An agent
or agent key not in the release, a carrying row (MCP server, A2A peer,
HTTP tool, egress route, gateway route) that differs from the release, or
a release that does not verify or has expired is a denial.

**Held calls run once after approval.** A `pending_approval` check is
recorded as a pending action for a person to decide on
(`POST /agents/actions/{id}/approve`, bound to the input hash they saw).
The decision is **signed with the reviewer's session key**, which their
passkey certified at sign-in ([edge.md](edge.md), sections 2-3): the browser
asks `POST /agents/actions/{id}/statement` for the `provenza.approval`
statement (organization, person, session, held action, agent, chain,
action type, tool, `input_sha256`, decision, `issued_at`), signs its
canonical JSON with Ed25519 and sends statement and signature with the
decision; the server accepts exactly that statement, at most five minutes
old. The approval keeps the statement, the signature, the session's
certificate and the passkey's public key. A denial is signed when the
session can sign; an approval always is. Nothing is replayed by the server. When the agent makes **exactly the same
call** again (same agent, chain, action type, tool and `input_sha256`)
within `APPROVAL_REDEEM_MINUTES` (60 by default) of the approval, the policy
engine still says `pending_approval`, and the orchestrator spends that
approval - only a signed one whose signature verifies, again, for exactly
this call: the new check is `allowed`, its reason names the approval and the
held action, and the approval records the check it was spent on. A repeat
after that, other arguments or another chain are held again. A denial that
applies at the time of the repeat (a suspended agent, a tripped breaker, a
quarantine) still wins: only `pending_approval` can turn into `allowed`. If
the executor refuses the call after the check (a rate limit, a disabled
connection, a changed tool), the approval is released for the next repeat.
This works the same for `/agents/actions/check` and every gateway. The
agent reads where a held call stands at `GET /agents/actions/{id}/decision`
(its own key; `pending_approval`, `approved`, `denied` or `expired`, with
`redeemable_until`); the SDKs wait for it with `wait_for_approval` (Python)
and `waitForApproval` (JS).

An allowed check also carries a **permit** for the tool: a compact JWS
(`alg` EdDSA, `typ` `provenza-permit+jwt`) signed by the organization's
permit key, which is separate from its audit key:

```json
{"iss": "provenza:org:<slug>", "sub": "agent:3", "aud": "db.read",
 "jti": "<permit id>", "iat": 1760000000, "nbf": 1760000000, "exp": 1760000300,
 "act": "tool_call", "chain": null, "ish": "<input_sha256>"}
```

- The tool verifies it against `GET /pvp/permits/{org}/jwks.json`, which is
  public, and refuses without it: another tool (`aud`), another input
  (`ish`, the hash of the JSON body it received), an expired permit or one
  signed by an unknown key.
- `POST /pvp/permits/redeem` (`permit`, `tool`, `input_sha256`) marks it used
  exactly once, for any replica of the tool. A permit for anything else is
  refused there too, and stays unused.
- The permit belongs to the check: `action.check` carries `permit_id` and,
  once a tool redeemed it, `permit_redeemed_at`. A receipt therefore shows
  that the tool, not only the agent, saw the permit for the recorded action.
- After a rotation (`POST /pvp/permits/keys/rotate`), the old key stays in
  the JWKS for an hour. Permits live five minutes.

The SDKs verify permits for tools: `provenza.permit` in Python (ASGI
middleware, a decorator, `PermitVerifier`) and `permit.ts` in JS (Express
middleware, a fetch-style wrapper, `PermitVerifier`).

### 3.2 `action.record` → `action`

The agent reports what it did: the same action fields, `input`, `output`,
`duration_ms`, the `check_id`, and a signature. An agent with a key must
present a `check_id` and must sign. Its signed payload is:

```json
{"check_id": "…", "agent_id": 3, "chain_id": null, "action_type": "tool_call",
 "tool_name": "db.read", "input_sha256": "<hex>", "output_sha256": "<hex>"}
```

The server checks the signature **before** it consumes the check, so a
forged record cannot burn a legitimate `check_id`. The stored verdict is the
one issued at check time.

The result is `action`. It keeps the hashes, not the data, together with
`signed_payload` and `signed_by` (a `PVPSignature`). Those two come
together or not at all.

### 3.3 `delegation`

`from_agent_id`, `to_agent_id` (never the same agent), `task`,
`delegated_capabilities`, optional `delegated_tools` (omitted = the
delegating agent's own tools in the chain, never more), `chain_id` (absent
= a new chain), and `nonce`, `issued_at`, `expires_in`, `signature`. A
signed delegation must carry `nonce` and `issued_at`. Its signed payload is:

```json
{"from_agent_id": 1, "to_agent_id": 2, "task": "…",
 "delegated_capabilities": ["a", "b"], "chain_id": null,
 "nonce": "…", "issued_at": 1760000000, "expires_in": 600,
 "delegated_tools": ["x"]}
```

`delegated_capabilities` is sorted and **not** de-duplicated.
`delegated_tools` is sorted, de-duplicated and present **only when sent**,
so payloads of agents that do not delegate tools stay unchanged.

The orchestrator enforces the following:

| rule | |
|---|---|
| freshness | `issued_at` no older than 300 s, at most 30 s in the future |
| replay | `nonce` single-use per delegating agent |
| subset | child rights ⊆ the delegating agent's rights in the chain |
| depth | within min(the delegating agent's and the root's `max_delegation_depth`, the policy hierarchy's limit) |
| lifetime | counted from the signed `issued_at` and never longer than the parent's, so a late resend cannot extend it |

### 3.4 Evidence: `checkpoint`, `receipt`

`checkpoint` is the object `GET /audit-logs/checkpoints` returns: the audit
log's Merkle root (RFC 9162 hashing) signed by the organization's audit key
([audit-proofs.md](../audit-proofs.md)). A verifier checks four things: the
`statement` is canonical, it states exactly the other fields, the
fingerprint matches the keys, and the signature verifies.

**Evidence.** When an action is recorded, its `action` message as it
stands at that moment is stored with it (`agent_actions.evidence`). It
holds ids, hashes and signatures, never the input or output, so retention
(which blanks content after a while) leaves it intact. It is never changed
afterwards: a later human approval is a record of its own, and the receipt
shows it separately as `current_decision`.

**Seals.** Writing one audit record per action would serialize every
action of an organization on the audit log's lock. Instead, a Celery task
runs every minute and commits the organization's new evidence in batches.
It computes an RFC 9162 Merkle root over `SHA-256(canonical evidence)`,
taken in action-id order, and writes it as **one** audit record
(`entity_type: "pvp_action_seal"`, metadata `root`, `size`, `first_action_id`,
`last_action_id`). The next signed checkpoint then covers that record. A
receipt asked for before the next run seals the action on the spot.

**`receipt`** (`GET /api/v1/pvp/receipts/{action_id}`) is valid offline when
all of the following hold:

1. `action.signed_by` verifies over `action.signed_payload`. An action
   executed by a Provenza gateway has no agent signature and carries
   `executed_by` instead: the gateway is the witness;
2. `signed_payload` names this action exactly: the same check, agent,
   chain, type, tool and hashes, and no other members;
3. `check` agrees with the action on `check_id`, agent, chain, type, tool
   and `input_sha256`. An executor may refuse after an allowed check, but
   an action recorded as allowed under a refused check is a violation;
4. the action's evidence is leaf `seal.leaf_index` of the seal's Merkle
   tree, and the path leads to `seal.root`;
5. the audit record in `audit_proof` is this seal (`entity_id`, `root`,
   `size`), it hashes to its `record_hash`, and its inclusion path leads
   to the checkpoint's root;
6. the checkpoint is signed by the organization's audit key;
7. when a person's approval let the action run, `approval` carries it as
   signed: the statement approves exactly this call (agent, chain, type,
   tool, `input_sha256`), the session key signed it within its
   certificate's validity, and the certificate is a WebAuthn assertion of
   the person's passkey (user verified) over that session key.

`PVPReceipt.problems()` runs checks 1-6 on the server's side.
`tools/provenza_audit.py receipt RECEIPT.json` runs them independently: it
shares no code with the server and needs only `cryptography`. Pass
`--fingerprint` (the audit key) and `--agent-fingerprint` (the agent's key)
to check *whose* keys signed, not only that the receipt is signed, and
`--approver-passkey` (repeatable; the fingerprints in *My profile →
Passkeys*) for whose passkey approved. Whether
a key was revoked before the record was made is a question for the key
history (`GET /agents/key-revocations`), not for the receipt alone.

Actions recorded before receipts existed have no evidence; their receipt
answers 409 `pvp.no_evidence`.

### 3.5 `query`, `error`

`query` has `subject` ∈ {`receipt`, `action`, `chain`, `checkpoint`}, an
`id`, and a `format` ∈ {`pvp`, `trace`}.

`error` has a stable dotted `code` (`agent.key_required`,
`delegation.agent_not_active`, …), a human-readable `message` and
`details`. A message never echoes the refused content back.

## 4. Security model

| component | trusts | holds |
|---|---|---|
| external agent | nothing on its own; it is identified by its key | no credentials for tools, data or models |
| adapter | nothing; it only parses | nothing |
| Input Guard | its own limits and detectors | rate-limit counters, guard log |
| orchestrator | only PVP and its own records | verdicts, checks, audit |
| executor | only the orchestrator | the credentials |

The orchestrator decides only what reaches it. An agent whose network lets
it call an API directly never asks. Confinement is the deployment's job:
the agent should reach only the egress proxy, which also relays its calls to
Provenza. Provenza generates the rules and checks that they hold: an egress
self-check, signed by the agent, plus a beacon that the server observes
itself. `require_confined_egress` makes a recent `confined` verdict a
condition of acting (`docs/egress-lockdown.md`).

Order of checks on an inbound request (P3 ✓, `backend/app/pvp/guard.py`).
Cheap and authenticated checks come first, so that an unauthenticated
request cannot spend the server's work or another agent's quota:

| # | check | refusal |
|---|---|---|
| 1 | raw body size, before anything parses it: `check` 1 MiB, `record` 8 MiB, `delegate` 64 KiB (the reverse proxy lets 200 MB through to `/api/*`) | 413 `pvp.body_too_large` |
| 2 | authentication: `X-Agent-Key` or a session | 401 |
| 3 | rate limit per authenticated principal (the agent's key, or the user), never per an id read from the body; `PVP_RATE_LIMIT_PER_MINUTE`, default 1200 | 429 `pvp.rate_limited` + `Retry-After` |
| 4 | structure: depth ≤ 64, ≤ 50 000 nodes, strings ≤ 2 000 000 characters, keys ≤ 1 000, no U+0000 | 422 `pvp.input_rejected` |
| 5 | identifiers (tool, action type, capability, tool lists): no invisible or control characters, no surrounding space, NFKC-stable, letters from one script | 422 `pvp.input_rejected` |
| 6 | PVP schema (§3) | 422 |
| 7 | signature, policy, supply chain, behaviour (ASI10): the orchestrator and the services it calls | per check |

Steps 4 and 5 exist for concrete reasons:
- before step 4, an input nested 5 000 levels deep crashed the check
  endpoint with a `RecursionError` (a 500), and PostgreSQL cannot store
  U+0000 in JSONB;
- step 5 refuses `stripe.chаrge` with a Cyrillic `а`: it is not the tool
  a policy names, and a log reader would not see the difference.

The guard **refuses and never rewrites.** A rewritten input no longer
matches the hash the agent signed. A 422 names a reason code and JSON
paths only. A key that is not a plain name shows as `*`, because the key
itself may be the content.

A refusal of an authenticated request is written to `pvp_guard_log`: the
reason, the findings (code + path), the body's SHA-256 and size, and the
client IP. The content is never written. Admins read the log at
`GET /api/v1/pvp/guard-log`. `agent_id` there is the agent **key** that sent
the request; it is empty for a session, because an id in the body is a
claim and not an identity. Rate-limit refusals are not logged row by row,
since a flood of them would turn into a flood of writes.

Suspicious but well-formed content is not the guard's call: policies decide
which tools need a person's approval (ASI09). Nothing is executed in a
"restricted mode".

## 5. Mapping to external protocols

| protocol | step | mapping |
|---|---|---|
| REST (`/agents/actions/*`, `/agents/{id}/delegate`) | P2 ✓ | the current endpoints are the first adapter; the wire format is unchanged, and a body PVP refuses is a 422 that does not echo the input |
| MCP (Streamable HTTP, JSON-RPC) | P4 ✓ | Provenza is the only MCP server the agent sees: `POST /api/v1/mcp`. See §5.1 |
| Google A2A 1.0 and 0.3 | P5 ✓ | remote agents are reached only through `/api/v1/a2a-gateway/<peer>`. See §5.2 |
| TRACE v0.2 (export) | P6 ✓ | a Trust Record per action or per delegation chain. See §5.3 |
| OpenAI chat completions | ✓ | the LLM gateway `POST /api/v1/gateway/v1/chat/completions`: every call is a PVP action. See §5.7 |

### 5.1 MCP gateway

Code: `backend/app/pvp/mcp_gateway.py` (decisions), `mcp_client.py` (upstream
calls), `app/api/mcp.py` (the endpoint and its administration).

**Protocol.** The gateway speaks both eras of MCP, toward agents and toward
upstream servers:

- the stateless **2026-07-28** revision: `_meta` on every request, mirrored
  headers validated (`-32020 HeaderMismatch`), and `server/discover`;
- the `initialize`-based **2025-03-26 … 2025-11-25** revisions.

Toward agents it is stateless: it mints no sessions, and `GET` and
`DELETE` return 405. An `Origin` that is not in `CORS_ORIGINS` gets 403
(DNS-rebinding protection). Upstream servers are reached over HTTP only;
stdio would mean running someone else's process on the Provenza host. The
era is detected as the specification describes: a modern
`server/discover` first, then a fallback to `initialize`.

**Authentication.** Only an agent key opens the endpoint: `X-Agent-Key`, or
`Authorization: Bearer <agent key>` for stock MCP clients. A user session
does not.

| guarantee | how |
|---|---|
| the agent never holds credentials | upstream URLs and secrets stay in Provenza, encrypted with the organization's key under BYOK; they are decrypted only for the call |
| the model reads only approved definitions | `tools/list` shows a tool only while the definition from the last sync hashes to its Tool Registry pin (`approved`). A description changed upstream ("tool poisoning") never reaches the model; the tool disappears until it is re-approved |
| the tool called is the tool approved | before each call the gateway fetches the live definition (cached 60 s) and hashes it **itself**. The digest goes into the check, so the Tool Registry, which until now relied on a digest reported by the agent, verifies independently. A changed tool is refused and marked `drifted`, with a `supply_chain_drift` incident |
| every call is governed | each call is a PVP `action.request` through the orchestrator (rights in the chain, policies, Tool Registry, behaviour, breaker), and the Input Guard runs first |
| every call is recorded | refused and denied calls too, with `executed_by: "mcp_gateway"`: Provenza is the witness, because an MCP client cannot sign |
| output | NUL and oversized structures are refused, since they could not even be stored |

Tools are exposed as `<server slug>.<tool name>`. That name is what agent
rights, policies and the Tool Registry use. The admin flow is: add a server
(`POST /api/v1/mcp-servers`) → sync → read the tools → approve each one
(`…/tools/{id}/approve` pins the definition that was read). A chain is
passed in `params._meta["provenza/chain_id"]`.

**Limitations.**
- A call that needs human approval (ASI09) is recorded as pending and is
  **not executed**; the agent is told so, with the action id. After the
  approval, the same call made again runs once (§3.1).
- Only tools are proxied. Resources, prompts and subscriptions are not
  offered.

### 5.2 A2A gateway

Code: `backend/app/pvp/a2a_gateway.py` (decisions), `a2a_wire.py` (formats),
`app/api/a2a_gateway.py` (endpoints and their administration).

**Versions.** A2A 1.0 broke 0.3, and agents in the field speak both. The
gateway keeps 1.0 as its one canonical form and converts at the edges:

| | 0.3 | 1.0 |
|---|---|---|
| methods | `message/send`, `tasks/get`, `tasks/cancel` | `SendMessage`, `GetTask`, `CancelTask` |
| version | no `A2A-Version` header (an empty version means 0.3) | `A2A-Version: 1.0` |
| parts, roles, states | `kind` discriminator, `user`, `completed` | member name, `ROLE_USER`, `TASK_STATE_COMPLETED` |
| send result | the Task or Message itself | `{"task": …}` or `{"message": …}` |

The calling agent may use either version; the remote agent is addressed in
the version its card declares. A malformed message is refused (`-32602`)
and is never forwarded half-understood.

**Model: a governed action, not a delegation.** An A2A message carries no
rights and no Provenza signature, and the receiver may not be a Provenza
agent at all. So each operation is a PVP action of the **caller** on the
tool `a2a.<peer>`, with action types `a2a.send`, `a2a.get_task` and
`a2a.cancel_task`. Which agent may talk to which peer is therefore decided
by agent rights and policies, exactly as for tools. A chain is passed in
`metadata["provenza/chain_id"]`.

| guarantee | how |
|---|---|
| the agent sees only Provenza | `GET …/<peer>/.well-known/agent-card.json` returns the **approved** card, pointing at Provenza and asking for the agent's own key. It never contains the peer's address or security schemes. Streaming and push are switched off |
| the peer is the one approved | the card is pinned in the Tool Registry (`a2a.<peer>`, signatures excluded). Before each call the live card is fetched (cached 60 s) and hashed by the gateway. A changed card is refused and drifts, with an incident, until it is re-approved. This also covers a card that suddenly points at another endpoint |
| tasks are owned | a task belongs to the agent that created it, claimed atomically. `GetTask`, `CancelTask`, a follow-up `taskId` or a `referenceTaskIds` entry naming someone else's task returns **TaskNotFound**. This is checked before anything else, so it reveals nothing (A2A 1.0 §13.1). A peer that answers with another caller's task is withheld |
| no side channels | push-notification configs are refused (`-32003`): the peer would deliver to a URL outside the audit trail. Streaming, resubscription, `ListTasks` and the extended card return `-32004` |
| unknown = forbidden | a peer that does not exist, is not approved, or is not in the agent's rights all answer the same 404 |
| answers | unstorable structures are refused. Peer errors are passed through with their code, and the attempt is recorded |

Admin flow: `POST /api/v1/a2a-peers` (card URL + secret) → sync → read the
card → approve.

A call that needs human approval is recorded as pending and is not sent;
after the approval, the same call made again is sent once (§3.1).

### 5.3 TRACE export

`GET /api/v1/pvp/receipts/{id}/trace` (one action) and
`GET /api/v1/pvp/chains/{id}/trace` (one delegation chain, the "run") return
a TRACE v0.2 Trust Record. TRACE is an OPAQUE specification hosted by the
Linux Foundation; v0.2 is a developer preview. The record is a JWT whose
payload is the RFC 8785 (JCS) form of the claims. It is signed EdDSA by
the organization's audit key, which is also given in `cnf.jwk`.

Every claim states only what Provenza actually knows:

| claim | value | why |
|---|---|---|
| level | **0** | software signing. Level 1+ needs a key generated inside a hardware TEE |
| `origin` | `third-party-control-plane` | Provenza governed and recorded the actions; it is not the agent. The schema then requires `runtime.platform: software-only` |
| `subject` | `did:provenza:org-N:agent-M` | not a resolvable DID method; the identity proof is the key fingerprint |
| `runtime.measurement` | hash of the agent's key fingerprint and its latest passed workload attestation | what Provenza verified about the agent. It is not a platform measurement |
| `model` | `unobserved` | actions were governed, not the model behind them |
| `policy.bundle_hash` | hash of the verdicts applied | of the decisions, not of policy text |
| `policy.enforcement_mode` | `enforce` only if a Provenza gateway executed every call, else `advisory` | an agent that reports its own actions could have ignored a denial |
| `build_provenance` | SLSA 0; `digest` = hash of the Tool Registry pins of the tools used | there is no build provenance |
| `tool_transcript.hash` | JCS hash of the PVP actions carried | |
| `appraisal.status` | `affirming` (receipts verify, agent-signed), `warning` (some only gateway-witnessed), `contraindicated` (a receipt does not verify) | Provenza's own appraisal of the receipts |
| `transparency` | omitted | Provenza's signed checkpoints are not a SCITT log; they are listed under `references` |
| `references` | each `pvp-receipt` (JCS digest), each `audit-checkpoint` (root) | |

The export envelope (`provenza.trace-export/1`) carries the JWT, the claims,
the signing key, every receipt the record references and, for a hybrid
audit key, the ML-DSA-65 signature over the JWS signing input. TRACE has no
field for it. `tools/provenza_audit.py trace EXPORT.json` verifies the JWT,
recomputes the JCS digests with its own RFC 8785 implementation and checks
every receipt.

### 5.4 Egress actions (SDK auto-instrumentation)

`provenza.auto` in the Python SDK reports a process's direct calls to AI
providers as actions with `action_type: "egress"`, `tool_name:
"egress.<host>"` and `input` {host, method, path, body_sha256, body_bytes}.
The input holds hashes only, never the prompt.

The organization's AI domain catalog is the right for these actions, not
the agent's `allowed_tools`:

- `blocked`: denied, with incident `ai_domain_blocked`;
- `allowed`, or not classified yet: allowed.

Policies, the behaviour baseline and the breaker still apply. The Tool
Registry does not: provider hosts are managed in the catalog. `tool_name`
must name `input.host`. Agents read the catalog at
`GET /api/v1/pvp/egress-catalog`: the organization's entries, followed by
the built-in hints it has not classified. Code: `backend/app/pvp/egress.py`.

### 5.5 Egress proxy

Code: `proxy/` (the proxy, Go), `backend/app/pvp/egress_proxy.py`
(decisions), `app/api/egress_proxy.py` (endpoints and their administration).

Agents reach an external API only as `http://<proxy>/<route>/<path>`. The
route is administered in Provenza: upstream URL, methods, path prefixes,
body limit and credential. The credential is either sealed in the browser
to each proxy's own encryption key - Provenza stores envelopes it cannot
open, the proxy opens its own and keeps the credential in memory only
(edge.md §4.1) - or held by the proxy alone. The request chooses neither
the upstream nor the credential.

Each request is a PVP action with `action_type: "proxy"`, `tool_name:
"proxy.<route>"` and `input`:

    {"route", "method", "path", "query_sha256", "body_sha256", "body_bytes"}

- `path` is the path after the route segment, exactly as sent, with its
  percent-encoding kept;
- the query string and the body are hashed as raw bytes;
- a hash is `null` when the query or the body is empty.

The agent needs `proxy.<route>` in its rights, and then policies, argument
rules, the behaviour baseline and the breaker apply as to any action. The
route's own rules are checked as well: the method, a path prefix, no `.` or
`..` segment or encoded `/` or `\` (an upstream that normalizes them would
escape the prefix), and the body limit.

There are two ways to obtain the check:

| | who checks | the agent sends |
|---|---|---|
| mediated | the proxy, with the agent's key | `X-Agent-Key` |
| SDK | the agent | `X-Provenza-Check-Id` |

Both continue the same way. **Redeem** (`POST /egress-proxy/redeem`,
`X-Proxy-Key`): the proxy describes the request it is about to send.
- If it is not exactly the checked one, the check is burned and an
  `action_mismatch` incident is raised.
- A refused check is recorded at this point.
- An allowed check is reserved, so neither the agent nor another proxy can
  use it.

The proxy then forwards the request. It never passes on `Authorization`,
`Cookie`, `X-Agent-Key`, `X-Provenza-*` or hop-by-hop headers, and it does
not follow redirects. **Complete** (`POST /egress-proxy/complete`) records
the action with the upstream status and the response hash and size
(`status: 0` and an `error` code when there was no response), with
`executed_by: "egress_proxy"`.

A reserved check that is never completed stays visible to admins as an
open redemption (`GET /api/v1/egress/redemptions?open=true`). The proxy is
fail-closed: without Provenza nothing is sent.

**The proxy's own key and receipts.** The proxy generates an Ed25519 key
on its host (or reads `signing_key_file`) and registers the public half
once (`POST /egress-proxy/key`); a different key later is refused
(`egress.proxy_key_changed`) - a new key is a new proxy. With **complete**
(and with a refusal of its own, below) it sends its signed receipt
(`app/pvp/witness.py`):

```json
{"type": "provenza.proxy.receipt", "v": 1, "check_id": "…", "agent_id": 5, "chain_id": null,
 "action_type": "proxy", "tool_name": "proxy.stripe", "input_sha256": "…", "output_sha256": "…",
 "decision": "allowed", "agent_signature": "verified", "policy": {"release": 3, "bundle_sha256": "…"},
 "log": {"seq": 41, "prev": "<SHA-256 of the previous line of its log>"}, "issued_at": 1760000000}
```

The server keeps it as the action's `witness` - part of the sealed
evidence - only when it names exactly the recorded action and verifies with
the registered key; otherwise it raises a `witness_mismatch` incident. The
proxy appends the same line to its own hash-chained log
(`state_dir/receipts.jsonl`). `tools/provenza_audit.py receipt
--proxy-fingerprint` checks the witness offline; the fingerprint is shown
under *Egress → Proxies* and in the key manifest.

**Enforcing the signed policy** (`policy.mode: "enforce"` in the proxy's
configuration, [edge.md](edge.md) §4). The proxy fetches releases
(`GET /egress-proxy/policy-release?after=N`) and accepts one only when the
quorum of the manifest it already trusts signed it - the manifest pinned in
its configuration (`policy.pin`, the SHA-256 shown in the *Signed policy*
panel) before the first. A request then goes out only when the server's
check AND the proxy's own evaluation of that release
(`proxy/internal/policy`, the same decisions as `app/pvp/bundle_eval.py`,
`sdk/testdata/policy-vectors.json`) allow it; the route's upstream comes from
the release. A call the release holds for approval needs a human approval
the proxy verifies itself (`POST /egress-proxy/check-info` hands it over).
In SDK mode the agent also sends its signed request (`X-Provenza-Request`:
base64url of `{"payload", "signature", "public_key", …}`), which the proxy
checks against the key fingerprint in the manifest - its Ed25519 half; the
server checks both halves of a hybrid key. With `require_agent_signature`
nothing else is accepted. A refusal of the proxy's own is recorded through
the check (`redeem` with `enforcement`), its reason prefixed "refused by the
egress proxy under the signed policy".

**Enforce mode** ([edge.md](edge.md) §4.2). When the signed policy says
`"enforcement": {"mode": "enforce"}`, the proxy takes on every path only a
request the agent signed over the HTTP request itself (`tool_name`
"proxy.<first path segment>", e.g. "proxy._llm"; the SDKs, or the proxy's
agent mode for clients that cannot sign), and sends Provenza
`X-Provenza-Proxy-Mode: enforce` on every call. A mediated `POST
/egress-proxy/check` then needs the agent's `X-Provenza-Request` (verified as
the agent's own check: `require_signature`), a plan needs it with
`X-Provenza-Descriptor` (base64url JSON of the request it describes), `redeem`
refuses a check the agent did not sign, and `complete` raises a critical
`unenforced_action` incident when the receipt does not name a signed release
and `agent_signature: "verified"`. `POST /agents/actions/check` still
answers, without a permit, its reason ending "enforce mode: this check
authorizes nothing by itself"; the server's own gateways refuse
(`enforce_mode` for the LLM gateway).

**Sealed credentials** ([edge.md](edge.md) §4.1). The proxy also registers
an X25519 encryption key, signed by its signing key (`POST /egress-proxy/key`
with `encryption_key`, `encryption_key_signature`). Credentials are sealed to
it in the browser (`PUT /api/v1/egress/credentials/{object}/{id}`, one
envelope per proxy, bound to the object, the proxy and the upstream origin)
and fetched by the proxy (`GET /egress-proxy/credentials`); the server
refuses a credential in clear text everywhere and holds none it can read.
The PUT carries the administrator's session-key signature over the envelopes
(`statement` from `POST .../statement`, `signature`): `provenza.credential.sealed`
with the object, its origin and each proxy's envelope SHA-256; it is served
with each envelope (`sealer`), and an enforcing proxy opens only envelopes an
administrator of its signed manifest vouched for. Envelopes the server sealed
from credentials it held are countersigned (`POST .../countersign`).

**The gateways' actions** (`app/pvp/proxy_actions.py`). An HTTP tool, AI
connection, MCP server or A2A peer that takes a credential is reached
through a proxy, with the gateway's own protocol (`/_tools/call`,
`/_llm/v1`, `/_mcp`, `/_a2a/<peer>`). The proxy asks for a plan
(`POST /egress-proxy/{http-tools,llm,mcp,a2a}/plan`, with the agent's key in
`X-Agent-Key`): the server decides as the gateway does - the same input is
recorded (for LLM calls the metadata only) - records a refusal at once and
reserves an allowed check for that proxy. The proxy completes it
(`POST /egress-proxy/complete` with `output` - metadata and hashes - or
`enforcement` when it refused under the signed policy; for A2A
`POST /egress-proxy/a2a/complete` with the peer's answer, which the server
reads as its gateway does). MCP servers' tools and A2A peers' cards are
reported by the proxies (`POST /egress-proxy/mcp/sync`, `/a2a/sync`); the
server's own sync of such an upstream answers `mcp.synced_by_proxy` /
`a2a.synced_by_proxy`. `GET /egress-proxy/config` lists the MCP servers and
peers a proxy serves.

**Limitation:** the proxy governs only what goes through it. Each
deployment has to close the direct paths to the upstreams with a network
policy or firewall (`proxy/deploy/`).

### 5.6 HTTP tool gateway

Code: `backend/app/pvp/http_tools.py`, `app/api/http_tools.py`.

An administrator registers an HTTP API as a tool: `name` (the tool name
that rights, policies and the Tool Registry use), method, URL with optional
`{argument}` path placeholders and input schema. This server holds no
credential: a tool that takes one has it sealed to the egress proxies
(edge.md §4.1) and is refused here. Saving it pins the digest of the
definition (`name`, `method`, `url`, `input_schema`, `description`) in the
Tool Registry as approved.

The agent sends `POST /http-tools/call` with its key and a signed
`action.request` (§3.1, `action_type: "tool_call"`). Provenza then does
everything in one operation:

1. verifies the agent's signature, freshness and nonce;
2. checks the action, reporting the pinned digest itself;
3. checks the arguments against the top level of the input schema
   (`required`, `type`, `enum`, `additionalProperties: false`);
4. calls the API with the SSRF-guarded client, injecting the credential.
   For POST, PUT and PATCH it also sends the check's permit (§3.1), so an
   API behind the permit middleware accepts only calls made through
   Provenza;
5. records the action with `executed_by: "http_gateway"`, and records
   denied and refused calls too.

The answer is `{decision, reason, action_id, status, body}`. When the API
failed or the answer was refused, `error` or `withheld` comes instead of
`body`. A response over the tool's size limit or a redirect never reaches
the agent. The SDKs
expose it as `agent.invoke(tool, arguments)`.

### 5.7 LLM gateway

Code: `backend/app/services/gateway_service.py`, `app/api/gateway.py`.

The agent calls an OpenAI-compatible endpoint with its own key
(`X-Agent-Key`, or `Authorization: Bearer <agent key>` for stock clients).
Each chat completion is a PVP action of the agent:

| field | value |
|---|---|
| `action_type` | `model_call` |
| `tool_name` | `llm.<model>` (at most 100 characters) |
| `chain_id` | the `X-Provenza-Chain-Id` header, if the call runs in a delegation chain |
| `input` | `{"model", "provider", "messages", "messages_sha256", "max_tokens"}`: the message count and the JCS hash of the messages as the client sent them (fields left out are not null) |
| `executed_by` | `llm_gateway` |
| output | `{"finish_reason", "prompt_tokens", "completion_tokens", "response_sha256"}`, or `{"provider_error"}` |

The orchestrator decides as for any action: the agent's state (a
quarantined agent is refused), the chain and its breaker, then the policy
engine. Model calls are not counted in the behaviour baseline: their volume
is the gateway's rate limit. The right to
a model is the model allow list (the agent's `allowed_models` and every
level's `models.allow`), not the tool list: `allow_only_tools` and
`tools.allow` do not apply to `model_call`, while deny and approval lists
apply to `llm.<model>` (`deny_tool_patterns: ["llm.gpt-4*"]`,
`require_approval_tool_patterns: ["llm.*"]`). The Tool Registry does not
pin models; the gateway's routes are their list.

After an allowed check the gateway, as executor, refuses a model without a
route, a disabled connection, a provider outside `providers.allow`, a cloud
provider under "self-hosted only", and a call over the rate limit. Every
outcome is recorded as the action (refusals as denied) and as a
`gateway_calls` row linked to it. A call that needs approval is recorded as
pending and answered `403 approval_required` with the action id; it is not
sent. After the approval, the same request (same messages) runs once
(§3.1). The prompt and the answer are never stored, only their hashes.

## 6. Versioning

`pvp/1` changes only compatibly: new message types, or new optional
members on new message types. Anything a deployed verifier would read
differently (a new member on an existing message, a changed signed payload,
a changed canonical form) requires `pvp/2`. A server may speak both.
