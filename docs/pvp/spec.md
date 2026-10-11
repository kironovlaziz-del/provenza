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

The answer is `action.check`: `decision` ∈ {`allowed`, `denied`,
`pending_approval`}, `reason`, `incident_type`, `policy_id`,
`required_capabilities`, and a `check_id` that

- is random, single-use and expires at `expires_at` (five minutes by
  default);
- is bound to `agent_id`, `chain_id`, `action_type`, `tool_name` and
  `input_sha256`. Recording any other action under it raises an
  `action_mismatch` incident.

A denied check is still issued, so the attempt can be recorded.

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
6. the checkpoint is signed by the organization's audit key.

`PVPReceipt.problems()` runs these checks on the server's side.
`tools/provenza_audit.py receipt RECEIPT.json` runs them independently: it
shares no code with the server and needs only `cryptography`. Pass
`--fingerprint` (the audit key) and `--agent-fingerprint` (the agent's key)
to check *whose* keys signed, not only that the receipt is signed. Whether
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
| 7 | signature, policy, injection (ASI01), code shapes (ASI05), behaviour (ASI10): the orchestrator and the services it calls | per check |

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

Suspicious but well-formed content is not the guard's call. In enforce
mode, the injection and code-execution guards already hold such an action
for human approval (ASI09). Nothing is executed in a "restricted mode".

## 5. Mapping to external protocols

| protocol | step | mapping |
|---|---|---|
| REST (`/agents/actions/*`, `/agents/{id}/delegate`) | P2 ✓ | the current endpoints are the first adapter; the wire format is unchanged, and a body PVP refuses is a 422 that does not echo the input |
| MCP (Streamable HTTP, JSON-RPC) | P4 ✓ | Provenza is the only MCP server the agent sees: `POST /api/v1/mcp`. See §5.1 |
| Google A2A 1.0 and 0.3 | P5 ✓ | remote agents are reached only through `/api/v1/a2a-gateway/<peer>`. See §5.2 |
| TRACE v0.2 (export) | P6 ✓ | a Trust Record per action or per delegation chain. See §5.3 |

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
| every call is governed | each call is a PVP `action.request` through the orchestrator (rights in the chain, policies, Tool Registry, ASI01/05 on the arguments, behaviour, breaker), and the Input Guard runs first |
| every call is recorded | refused and denied calls too, with `executed_by: "mcp_gateway"`: Provenza is the witness, because an MCP client cannot sign |
| output | NUL and oversized structures are refused, since they could not even be stored. Injected instructions (ASI01) are recorded, and in enforce mode the output is withheld |

Tools are exposed as `<server slug>.<tool name>`. That name is what agent
rights, policies and the Tool Registry use. The admin flow is: add a server
(`POST /api/v1/mcp-servers`) → sync → read the tools → approve each one
(`…/tools/{id}/approve` pins the definition that was read). A chain is
passed in `params._meta["provenza/chain_id"]`.

**Limitations.**
- A call that needs human approval (ASI09) is recorded as pending and is
  **not executed**; the agent is told so. The gateway does not yet execute
  a call after it is approved.
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
| no side channels | push-notification configs are refused (`-32003`): the peer would deliver to a URL outside scanning and audit. Streaming, resubscription, `ListTasks` and the extended card return `-32004` |
| unknown = forbidden | a peer that does not exist, is not approved, or is not in the agent's rights all answer the same 404 |
| answers | scanned (ASI01) and, in enforce mode, withheld. Unstorable structures are refused. Peer errors are passed through with their code, and the attempt is recorded |

Admin flow: `POST /api/v1/a2a-peers` (card URL + secret) → sync → read the
card → approve.

**Limitation:** a call that needs human approval is recorded as pending
and is not sent.

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

## 6. Versioning

`pvp/1` changes only compatibly: new message types, or new optional
members on new message types. Anything a deployed verifier would read
differently (a new member on an existing message, a changed signed payload,
a changed canonical form) requires `pvp/2`. A server may speak both.
