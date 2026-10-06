# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Agents Found and Devices (Discovery).** The endpoint agent (v1.2.0)
  recognizes AI agents running on a machine - coding agents (Claude Code,
  Cursor, GitHub Copilot, Codex CLI, Gemini CLI, Aider, Goose, OpenCode,
  Amazon Q, OpenHands, Open Interpreter), agent frameworks (CrewAI,
  LangGraph, AutoGen Studio, Letta) and agent platforms (n8n, Flowise,
  Langflow) - and reports them as `agent_detected` events. Each finding is
  kept per device for review: register it as a governed agent (the
  registration form opens pre-filled and links the finding) or ignore it.
  Every telemetry batch also refreshes its device, so Discovery -> Devices
  lists each reporting machine and browser with user, OS, collector
  version and last activity. New notification event `agent_discovered`.
  API: `/devices`, `/agents-found`.
- **Unrecognized agents found by behavior** (endpoint agent 1.3.0). A
  process no catalog knows is reported as `custom.<script or program>`
  when it has a connection to an LLM API (addresses of the major providers
  are resolved periodically) or an LLM SDK loaded (`/proc/<pid>/maps`:
  jiter, tiktoken, tokenizers); LLM API key variable names in its
  environment raise the confidence - names only, never values. Agents
  Found shows the signals and a high / medium confidence.
- **Tamper-evident audit log** ([docs/audit-proofs.md](docs/audit-proofs.md)).
  Audit records are hash-chained per organization (`seq`, `prev_hash`,
  `record_hash`); every 5 minutes the server signs the Merkle root of each
  log that grew (RFC 9162 hashing, Ed25519 + ML-DSA-65 audit key). New
  endpoints: `GET /audit-logs/{id}/proof` (inclusion proof),
  `GET /audit-logs/consistency` (a later checkpoint extends an earlier
  one), `GET/POST /audit-logs/checkpoints`, `GET /audit-logs/integrity`,
  `POST /audit-logs/verify` (admin: recompute the whole chain). The Audit
  Log page shows the integrity status, checks a record's proof in the
  browser and downloads proofs and checkpoints; `tools/provenza_audit.py`
  verifies them offline without trusting the server.
- **Audit key rotation with quorum.** Each organization has its own audit
  key. A new one is proposed by an admin, approved by
  `AUDIT_KEY_ROTATION_QUORUM` admins (default 2) who each type its
  fingerprint as published outside Provenza, and takes effect after
  `AUDIT_KEY_ROTATION_NOTICE_HOURS` (default 24): the old key then signs a
  handover, countersigned by the new key. Verifiers - the offline tool and
  the browser - accept the new key only with both the valid handover chain
  and the independently confirmed fingerprint; on failure the tool prints
  the trust chain first. Any admin can cancel. New notification event
  `audit_key_rotation`. API: `/audit-logs/keys`.

- **Agent-held signing keys.** An agent can register its own Ed25519 public
  key (at registration or later via `POST /agents/{id}/signing-key`); the
  server never holds the private key. Server-generated keys remain as a
  quick start and are labelled `key_origin: "server"`. Every key is kept in
  a history with the period it was current.
- **Weak keys are refused.** Public keys must be canonical points of the
  Ed25519 prime-order subgroup; small-order keys (for which a fixed
  signature verifies every message) are rejected at registration and never
  count as valid - on the server, in the browser and in the offline tool. A
  key the server generated cannot later be registered as agent-held, and a
  key belongs to one agent only.
- **Signature evidence that does not depend on the server.** Verification
  endpoints for delegations and recorded actions return the exact signed
  text, the key that verified it and its fingerprint; the delegation map
  verifies over those bytes and computes the fingerprint in the browser,
  and offers the evidence as a download. `tools/provenza_sign.py`
  (keygen / fingerprint / sign / verify) and an OpenSSL recipe check it
  offline. Specification: `docs/agent-signing.md`.

- **Post-quantum hybrid signatures (Ed25519 + ML-DSA-65).** An agent key can
  be hybrid: delegations, recorded actions and agent-to-agent messages carry
  an ML-DSA-65 (FIPS 204) signature next to the Ed25519 one, over the same
  canonical bytes, and are valid only if both verify. Hybrid keys can be
  agent-held (`provenza_sign.py keygen --hybrid`) or server-generated
  (`key_scheme: "hybrid"`); the fingerprint covers both keys. The browser
  verifies ML-DSA with a bundled library (`@noble/post-quantum`, no CDN);
  the offline tool and an OpenSSL 3.5 recipe check both halves. The new
  organization setting `require_pq_signatures` refuses Ed25519-only keys
  and stops agents without a hybrid key from delegating, recording actions
  and sending messages until they get one.
- **Teams and role templates.** Registry → Teams & Roles: teams form a
  tree (organization → team → sub-team → agent) and agents belong to one by
  id (`agents.team_id`; `owner_team` stays as its display name). A role
  template is a named set of rights - capabilities, tools, models,
  delegation depth, `require_hybrid`, `require_attestation` (enforced once
  attestation lands). An agent enrolled with or assigned a role has exactly
  the role's rights, cannot have them edited individually, and follows
  every change to the role; a team's role is only for that team's agents.
  A role that requires a hybrid key cannot be given to an agent with a
  classic key. Teams and roles still in use are not deleted; every change
  is audited. API: `/teams`, `/teams/roles`, `PUT /agents/{id}/assignment`;
  enrollment tokens take `team_id` / `role_id`.
- **Workload attestation with Kubernetes ServiceAccount tokens**
  ([docs/attestation.md](docs/attestation.md)). A role template can require
  attestation under a policy (cluster issuer and keys, audience, allowed
  namespaces / service accounts, pod-bound tokens only, validity). Its agents
  cannot act until they send their pod's projected token, signed with their
  own key over a server challenge (`provenza_sign.py attest --every N`); a
  passing attestation lasts until the policy's validity or the token's
  expiry, and stops counting when the policy changes. JWKS by paste, URL or
  OIDC discovery (cached for an hour). Every attempt is audited
  (`attested`, `attestation_failed`, `attestation_refused`) and rate
  limited. Registry → Attestation: policies, a token tester, every attempt;
  the agent page shows its status. API: `/attestation/*`,
  `/agents/{id}/attestation[/challenge]`.
- **Policy hierarchy** ([docs/policies.md](docs/policies.md)). One policy
  document at three levels - organization, team (with its parent teams),
  agent - edited as a form or as YAML (Policies → Policy hierarchy). Lower
  levels can only tighten: smallest limit, every allow list must allow, all
  deny / approval lists and blocked terms apply, switches stay on. Applied in
  the gateway (rate limit, token cap, models, providers, blocked terms,
  output scanning - the gateway settings take part as the topmost level),
  to agent actions and delegation (tools allow / deny / approval, models,
  depth) and, at the organization level, to user requests (providers,
  blocked terms, approval). The editor previews the effective policy with
  the source of every value and lists what a level tried to loosen.
  Concurrent edits are refused rather than overwritten; every save is
  audited with the document before and after. API: `/policy-layers/*`.
- **Blocked terms in one place** ([docs/blocked-terms.md](docs/blocked-terms.md)).
  Policies → Blocked terms replaces the term lists of the gateway settings,
  the policy hierarchy levels and policy versions. Each term applies to the
  whole organization, all agents, a team (with its sub-teams), one agent or
  a policy's use cases; matches as a whole word - seeing through spacing,
  `_`/`-`, digits for letters, look-alike Cyrillic/Greek letters, accents,
  full-width and invisible characters, without gluing ordinary words
  together - or anywhere; and blocks or only monitors (let through and
  counted, not shown to whoever is watched). Categories
  switch groups of terms on and off; hit counts and last seen; CSV export
  (formula-safe) and import with a preview; a tester. Audited; terms are
  never hard-deleted; a team with terms scoped to it is not deleted.
  API: `/blocked-terms/*`.
- **PII rules** ([docs/pii-rules.md](docs/pii-rules.md)). Policies → PII
  rules: every built-in type of the Prompt Firewall (email, phone, card,
  SSN, IP address, API key, person, organization, place) can be switched
  off or set to block the prompt instead of masking it, and organizations
  add their own patterns (ПИНФЛ, ИНН, passport, contract numbers - presets
  included) with mask or block. Own patterns are checked first. Patterns
  are refused when they could backtrack catastrophically (nested or
  alternated repetition, back references, open-ended `.*`-like runs) or run
  slowly on long text, and run with a 250 ms limit; a rule out of time
  refuses the prompt and is counted. A tester shows what a rule finds and what the provider would get.
  Applied in the gateway, user requests, the playground and masked views.
  Audited; rules are never hard-deleted. API: `/pii/*`.
- **Kill switch with levels and undo** ([docs/kill-switch.md](docs/kill-switch.md)).
  Enforcement → Kill switch stops one agent, a team with its sub-teams, all
  agents, or all AI traffic (every agent plus the gateway, AI requests and
  the playground), with a required reason and, organization-wide, a typed
  confirmation. Each stop records exactly which agents it suspended and
  which delegation chains it ended; lifting it gives back only those -
  agents stopped earlier stay stopped, agents changed since are left alone,
  and agents still held by another stop are handed over to it. While a stop
  is in force, agents created or moved into its scope (teams created or moved
  under a stopped team included) start suspended, and
  the agents it holds cannot be switched back on by hand
  (`409 kill_switch.holds_agent`). History on the page, audit records
  (`kill_switch` engaged / lifted) and a new notification event
  `kill_switch`. `POST /agents/{id}/kill` is now an agent-level stop and
  returns its `event_id`. API: `/kill-switch`, `/kill-switch/events`,
  `/kill-switch/events/{id}/lift`.
- **Retire an agent** from its page: final - its key stops working, it no
  longer counts toward a team or role (they can then be deleted) and neither
  a kill nor a status change brings it back (`409 agent.retired_final`).
  Suspended (killed) agents can be reactivated.

### Changed

- **Navigation follows the lifecycle of an AI system:** Discovery →
  Registry → Policies → Enforcement → Audit (plus Settings), instead of
  grouping by feature type. Pages and URLs are unchanged. A few labels
  changed with it: Shadow AI Sightings, Audit Log, Notifications, and
  Playground (the governed chat with a connected provider).

### Removed

- **MLOps, RAG and Simple Mode.** Provenza is a discovery and control plane
  for AI in the organization; building and hosting models is not its job.
  Removed: dataset upload, compute detection, training jobs (scikit-learn,
  Transformers, hyperparameter search, the Docker training runner), model
  deployments with their monitoring and playground, RAG knowledge bases
  (collections, documents, chat), the Simple Mode wizard and its
  `/users/me/ui-mode` preference. API prefixes `/datasets`, `/compute`,
  `/training-jobs`, `/deployments`, `/rag` and `/simple-mode` are gone.
  Dependencies dropped: pandas, scikit-learn, joblib, numpy (direct),
  psutil, pypdf, python-docx, openpyxl, python-multipart, optuna, docker,
  and `requirements-ml.txt`.
- **Memory integrity** now covers agent memory only (the RAG-document
  scanning, trust and rescan went with RAG).
- **AI Inventory** no longer syncs deployments or knowledge bases; new data
  links name an external source. Existing entries and links stay readable.

### Fixed

- **Browser verification of non-ASCII payloads.** The browser now checks the
  exact signed bytes, and its canonical JSON matches the server's byte for
  byte (`\uXXXX` escaping, keys sorted at every level), so delegations with
  Cyrillic or Uzbek text no longer show as "signature does not match".
- **Key changes no longer break old signatures** — each signed record keeps
  the public key that verified it.

### Security

- **Agents join only with an enrollment token and proof of possession.** An
  admin issues a one-time token bound to a rights template; the agent
  generates its key and signs a fresh server challenge
  (`tools/provenza_sign.py enroll`), and only then is it created - with the
  template's rights, never its own. Key rotation needs the old key's
  consent and the new key's proof (`provenza_sign.py rotate`); a lost or
  revoked key is replaced through a re-key token (which also issues a new
  API key; a hybrid agent stays hybrid). Direct registration and
  admin key replacement without proof are off by default
  (`allow_direct_registration`). API: `/agent-enrollment/*`,
  `/agents/{id}/signing-key/challenge|rotate`. Tokens can also be used
  right in the browser ("Enroll in this browser"): the keys are generated
  on the page and downloaded, never sent to the server.
- **Strict agent identity by default** - for new and existing
  organizations: agents act only with their own key (`require_agent_key`),
  agents without a signing key cannot delegate or record actions (new
  `allow_keyless_agents`, off), and agent-to-agent messages are enforced
  (A2A mode `enforce`). An admin can relax each per organization; the Agent
  Identity page then shows a warning and asks for confirmation. A suspended
  agent's key no longer authenticates.
- **Signing keys can be revoked.** Append-only revocation list, every entry
  also in the hash-chained audit log; signatures received from
  `untrusted_from` (revocation time, or an earlier `compromised_since`) are
  not trusted - in evidence (`trusted`), in the browser and offline
  (`tools/provenza_sign.py verify --revocations`). Revoked keys can never be
  registered again.
- **Agent rights are computed by the server.** What an action needs comes
  from the Tool Registry (new `required_capabilities` per entry; all
  matching entries count), and requests that declare `action_capabilities`
  are refused with 422. Inside a delegation chain an agent holds what its
  incoming hop granted, capped by its own registration; a hop can also
  hand over only some tools (`delegated_tools`, signed when present), and
  from there tools only narrow. Fixed:
  an agent outside a chain could append hops to it with its full rights
  (now 403 + `not_in_chain` incident), and act in it; depth counted from
  the chain instead of the delegating agent's own hop and ignored the
  root's limit; suspended or retired agents could delegate and receive;
  an expired grant could be passed on; a hop's `verified` flag only meant
  "a signature was attached".
- **Rotating `ENCRYPTION_KEY` re-encrypts the audit keys too**
  (`scripts/rotate_encryption_key.py`); before, checkpoints would have
  stopped after a master key rotation.
- **The audit log is append-only in the database.** A trigger refuses
  `UPDATE`, `DELETE` and `TRUNCATE` on `ai_audit_logs` and
  `audit_checkpoints`; only `scripts/delete_org.py` may delete, by setting
  `provenza.allow_purge` for its own transaction. Changes made by someone
  who can bypass the trigger are caught by the hash chain and the signed
  checkpoints.
- **Process command lines no longer leave the endpoint.** The endpoint
  agent sent the full command line of matched processes, which can carry
  API keys and tokens. It now sends only the product it recognized and
  how (executable, package, module); the backend also drops any
  `cmdline` field an older agent still sends before storing the event.
  Matching is by whole tokens, so unrelated text ("january", a log file
  named after a tool) no longer counts as a detection.

- **Login throttling can no longer be walked around.** The per-account
  counter is keyed by the organization slug as the lookup normalizes it, so
  spellings like `"ACME "` and `" acme"` share one budget; a successful
  login gives back only its own attempt and never resets the per-IP
  counter, so a valid password for one account cannot be used to keep
  guessing others. Each limit now counts only its own counter: the
  per-account check used to bump the IP counter too and judge it against
  the per-account limit, locking an IP out after its third failed attempt.
- **Self-service sign-up is off by default.** `POST /users/register` (new
  organization + admin) answers 403 unless `ALLOW_PUBLIC_SIGNUP=true`, and
  is throttled per IP when enabled. `GET /auth/config` tells the UI.
- **SSRF guard for every admin-supplied URL** — AI providers, gateway
  upstreams, model listing, Vault Transit, webhooks. The address is
  resolved, checked and connected to in one step (no DNS rebinding);
  private and loopback targets need `OUTBOUND_PRIVATE_ALLOWLIST`,
  link-local/metadata is never allowed; redirects are not followed and
  upstream error bodies are no longer echoed to the caller.
- **Use cases are governed objects.** Creating or changing one needs the
  admin role; the linked policy version must be an approved version of the
  caller's organization; a request whose link does not resolve fails
  closed (409). Incidents can only reference the organization's requests.
- **Production refuses placeholder JWT keys** — anything that looks like an
  example value (including the one `backend/.env.example` used to ship) or
  is not random enough; the Docker entrypoint runs the same check.
- **Discovery cannot be used to capture directory credentials.** Only
  gateway/endpoint collector keys may report services; a report never
  moves a known service to another port; the connect wizard must confirm
  the host and port it showed; LDAP binds always use TLS (LDAPS or
  StartTLS) with certificate validation, optionally against an in-house CA;
  reported hosts must be bare hostnames or IPs.

### Upgrade notes

- **Sign-up closes.** Add users by invitation; create organizations with
  `scripts/create_admin.py`. Set `ALLOW_PUBLIC_SIGNUP=true` only for a demo.
- **Internal targets need the allowlist.** An in-house Vault (BYOK), a local
  model server (Ollama, vLLM), internal webhooks or custom providers on a
  private address stop working until listed in `OUTBOUND_PRIVATE_ALLOWLIST`.
  For BYOK this matters most: an unreachable Vault means encrypted data
  cannot be read. The allowlist is server-wide (every organization).
- **Egress proxies.** `HTTP(S)_PROXY` is no longer honoured for these calls;
  set `OUTBOUND_PROXY` instead.
- **LDAP connections need TLS.** A directory connected over plain port 389
  must offer StartTLS with a certificate the server trusts (or reconnect it
  with your CA); until then its re-verification reports an error.
- **Use cases** linked to a draft (unapproved) policy version now refuse new
  requests with `request.policy_version_invalid`; approve the version or
  re-link the use case.
- **Production `SECRET_KEY`** must not look like a placeholder - generate one
  with `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`.
- **Endpoint agent 1.3.0.** Rebuild and redeploy the agent to get agent
  detection. To see other users' processes (behavioral detection reads
  `/proc/<pid>/fd`, `environ`, `maps`) it must run as root or with
  `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`. Older agents keep working
  (their process command lines are now dropped on arrival). Run
  `alembic upgrade head` (new tables `endpoint_devices`,
  `discovered_agents`).
- **Audit log migration** (`alembic upgrade head`, revision
  `d5e8a1c3f7b2`): chains the existing records of each organization in the
  order they were written, adds `audit_checkpoints` and
  `audit_signing_keys` and installs the append-only triggers. Restart
  `celery beat` so checkpoints are signed. The audit key is encrypted with
  `ENCRYPTION_KEY` - keep that key as you already must. Audit records can
  no longer be inserted with raw SQL (the demo seed no longer does);
  deleting an organization's records needs `scripts/delete_org.py`.
- **Audit key rotation migration** (`e3b6d9f2a4c8`): per-organization audit
  keys, `audit_key_rotations`, `audit_key_rotation_approvals`,
  `audit_key_handovers`. Existing organizations keep the server-wide key
  until they rotate. Organizations with a single admin cannot rotate until
  they add a second one - or the operator sets `AUDIT_KEY_ROTATION_QUORUM=1`
  (server-wide).
- **Derived capabilities** (migration `f2a7c4e9d1b3`). Integrations that
  send `action_capabilities` must stop sending it; set
  `required_capabilities` on Tool Registry entries instead (Registry ->
  Tool Registry). Tools without it are checked only against the agent's
  allowed tools, as before.
- **Strict identity defaults** (migration `a8c3e5f1b7d9`): existing
  organizations are switched to `require_agent_key`, no keyless agents and
  A2A `enforce`. Integrations that call Provenza with a user's token in an
  agent's name, or run agents without a signing key, stop working until
  they use the agent's own key (X-Agent-Key) and a signing key - or an admin
  relaxes the setting temporarily (Agent Identity, A2A settings). Downgrading
  this migration does not restore the earlier relaxed values.
- **Enrollment** (migration `b4d6f8a0c2e5`): `POST /agents/register` and
  `POST /agents/{id}/signing-key` answer 403 unless an admin turns on
  `allow_direct_registration`. New agents: issue an enrollment token and run
  `tools/provenza_sign.py enroll` where the agent lives. Existing agents
  keep working; their keys rotate with `provenza_sign.py rotate`.
- **Teams** (migration `c6e8a0b2d4f7`): every distinct `owner_team` of an
  organization's agents and open enrollment tokens becomes a team, and those
  agents and tokens are linked to it. No roles are created - existing agents
  keep their own rights until you assign one.
- **Blocked terms** (migration `b5e7a9c1d3f6`): existing terms move to the
  Blocked terms page and keep applying where they did - gateway settings →
  all agents, policy hierarchy levels → organization / team / agent (the
  key is removed from the level, whose YAML is then shown from the
  document), policy versions → that policy (latest approved version and
  versions linked to use cases). They keep "anywhere" matching; switch them
  to whole word on the page. What applies widens slightly: organization-wide
  terms now also apply to the playground; a policy's terms apply to all its
  use cases whichever version they are pinned to, and to the playground
  while the policy is active. A hierarchy level that had terms loses its
  stored YAML text (comments) - it is shown from the document. `blocked_terms` in gateway settings, in a hierarchy document
  or in a new policy version is refused with a pointer to the page.
- **PII rules** (migration `a3d5f7b9c1e4`): new dependency `regex` - run
  `pip install -r requirements.txt`. Nothing changes until an admin edits the
  page: every built-in type stays on and masks.
- **Kill switch** (migration `f1c3e5a7b9d2`): agents killed before this
  release have no stop to lift and stay suspended until reactivated as
  before. Killing a retired agent now answers `409 agent.retired_final`;
  killing an agent again returns its existing stop.
- **Policy hierarchy** (migration `e9b1d3f5a7c2`): new dependency PyYAML -
  run `pip install -r requirements.txt`. No level exists after upgrading, so
  nothing is enforced differently until an admin writes one.
- **Attestation** (migration `d7f9b1c3e5a8`): no behaviour changes until a
  role requires attestation. A role that had *require attestation* ticked
  before this release names no policy: its agents are refused
  (`agent.attestation_policy_missing`) until you pick a policy or untick it.
- **Removed features keep their data.** The tables of the removed MLOps and
  RAG features (`datasets`, `training_jobs`, `model_deployments`,
  `prediction_logs`, `document_collections`, `rag_documents`,
  `document_chunks`, `rag_query_logs`) and the files under `data/` are left
  untouched; no migration drops anything. The old `DATASETS_DIR`,
  `MODELS_DIR`, `RAG_*_DIR` and `TRAINING_*` settings are still accepted in
  `.env` and ignored. Notification channels subscribed to `training_*` /
  `deployment_*` events simply never receive them. Training jobs that were
  still queued or running keep that status in the kept table, and training
  tasks still waiting in Redis are rejected by the new worker as unknown -
  let the queue drain (or accept the loss) before upgrading.

## [0.2.1] - 2026-09-19

### Added

- **Discovery connect handlers (LDAP/AD, DNS)** — the explicit-connect
  wizard now really connects. For Active Directory/LDAP it performs a
  real `ldap3` bind with the admin-supplied read-only credentials, does
  one bounded read (naming context + capped person count), and stores
  the connection with the bind password encrypted at rest (Fernet). For
  DNS it runs a credential-less reachability probe. Unsupported service
  types still report honestly instead of faking success.
- **`service_connections` table** — holds connected-service state and
  encrypted secrets for discovered infrastructure, separate from
  `ai_providers`.


## [0.2.0] - 2026-09-18

### Added

#### Shadow AI Monitor
- **Telemetry ingestion pipeline** — batched, asynchronous ingestion
  (`POST /shadow-ai/ingest`) authenticated by a machine key
  (`X-Ingestion-Key`), processed on Celery. Every event is stored raw
  for later behavioral analysis; domain visits are classified against
  the org's catalog into allowed / blocked / unknown.
- **Endpoint Agent** — a native Go binary that detects locally-running
  AI tools: processes (`ollama`, `vllm`, `lmstudio`, …), listening
  ports, and model weight files on disk.
- **Network Discovery** — passive discovery in the agent: DNS servers,
  default gateway, Active Directory / Kerberos / LDAP (DNS SRV), plus
  mDNS and LLMNR. ARP scan and passive DHCP run automatically when the
  agent is granted `CAP_NET_RAW` (probed at runtime). ARP discovery
  sends requests only — never forged replies.
- **Explicit-connect wizard** — `/discovery` lists discovered services
  read-only; connecting to one (AD/DNS/firewall) requires an admin to
  supply credentials for that specific service. No anonymous auto-attach.
- **Browser Extension (Manifest V3)** — flags visits to known AI
  services and warns the user before pasting or typing secrets (API
  keys, cards, private keys) into an AI tool. Reports only that a
  detection happened — never any fragment of the value.
- **Self-service extension download** —
  `GET /shadow-ai/extension/download` packages the extension
  preconfigured with the server URL and a fresh, org-scoped ingestion
  key (admin only).
- **AI Domain Catalog** — per-org allow/block/unknown classification of
  AI domains (`/domain-catalog`) with known-domain autofill hints.
- **Ingestion Sources** — machine credentials for agents/collectors
  (`/ingestion-sources`); keys hashed with SHA-256 and shown once.
- **Sightings enrichment** — human-readable detail (port, file, device),
  a "seen N times" repeat counter, and per-agent deduplication for local
  signals.
- **`shadow_ai_blocked_domain`** notification event.

#### MLOps
- **RAG service** — build knowledge bases from PDF/DOCX/TXT
  (`/rag/collections`), retrieve and chat over them. TF-IDF by default
  (character n-grams for morphologically rich languages), auto-upgrades
  to neural embeddings when the optional ML stack is present.
- **Simple Mode** — a guided, jargon-free wizard (`/simple`) taking a
  non-technical user from task selection to a working model, auto-choosing
  RAG vs fine-tuning from the data shape. Includes file auto-parsing into
  Q&A pairs and a pre-training preview chat.
- **`ui_mode` preference** — per-user Simple/Advanced interface choice,
  independent of role (`PUT /users/me/ui-mode`).
- **Deployment Manager** — versioned model deployments with
  `POST /deployments/{id}/predict` and `POST /deployments/{id}/chat`.
- **A/B routing** — `POST /deployments/by-name/{name}/predict` picks a
  version proportional to `traffic_weight`.
- **In-UI Playground** — `/playground` lets you chat with any active
  deployment without leaving the app.
- **Webhook events** for deployment lifecycle:
  `deployment_created`, `deployment_updated`, `deployment_archived`.
- **Docker isolation per training job** — each job runs in a dedicated
  container when `TRAINING_USE_DOCKER=true`.
- **SSE progress stream** for training jobs
  (`GET /training-jobs/{id}/stream`).

#### Platform
- **Prompt Firewall NER layer** — person names, organizations, and
  locations are masked in addition to the regex detectors. Configurable
  via `PROMPT_FIREWALL_NER_ENABLED` / `PROMPT_FIREWALL_NER_MODEL`.
- **Dashboard metrics** — `/dashboard` shows a 7/14/30/90-day request
  trend line, distributions by status/severity, and live counters.
- **i18n** — full English + Uzbek coverage, plus machine-readable error
  codes translated on the frontend.
- **Pagination** on every list endpoint (`?skip=0&limit=50`).
- **CI pipeline** on GitHub Actions: backend tests, frontend build,
  security scan, compose validation. Dependabot for dependency updates.
- **Test suite** covering auth, RBAC, approvals, firewall, requests,
  pagination, and the ML pipeline.
- **Administrator guides** — `USER_GUIDE.md` (English) and
  `USER_GUIDE.uz.md` (O‘zbekcha).

### Changed

- **Telemetry ingestion is asynchronous** — `POST /shadow-ai/ingest`
  returns `202 Accepted` and hands the batch to a Celery worker.
- **Celery database sessions** use a dedicated `NullPool` engine so that
  short-lived `asyncio.run()` task loops never reuse asyncpg connections
  bound to a closed loop.
- **README** rewritten to document the full platform (Shadow AI Monitor,
  RAG, Simple Mode, agent, extension, discovery), all environment
  variables, the API router map, and the updated security model.
- `input_text` is now stored encrypted at rest and no longer returned by
  the API; only `masked_input_text` is exposed.
- Approver assignment is server-side: policies can name a specific
  approver, otherwise an available admin/approver is selected.
- Rate limit on `/auth/login`: 10 attempts per IP and 5 per email
  within 5 minutes.
- `users.email` is unique per organization instead of globally; login
  requires `org_slug`.
- `training_jobs.task_type` widened to 50 chars.
- `users.role` is now a plain VARCHAR — adding a role no longer requires
  an enum migration.

### Fixed

- **Cross-event-loop asyncpg error** ("got Future attached to a different
  loop") in Celery tasks — affected both telemetry and request workers.
- **Browser extension** — restored broken template literals (the previous
  build could not load), removed a `preview` field that leaked the first
  characters of detected secrets to the server, and stopped sending full
  page URLs.
- **Extension** — real batching (previously one HTTP request per event),
  per-tab navigation deduplication, and a stable per-install agent id.
- **CSV auto-parsing** tolerates malformed rows (unescaped delimiters)
  instead of failing the whole upload.
- **RBAC** — Override Console creation restricted to admin/approver.
- **Audit log listing** — fixed an undefined `skip` parameter that broke
  every `GET /audit-logs/` call.
- Prompt Firewall no longer masks ISO dates as phone numbers.
- Event loop mismatch in pytest-asyncio fixtures (session/function scope).
- Race in `_update_progress` that could overwrite `status` / `finished_at`.
- `cancel_job` and `retry_job` race conditions.
- `_detect_gpu` fallback when torch is installed but built for CPU only.
- Various N+1 query fixes via cached model loading (`lru_cache`).
