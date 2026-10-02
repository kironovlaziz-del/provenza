# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

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
