# Security model

What Provenza protects, how, and where its guarantees stop.

## Data and access

- **Prompt Firewall.** Before a prompt is stored or sent to a provider,
  e-mails, card numbers, SSNs, IP addresses, API keys and phone numbers
  are replaced with `[MASKED:TYPE]`, along with your own patterns
  ([PII rules](pii-rules.md)). Disguised values are found too: invisible
  characters, full-width forms, look-alike letters, spaced-out text,
  base64 and hex. The raw prompt is kept only encrypted and is never
  returned by the API.
- **Blocked terms.** They are kept on one page with scopes. A prompt
  containing a blocking term is refused before it reaches a provider; a
  monitored term lets the prompt through and is counted
  ([blocked terms](blocked-terms.md)).
- **Intent guardrail.** A classifier model on your own connection reads
  the already-masked prompt and flags or refuses forbidden intents
  ([intent guardrail](intent-guardrail.md)).
- **Provider credentials.** They are encrypted at rest with Fernet. The
  API never returns a key, only `has_credentials: true/false`.
- **Machine vs. user auth.** Collectors (the endpoint agent and the
  browser extension) authenticate with an `X-Ingestion-Key` tied to an
  Ingestion Source, never with a user's JWT. Keys are stored hashed
  (SHA-256) and shown once, at creation.
- **Identity provider.** Sign-in uses OpenID Connect (code + PKCE, a
  verified `id_token`, accounts bound to the provider's subject). SCIM
  switches people off, and with them their sessions and their agents'
  keys ([identity provider](identity-provider.md)).
- **Explicit connect only.** Network discovery is read-only. Connecting
  to a discovered AD, DNS or firewall requires an admin to supply
  credentials for that specific service. There is no anonymous
  auto-attach and no ARP spoofing: ARP discovery sends requests only,
  never forged replies.
- **Least-privilege agent.** The endpoint agent runs as an unprivileged
  user. ARP and DHCP discovery need the single `CAP_NET_RAW` capability,
  which the agent probes at runtime ([Shadow AI](shadow-ai.md)).
- **Extension privacy.** The browser extension reports only *that*
  sensitive data was detected (type and label), never any fragment of the
  value, and it does not send full page URLs.
- **Network isolation.** In the production stack (`deploy/`), Postgres and
  Redis sit on an internal container network and only Caddy publishes ports
  (80/443). In a manual setup, the backend (8000) and the frontend (3000)
  bind to `127.0.0.1`. Forwarding headers are trusted only from
  `TRUSTED_PROXIES`.
- **Outbound calls.** URLs that admins configure (AI providers, Vault,
  webhooks, identity providers, time-stamp authorities) cannot reach
  private or internal addresses unless those addresses are listed in
  `OUTBOUND_PRIVATE_ALLOWLIST`. The check is made at connect time, so a
  host name that resolves to an internal address is refused too.
- **Audit trail.** Every change writes a row to `ai_audit_logs`. A trigger
  refuses `UPDATE` and `DELETE`. Records are hash-chained and covered by
  signed Merkle checkpoints, optionally time-stamped by an RFC 3161
  authority, so a change is detectable by anyone who kept an earlier
  checkpoint ([audit proofs](audit-proofs.md)).

## Agent governance: guarantees

These apply to agents with a signing key, whether agent-held or generated
by the server at registration.

- **Agent-held keys.** The agent generates its Ed25519 key pair and
  registers only the public key. The server never sees the private key and
  cannot sign as the agent. Keys can be replaced. Every key is kept with
  the period it was current, and each signed record keeps the key that
  verified it, so old records stay verifiable.
- **Signed delegations.** A delegation from an agent with a registered key
  must be signed over `{from_agent_id, to_agent_id, task,
  delegated_capabilities, chain_id, expires_in, nonce, issued_at}` in a
  fixed canonical form ([spec](agent-signing.md)). Unsigned or tampered
  requests are rejected. The exact signed text is stored on the hop, so
  anyone can re-verify it offline.
- **No replay.** Each delegation nonce is single-use per agent (enforced
  by a database unique constraint). Requests older than 5 minutes are
  rejected, and the TTL counts from the signed `issued_at`, so a late
  resend cannot extend a delegation.
- **Capabilities only narrow.** A hop may delegate only a subset of what
  the delegating agent holds in that chain. A superset is rejected and
  raised as a `capability_escalation` incident. Depth and TTL are bounded
  the same way: a child delegation cannot outlive its parent.
- **What was checked is what gets recorded.** `/actions/check` issues a
  single-use `check_id` (valid for 5 minutes) bound to the agent, the
  chain, the tool and a SHA-256 of the input. `/actions/record` must
  present it for exactly that action and be signed by the agent. A
  mismatch is rejected and raised as an `action_mismatch` incident. The
  stored verdict is the one from check time.
- **Post-quantum hybrid (optional, can be required).** A hybrid key pairs
  Ed25519 with ML-DSA-65 (FIPS 204). Every record carries both signatures
  over the same bytes and is valid only if both verify, so a forgery
  needs both schemes broken. That includes a future quantum computer,
  which would break Ed25519 alone. One fingerprint covers both keys. An
  organization can require hybrid keys for all signing agents.
- **Offline-verifiable history.** Hops and recorded actions keep the exact
  signed payload, the signature and the signer key. The browser check and
  `tools/provenza_sign.py verify` recompute the key fingerprint
  themselves. Matching it against the fingerprint the agent's owner holds
  is what removes the server from the trust chain.

## Agent governance: limitations

What this does **not** do:

- **Tool calls are reported by the agent.** Model calls that go through
  the LLM gateway are enforced there. Tool calls are seen only when the
  agent reports them: an agent, or a compromised host, that calls its
  tools directly without `/actions/check` and `/actions/record` is
  invisible to Provenza. Two things narrow this gap where they are
  deployed: [egress lockdown](egress-lockdown.md) leaves an agent one way
  out, through the Provenza egress proxy, and the
  [egress sensor](../sensor/README.md) enforces the agent's egress policy
  in the kernel (cgroup BPF), so a direct call to a destination that is not
  allowed fails and is reported.
- **Server-generated keys are a convenience, not evidence.** The
  quick-start option generates the key pair on the server and returns the
  private key once. The key is not stored, but the server had it at that
  moment. Such keys are labelled in the UI and in evidence files; use
  agent-held keys where independence from the server matters.
- **The fingerprint check is yours to do.** A valid signature proves the
  record matches the key. That the key belongs to the agent is
  established by comparing fingerprints with its owner, outside Provenza.
- **`/actions/check` is not signed.** The binding to a specific action and
  the agent's signature are enforced when the action is recorded.
- **Keyless agents** (created without a key) stay on the unsigned,
  cooperative path.

Report vulnerabilities privately, as described in [SECURITY.md](../SECURITY.md).
