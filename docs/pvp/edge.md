# PVP enforcement at the edge (draft)

Status: **in progress**. Implemented: section 2 (passkeys, session keys,
one session per person), section 3 (signed approvals, signed policy
releases) and section 4 for the egress proxy - its decision and evidence
(it verifies releases, agents' signatures and approvals itself, evaluates
the bundle and signs receipts with its own key), sealed credentials (§4.1)
and the gateways' protocols executed by the proxy (spec.md §5.5), and
section 5 (the sensor follows the signed policy, lets out only a pinned
proxy binary, runs only administrators' signed commands) and sections 6-7
(offline operation, the local kill switch, the reconciliation and the
quorum's lift). The rest (the agent mode) is the plan for the stage that
follows. The current behaviour is described in
[spec.md](spec.md).

## 1. Goal

A compromised Provenza server must not be able to make an agent act, to
loosen a policy, to forge a human approval, to read a provider's or an
API's credential, or to rewrite the evidence. It may still stop service
(refuse, go down) and read metadata; that is the limit.

The rule that gives this: **no single party holds everything an action
needs**. An action runs only when three independent parties agree, and the
server is none of them.

| party | holds | signs |
|---|---|---|
| the agent | its own key (as today) | the request: exactly this action (`input_sha256`) |
| the administrators | a passkey each, on their own device, unlocked by the device PIN | the policy bundle, the key manifest, approvals, kill-switch decisions, sensor commands |
| the enforcement point (proxy, with the eBPF sensor on its host) | its own key, generated on its host; the credentials of the upstreams it serves | the receipt: "I checked the agent's request against the signed policy, executed it, here is what happened" |
| the Provenza server | nothing secret | nothing an enforcement point relies on |

The server keeps the interface, distributes what the others signed,
collects evidence and computes what needs history (the circuit breaker,
the behaviour baseline, rate limits). Those can only **add a denial** to
what the signed policy allows; they never allow anything.

No hardware security module is required. An enforcement point may keep its
key in a TPM, vTPM or cloud KMS where one exists; the evidence then says so
(`key_storage`), as TRACE states its level today.

## 2. Administrator keys

### 2.1 The anchor: a passkey

Each administrator registers a passkey (WebAuthn, platform or roaming
authenticator) under *My profile*. Every use requires user verification:
the device PIN, or the device's biometric where the device offers it. The
PIN never leaves the device; the server never sees or stores it.

The first administrator's passkey is pinned when the first enforcement
point is enrolled (the installer shows its fingerprint to confirm). Every
later passkey - a new administrator, a replaced phone - enters the **key
manifest** (§4) only with the signatures of the quorum of administrators
already in it. Removing one needs the same.

### 2.2 Session keys

Signing with the passkey on every click would be unusable, so each sign-in
creates a session key:

1. After the password (and two-factor) sign-in, the browser generates an
   Ed25519 key pair with WebCrypto, **non-extractable**: page scripts can
   use it but cannot read it. It is kept in the browser's IndexedDB for the
   session only.
2. The administrator confirms the passkey once (device PIN). The passkey
   signs a **session certificate**: the session key's public key, the
   administrator, the session id, `not_before` and `not_after` (the session
   lifetime: the sign-in token's, `ACCESS_TOKEN_EXPIRE_MINUTES`).
3. During the session every signature (§3) is made with the session key,
   without further prompts. Enforcement points accept a session signature
   only with a certificate signed by a passkey that is in the manifest.
4. Signing out deletes the key from the browser and publishes a revocation
   signed by the session key itself; expiry ends it anyway. A new sign-in is
   a new key and a new certificate.

The server cannot mint a session certificate: it has no passkey.

### 2.3 One session per person who signs

Administrators and approvers (the roles that sign) have one session at a
time. When one of them signs in while a session of theirs is open, the new
session is **blocked**: it can only wait (`GET /auth/session`), end the
other session with the passkey, or cancel. The open session immediately
sees it - time, address, browser - in a banner, an incident
(`session_conflict`) is opened and the `session_conflict` notification goes
out. The open session then

- **lets it in** with the passkey: a `provenza.session.admit` statement
  naming the blocked session. A person who has no passkey yet confirms with
  the password instead;
- or **refuses** it: the blocked session ends.

The blocked session may **take over** - end the person's other sessions -
only with the passkey (`provenza.session.takeover`), for when the open
device is closed, lost or out of reach; that is an incident too. Someone who
knows the password but holds no passkey can neither get in nor push the
owner out, and never gets a session certificate.

A password change ends every session of the person; the sign-in that
changed it continues in a new session.

### 2.4 Registering passkeys

*My profile → Passkeys* (`POST /users/me/passkeys/options`, then
`POST /users/me/passkeys`). The password is asked again. A person who already
has a passkey confirms the new one with an existing one
(`provenza.passkey.add` naming the new credential), so a stolen password
alone cannot plant a passkey; removing one needs the password and a passkey
(`provenza.passkey.remove`). Provenza requests no attestation and keeps the
public key only. ES256, EdDSA and RS256 keys are accepted; every use must be
user-verified (PIN or biometric), and a signature counter that goes back (a
copied authenticator) is refused.

The relying party is the host of the first `CORS_ORIGINS` entry
(`WEBAUTHN_RP_ID` overrides it); the allowed origins are `CORS_ORIGINS`.

## 3. Signed objects

Every statement has a `type`, so one kind never passes for another, a
version `v`, the organization and the person, and `issued_at`. It is
signed in its canonical JSON (sorted keys, no whitespace, non-ASCII
characters escaped - `app/core/agent_signing.canonical_bytes`): a passkey
signs SHA-256 of it as its WebAuthn challenge, a session key signs it
directly (Ed25519). The server builds each statement and accepts back only
exactly that statement, at most five minutes old.

| object | signed by | content |
|---|---|---|
| `policy.bundle` | quorum of administrators | everything that decides allow or deny (§3.1), `version`, `previous` (hash), `not_after`, `offline_seconds` |
| `key.manifest` | quorum | the quorum, the people who sign (administrators and approvers) with their passkeys' public keys, agent key fingerprints, egress proxies and sensors, the sensor command key; later fingerprints of upstream credentials (HMAC under the enforcement point's key, not the secrets) and the expected proxy binary hash |
| `approval` | one administrator or approver (session key) | the held action's id, its agent, chain, action type, tool and `input_sha256`, the decision (spec.md §3.1); kept with the session certificate and the passkey's public key, carried in the receipt of the call it released |
| `killswitch` | administrator (engage) / quorum (lift) | scope, reason, the reconciliation report hash when lifting a local kill (§7) |
| `sensor.command` | administrator | as today's signed commands, now with a session signature instead of the server's |
| `session.allow` | the administrator's passkey, from the open session | the blocked session's public key (§2.3) |

A change made in the interface goes to the **working copy**; a change that
loosens anything takes effect when the quorum has signed a release that
contains it. The quorum is part of the manifest (default 1, recommended 2).

### 3.1 Signed policy releases

A **release** (`/policy-releases`, the *Signed policy* panel on the policy
page) freezes the working copy into the two documents:

- **bundle**: agents' rights (status, team, capabilities, tools, models,
  delegation depth), agent policies, the policy hierarchy and teams, the
  Tool Registry (mode; approved and blocked entries with pins and required
  capabilities - pending entries allow nothing a missing one would not),
  agent identity settings, the provider policy, the AI domain catalog
  (classified domains), the LLM gateway's settings and routes, MCP
  servers, A2A peers, HTTP tools and egress routes - their configuration,
  never their credentials;
- **manifest**: as in the table above.

An administrator prepares a release; the panel lists what it changes
against the release in force, item by item, with the hashes the passkeys
will sign. Each administrator signs `provenza.policy.release` (organization,
person, release number, both documents by version and SHA-256,
`not_after`) with a passkey - a PIN prompt each. Who may sign, and how many
must, comes from the manifest of the release in force when the draft was
prepared; the first release is signed by the quorum its own manifest
states. A passkey added or a quorum lowered meanwhile counts only from the
release that contains it. Preparing a new draft withdraws the old one with
its signatures.

Once a release is in force, an action is allowed only when **both** the
working copy and the release allow it (`app/pvp/signed_policy.py`):

- tightening in the interface (suspending an agent, taking a tool away, a
  deny rule, blocking a domain, a stricter setting) applies at once;
- loosening applies only after the quorum signs it;
- an agent that is not in the release, or whose key is not the one in the
  manifest, cannot act; an MCP server, A2A peer, HTTP tool, egress route or
  gateway route that would carry the call must be in the release exactly as
  configured now (the call goes where the row says, so a changed row serves
  nothing until signed);
- an approval releases a held call only when the passkey behind the
  approver's session is the one the manifest lists for them;
- a release that does not verify (hashes, the quorum's passkey signatures,
  back to the first release) or whose `not_after` has passed allows
  nothing, and the first is an incident (`signed_policy_invalid`). The next
  release is then governed by the latest release that still verifies.

`GET /policy-releases/{id}` returns a release as signed, with the governing
manifest; `tools/provenza_audit.py release` checks it offline.

**What the server's check alone does not cover.** Whoever controls the
server or writes to its database can delete the releases and fall back to
the working copy, or present a different first release - for the server's
own decisions. An egress proxy enforcing the signed policy is not fooled by
either: it pins a manifest, verifies every release itself and keeps the last
one it verified (spec.md §5.5). The server's own gateways (LLM, MCP, A2A,
HTTP tools) serve only upstreams that take no credential; the others are
reached through a proxy (§4).

## 4. Enforcement points

The egress proxy (`proxy/`, Go) becomes the enforcement point for every
protocol:

- **Adapters** (stage 9, `proxy/internal/egress/act.go`, `app/pvp/proxy_actions.py`):
  plain egress routes, HTTP tools (`/_tools/call`), OpenAI chat completions
  to OpenAI, Groq, Azure OpenAI, Anthropic and custom connections
  (`/_llm/v1`), MCP (`/_mcp`) and A2A (`/_a2a/<peer>`). The agent speaks its
  own protocol and gets the answer in the same protocol; inside, every call
  is a PVP action: the proxy asks the server for a plan (the server decides
  as its gateway does and records a refusal at once, and sees only what its
  gateway records - for an LLM call the messages' count and hash), judges it
  itself under the signed policy, sends it with the credential and reports
  status, token counts and hashes with its receipt. The proxy syncs the MCP
  servers and A2A peers it serves (tools and cards go to the Tool Registry
  as an admin's sync would) and hashes live definitions itself.
- **Decision**: the proxy verifies the agent's signature, evaluates the
  signed bundle itself and asks the server only for its deny-only checks.
  The policy logic exists twice (Python, Go); a shared set of test vectors
  (`sdk/testdata/policy-vectors.json`) runs against both in CI.
- **Credentials**: entered in the interface and encrypted in the browser to
  the proxy's public key, or entered on the proxy host. The server stores
  ciphertext only. The proxy decrypts into memory only.
- **Evidence**: the proxy signs each receipt with its key and keeps its own
  hash-chained log; the server's seals and checkpoints cover them as today.
- **Agent mode** (stage 12, `proxy/internal/egress/agentmode.go`): the
  same binary runs next to an agent as a local adapter, signing with the
  agent's key for clients that cannot sign (stock MCP, OpenAI and A2A
  clients, plain HTTP for an egress route): `provenza-proxy -agent-identity
  <the SDK's identity file> -listen unix:<path> -upstream <proxy>`. It
  listens on a unix socket of mode 0600 (only the agent's user reaches it;
  a loopback TCP address is allowed, with a warning: any local process
  reaches that), signs each request as below and passes it
  on with the agent's key.

An action runs only if: the agent's signature verifies, the bundle allows
it (or a signed approval covers it, once, §3.1 of spec.md), and the server
did not deny it.

### 4.1 Sealed credentials

The server holds no credential it can read (`backend/app/pvp/sealed.py`,
`app/services/credentials.py`, `proxy/internal/egress/sealed.go`,
`frontend/lib/sealing.ts`):

- **The proxy's encryption key.** Derived on the proxy host from its signing
  seed (HKDF-SHA256, `provenza proxy encryption key v1`), so its one key file
  holds both. The X25519 public half is registered once, signed by the
  signing key (`{"type": "provenza.proxy.encryption_key", "v": 1, "key"}`);
  another key later is refused - a new key is a new proxy. Its fingerprint is
  in the signed manifest (`egress_proxies.<id>.encryption_key_fingerprint`)
  and the proxy logs both fingerprints on start.
- **Sealing.** An administrator types the credential of a route, AI
  connection, MCP server, A2A peer or HTTP tool; the browser checks each
  proxy's encryption key against its signing key and seals the credential
  to it - X25519 with an ephemeral key, HKDF-SHA256 (salt: both public keys,
  info: a label and the canonical context), AES-256-GCM with the context as
  associated data. The context is `{org_id, object, object_id, proxy_id,
  upstream}`, `upstream` being the origin (scheme, host, port) the
  credential may be sent to: the server cannot move an envelope to another
  object or another proxy, and pointing an object at another host does not
  take its credential along - the proxy sends a credential only to the
  origin it was sealed for, so an object whose address changed needs its
  credential sealed again (the interface says so).
  Only envelopes reach the server; one in clear text is refused
  (`credential.plaintext_refused`) on every API that took one.
- **Who sealed it.** The administrator signs the envelopes with their
  session key: `provenza.credential.sealed` names the object, its origin
  and the SHA-256 of each proxy's envelope (`POST
  /api/v1/egress/credentials/{object}/{id}/statement`; the browser checks
  the digests against the envelopes it made before signing). The proof
  travels with each envelope. A proxy in `policy.mode` "enforce" opens an
  envelope only when an administrator of the signed manifest it verified
  vouched for exactly it (`proxy/internal/trust/sealer.go`), so the server
  cannot slip in a credential of its own choosing (its own account at the
  same API, say). Envelopes the server made from the credentials it held
  before are vouched for by an administrator after *Seal and erase*
  (*countersign*); the browser cannot see what those hold - that was the
  server's word, once. An envelope whose sealer left the signed manifest
  stops opening: seal it again.
- **Opening.** A proxy fetches the envelopes sealed to it
  (`GET /egress-proxy/credentials`), opens each one only for the context it
  expects, and keeps the credentials in memory. A credential that does not
  open is not used: the request is refused (`proxy.sealed_credential_missing`).
  A credential can also live only in the proxy's configuration
  (`credential_source: "local"`).
- **What the server held before.** Credentials stored before stage 9
  (encrypted with the server's own key) are used by nothing. An
  administrator seals them once to every proxy with a key
  (Gateways → External APIs → Proxies, *Seal and erase*) and they are erased; a
  proxy added later needs them entered again.
- **The server's own gateways** (LLM, MCP, A2A, HTTP tools) serve only
  upstreams that take no credential; one whose credential is sealed is
  refused there and reached through a proxy.

What sealing does not cover: a server that serves another version of the
browser code (§8); and, for a proxy not in enforce mode (it knows no
signers), a server that seals a credential of its own choosing to it.
Python, Go and the browser make and open the same envelopes
(`sdk/testdata/trust-vectors.json`, `sealed`).

### 4.2 Enforce mode

Stage 12 (`backend/app/pvp/enforcement.py`, `proxy/internal/egress/agentsig.go`).
The mode is part of the signed policy: the bundle's `enforcement` section
(`{"mode": "enforce"}`; absent means observe, so releases signed before it
are unchanged), set under Policies → Signed policy → settings. It is in
force when the working copy or the release in force says so: switching it on
takes effect at once, switching it off only with a release the quorum signed.
In enforce mode no action runs anywhere without the two signatures - the
agent's own and the quorum's over the policy that allows it:

- **This server's gateways execute nothing** (LLM, MCP, A2A, HTTP tools):
  their calls are refused and recorded. Every MCP server and A2A peer is
  served by the egress proxies, whatever their credential.
- **The REST check-then-act path only observes**: `/agents/actions/check`
  answers as before but issues no permit, and what an agent records about
  itself is recorded as an observation.
- **The egress proxy** takes, on every path, only requests the agent signed:
  `X-Provenza-Request`, the agent's `action.request` with `action_type`
  "proxy" and `tool_name` "proxy.<route>" over the HTTP request it sent -
  `{route, method, path, query_sha256, body_sha256, body_bytes}`, `route`
  being the first path segment (`_tools`, `_llm`, `_mcp`, `_a2a` or an
  egress route). It verifies the signature with the key fingerprint the
  release names for the agent, fresh and once, and judges the action under
  the release with that key verified. The SDKs sign (the HTTP tool call
  through a proxy too); other clients go through agent mode.
- **The server verifies it again**: a proxy says it enforces the signed
  policy (`X-Provenza-Proxy-Mode: enforce`; one that does not takes part in
  nothing); a plan carries the agent's signed request and the request it
  describes (`X-Provenza-Request`, `X-Provenza-Descriptor`), verified with
  the agent's registered key, its nonce used once; a mediated check with the
  signed request is the agent's own check (`action_checks.agent_signed`),
  and a check the agent did not sign is not redeemed.
- **What a proxy reports** without a receipt naming a release that was
  signed with that bundle and the agent's verified signature raises a
  critical `unenforced_action` incident.

What enforce mode does not cover: the server cannot see the body a proxy
received - the body hash in the signed request is checked by the proxy, the
server checks the signature and the rest; a request's body under a plan is
the proxy's word. Reads (model lists, agent cards, MCP `tools/list`) are not
actions and need no signature. A proxy that is not in `policy.mode`
"enforce" is refused, and so are clients that cannot sign and are not
behind agent mode.

## 5. The eBPF sensor

On the agent hosts, the sensor (enforce mode) lets agent workloads reach
only their enforcement point. On the proxy host it lets out only the proxy
process whose binary hash is the one in the manifest. Commands to sensors
need an administrator's signature.

A sensor follows the signed policy when it is given a pin (`policy.pin`,
as an egress proxy): it fetches the releases (`GET
/egress-sensor/policy-release`) and takes one only when the quorum of the
manifest it already trusts signed it, keeping the last one in its state
directory. From that release:

- **Workloads** (`egress_workloads` in the bundle). The server's policy for
  sensors is not signed, so the sensor holds each workload the release
  names to its signed version: a destination the server adds is applied
  only when the signed workload allows it too; a stricter mode, an
  isolation, a removed destination apply at once; the signed cgroup
  patterns, users and agent are matched first, and a workload the server
  deletes or disables stays governed as signed. The agent's egress, signed
  as "only its enforcement point", cannot be widened by the server.
  (`sensor/internal/daemon/signedwl.go`)
- **The proxy binary** (`proxy_binaries` in the manifest: SHA-256 hashes
  the administrators set with the quorum and validity). `provenza-sensor
  --proxy run -- provenza-proxy ...` puts the proxy in a cgroup that is
  held - nothing in or out - until every process in it runs a pinned
  binary and none is traced; checked five times a second, a traced process
  stays held until it exits. (`sensor/internal/daemon/proxyrun.go`)
- **The proxy configuration** (`proxy_configs` in the manifest: SHA-256 of
  the configuration files, `sha256sum proxy.json`). The pinned binary
  tells the sensor the SHA-256 of the configuration it read, on the run
  socket (`PROVENZA_SENSOR_SOCKET`); the sensor takes it only from a process
  of that run cgroup running a pinned binary, untraced, and keeps it with
  the process's start time. The cgroup stays held until every process
  reported a pinned configuration: the pinned binary run with another
  server, another pin or `policy.mode` "off" gets nothing out.
- **Commands** (`signers` in the manifest). Detach, restart and dump-state
  run only when an administrator's session key signed
  `provenza.sensor.command` for this sensor and kind, the session was
  certified by a passkey the manifest lists for an administrator, the
  statement has not expired (Provenza makes it valid for 4 minutes; a
  sensor takes at most 5 - it cannot learn that the signer signed out
  meanwhile), and its nonce was not used before. The
  organization's command key, which the server holds, does nothing there.
  (`sensor/internal/trust/command.go`, `docs/sensor-commands.md`)

A sensor without a pin keeps today's behaviour (the server's policy as
sent, the organization's key for commands, `proxy_binaries` from its own
configuration) and says so in its warnings. What the sensor verified (pin,
release, each proxy's state) is reported with its heartbeat and shown on
its page. The signed commands are made by the server's code and checked by
the sensor's (`sdk/testdata/sensor-command-vectors.json`); the sensor
carries a copy of the proxy's `internal/trust`, kept identical by a test.

Root on a host defeats its sensor (it can stop it or change the kernel);
on a proxy host, `kernel.yama.ptrace_scope=3` keeps anyone from changing
the running proxy's memory, which a binary hash cannot see.

## 6. When the server is unreachable

- The proxy and the sensors keep working with the last bundle they verified,
  counting time with a monotonic clock from the last successful contact (a
  changed system clock does not help). An answer that refuses their key
  (401; for a sensor also 403) is no contact: a revoked key, or someone
  answering in the server's place, does not keep the kill switch away.
- After `offline_seconds` (in the bundle, default 900) without the server,
  the proxy refuses every action and the sensors deny all agent traffic: a
  **local kill switch**. The server cannot extend this time; it is signed.
- A bundle past its `not_after` is never used, so an old bundle cannot be
  replayed.

Cutting the network therefore stops the agents. Losing control does not
follow from it.

How it is done (policy.mode "enforce" on the proxy, `policy.pin` on the
sensors):

- **Offline actions.** Without the server there is nobody to check a request,
  so the proxy takes, while the server does not answer, only egress-route
  requests the agent signed itself and sent without a check id - the SDKs do
  that on their own when the server is unreachable
  (`proxy_request_headers` / `proxyRequestHeaders`). The agent's signature
  must verify with the key the release's manifest names for it, once; the
  release must allow the call outright (one that needs a person's approval or
  belongs to a delegation chain waits for the server); the route is the
  signed one. Each request, sent or refused, is kept with the proxy's receipt
  in `state_dir/offline.jsonl` and handed to the server when it answers again
  (`POST /egress-proxy/offline-actions`): it becomes an ordinary action,
  executed by the proxy, with the agent's signature and the receipt as its
  evidence; one that does not verify is recorded too, with a critical
  incident. An agent's key alone (the mediated mode) is not taken offline.
  The other adapters (HTTP tools, LLM, MCP, A2A) refuse while the server is
  unreachable. (`proxy/internal/egress/offline.go`, `app/pvp/proxy_offline.py`)
- **The proxy's kill switch** engages after `offline_seconds` without an
  answer and is kept in `state_dir/killswitch.json` with the release held
  before the outage: a restart does not lift it. (`killswitch.go`)
- **The sensors' kill switch** isolates every workload after `offline_seconds`
  without an answer (the time of the last answer is kept in
  `state_dir/contact.json` across restarts) or when the release is past its
  `not_after`, and lifts itself when the server answers again: the agents then
  still reach only their proxy, which stays stopped until it is lifted. The
  proxy's own cgroup on its host is not isolated - it must reach the server
  to be lifted. (`sensor/internal/daemon/killswitch.go`)

## 7. Recovery after a local kill switch

1. The server is back. The proxy stays stopped and fetches the current
   state.
2. The proxy compares it, item by item, with its last signed manifest:
   agent keys, administrator passkeys and quorum, enforcement point and
   sensor keys, Tool Registry pins, credential fingerprints, the proxy
   binary hash.
3. Every difference becomes an incident in the proxy's signed log and is
   shown in the interface: the **reconciliation report**.
4. Lifting the stop needs the quorum's signatures over the report's hash: the
   administrators confirm what they saw. A difference that is a substitution
   (a key that was not changed through a signed manifest) has to be undone,
   or accepted by a separate quorum signature, before the stop can be lifted.
5. After lifting, a new manifest is signed.

Only keys from the manifest the proxy held **before** the outage count for
these signatures, so a passkey the server slipped in meanwhile cannot lift
anything.

How it is done: the proxy compares the server's working copy (`GET
/egress-proxy/reconciliation`: the manifest and the Tool Registry) and the
envelopes sealed to it with the release and envelopes it held when the kill
switch engaged. A difference the newest release it verified states is marked
*signed*; any other is not. The report - with no time in it but the moment
the switch engaged, so it does not change while nothing changes - is signed
with the proxy's key, kept in its receipt log and sent (`POST
/egress-proxy/kill-switch`); the server opens an incident for each difference
and notifies (`kill_switch`). Under Gateways → External APIs → Proxies each
administrator of the release held before the outage signs with a passkey

    {"type": "provenza.kill_switch.lift", "v": 1, "org_id", "user_id", "proxy_id",
     "report_sha256", "accept": [the differences not signed], "issued_at",
     "expires_at"}

- every unsigned difference must be in `accept`: accepting it is the separate
signature step 4 asks for, made in the same signature; undoing it instead
changes the report, and the signatures over the old one no longer count. The
proxy fetches the signatures (`GET /egress-proxy/kill-switch/lift`), checks
each itself against that manifest (`proxy/internal/trust/lift.go`), lifts when
the quorum is reached, logs the lift and tells the server. A signature counts
for 12 hours (`expires_at`; the proxy refuses one valid for more than a day,
and an expired one). A credential sealed again during the outage is a signed
difference when an administrator of the newest verified release vouched for
its envelope (§4.1). Step 5 - a new
release - is the administrators' next step; the interface says so.

## 8. Threat model

| compromised | can | cannot |
|---|---|---|
| Provenza server | refuse service; read metadata; hide data in the interface (the proxy's own log shows it) | make an agent act, loosen a policy, forge an approval or a session, read credentials, rewrite evidence |
| an enforcement point host | use that proxy's credentials while it controls the host | act beyond the signed bundle without detection (its receipts and the agents' signatures do not match); last past a manifest that revokes its key |
| an agent | act within its rights | act outside the bundle, reach anything except its enforcement point |
| an administrator's device | sign as that administrator | reach a quorum alone when the quorum is 2 or more |
| the network | stop the agents (local kill switch) | make them act |

**Residual risk to discuss**: the interface is a web page the server
delivers. A compromised server could deliver a modified page that, during an
open administrator session, signs something other than what it shows.
Options: a quorum of 2 for policy changes (a second person on a second
device sees the draft), showing the hash of what is signed on the device, or
delivering the administration interface from a separately pinned bundle.

## 9. Stages

| stage | what | migration |
|---|---|---|
| 5 | passkeys in *My profile*; session keys and certificates; one session per administrator with the blocked-second-session flow | nothing required yet |
| 6 | approvals signed with the session key | old approvals stay valid records |
| 7 | signed `policy.bundle` and `key.manifest` in releases signed by the quorum; the server allows only what both the working copy and the release allow | nothing changes until the first release is signed; then it is bundle and manifest version 1 |
| 8 | the egress proxy evaluates the bundle, verifies releases, agent signatures and approvals, signs receipts with its own key; shared policy test vectors (Python, Go) | proxies with `policy.mode` "off" keep today's behaviour, and their receipts say so (`policy: null`) |
| 9 | adapters in the proxy; credentials encrypted to the proxy; the server's credential storage is removed | credentials the server held are sealed once to the proxies with keys and erased (*Seal and erase*); a proxy added later needs them entered again |
| 10 | sensor: egress only for the pinned proxy binary; signed commands; workloads held to the signed release | sensor upgrade; `policy.pin` on each sensor (`enroll --policy-pin`); sign a release naming the proxy binaries and the workloads; the proxy started through `provenza-sensor --proxy run` |
| 11 | offline operation, local kill switch, reconciliation and lifting | none (enforce-mode proxies and pinned sensors only; set `offline_seconds` in the signed policy settings) |
| 12 | agent mode of the proxy; enforce mode: no action without the two signatures anywhere (§4.2) | the REST check-then-act path becomes observation only in enforce mode; proxies in `policy.mode` "enforce" and upgraded; clients that cannot sign go through agent mode; then set *Mode: enforce* and sign a release |
