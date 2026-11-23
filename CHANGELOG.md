# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Simple mode, the console's new default**: four tabs - **AI agents**, **Rules** (the policy hierarchy with its levels, rule packs and signed policy, and the **Gateways** agents reach models, tools and APIs through), **Audit log** and **Shadow AI** - with Settings (you, people, notifications) and Help beside them. The top bar keeps **Stop all** and adds a bell with what waits for a decision (approvals and open incidents, opening the Inbox) and, for administrators, whether the protection works (**Protected**, **Needs attention** or **Setup unfinished**, from the protection coverage). **Settings → Open the full console** shows every page as before, and **Back to simple mode** returns; the browser remembers the choice. Every page keeps its address and opens in either mode; nothing changes on the server. Help (English and Uzbek), the quickstart and the self-hosting guide describe both.
- **Connect an agent in two steps** (**AI agents → Connect an agent**, administrators): tick the tools the agent may use - the gateways' approved tools are offered, those awaiting approval are named - then copy the one command that enrolls the agent on the client's machine and connects the client. **Start over** revokes the unused token. Teams, roles, models and a key registered by hand stay on the full registration form; simple mode shows only **Connect an agent** on the agents page.
- **Shadow AI → What works** (administrators): where the sightings come from and whether each source reports now - the browser extension and the endpoint agent with their state from the protection coverage, and DNS and proxy logs with the button that imports them.
- **The audit log is published outside the server**: every hour by default (5 minutes to 24 hours), the latest signed checkpoint goes to **Sigstore Rekor** (`rekor.sigstore.dev`), a public append-only transparency log - on by default, on new and existing installations. Only the SHA-256 of the checkpoint's statement, a signature by the organization's new publishing key (ECDSA P-256) and that key leave the server, never the log. Rekor's answer is verified (the entry sent, its signed entry timestamp with the key Sigstore distributes) before it is kept; failures are shown and retried every 5 minutes. Publications are append-only and travel with the checkpoints. **Audit Log → Publication outside the server** shows each target with the host it sends to, the last publication and the last failure; administrators set the interval, publish now, switch Rekor off or point it at another instance (API: `GET`/`PUT /audit-logs/publication`, [docs](docs/audit-proofs.md#publication)). An installation without internet access shows the failure and keeps working.
- **Audit log publication to S3 with Object Lock**: an administrator adds a bucket (Amazon S3 or an S3-compatible store - MinIO, Backblaze B2, Wasabi, Ceph) under **Audit Log → Publication outside the server**. Each publication writes the signed checkpoint as one object locked in compliance mode for the days chosen (1 to 3650, 365 by default), so nobody - not the bucket's owner either - can delete or overwrite it before then; the lock is read back after every write, and a bucket that does not lock is refused. Saving tries the bucket first with a test object locked for one day. Requests are signed with AWS Signature Version 4 (checked against Amazon's published examples); the secret key is kept encrypted ([docs](docs/audit-proofs.md#publication)).
- **Argument rules in the policy hierarchy** (`tools.arguments`, [docs](docs/policies.md#argument-rules)): a level of the organization, a team or an agent now also says what a tool may be called **with** - a refund of at most 100 without a person, e-mail only to your own domain, files only under one folder - with the effect `deny` or `require_approval`. Every level's rules apply (a lower level can only add), a refusal names the level and the rule, and under a signed policy a rule taken out keeps applying until the next signed release. They are the rules of the Agent Policies page, checked the same way and failing closed, and they apply wherever the hierarchy does: agent actions, the MCP gateway, and the egress proxy from the signed policy (new shared vectors). Under Rules → Policy hierarchy the form edits them (**Argument constraints**), and *Effective policy* lists each rule with its level; own rule packs may add them, built-in packs do not. Compliance counts them for OWASP ASI02.
- **Public test vectors for verifying the audit log** (`sdk/testdata/audit-vectors.json`, [docs](docs/audit-proofs.md#test-vectors)): 43 cases - record proofs, checkpoints, consistency proofs, audit key changes, RFC 3161 time-stamps and Rekor publications, valid and tampered - each with the verdict a verifier must reach and why, among them a real checkpoint published in the public Sigstore Rekor. `tools/audit_vectors.py` runs `tools/provenza_audit.py`, or any verifier with the same command line (`--exec`), over all of them; CI checks every case with the standalone tool and with the server's own code.
- **The offline verifier checks the publications** (`tools/provenza_audit.py checkpoint` and `consistency`): each Rekor entry a checkpoint carries must be a `hashedrekord` of exactly that checkpoint's statement, signed by the publishing key, with a signed entry timestamp that verifies with the log's key - the key Sigstore distributes is built in, `--rekor-key` adds another instance's. `--require-rekor` requires at least one (for `consistency`, on the older checkpoint), `--publishing-key` pins the organization's publishing key; the S3 copy is the checkpoint itself and verifies with `checkpoint` ([docs](docs/audit-proofs.md#publication)).
- **Agent frameworks** ([docs/integrations.md](docs/integrations.md); Python SDK 0.3.0): **LangGraph** - a graph's tools governed, and a call that policy holds for a person pauses the graph (`interrupt()`) until the decision, then runs once if approved; the **OpenAI Agents SDK** - function tools governed and the model through Provenza's LLM gateway. Every tool wrapper (LangChain, LangGraph, OpenAI Agents SDK, CrewAI, AutoGen) can now wait for a person's decision (`approval="wait"`) instead of refusing a held call. CI tests each integration against its real framework.
- **OpenTelemetry export of PVP decisions** ([docs](docs/opentelemetry.md)): an administrator points Provenza at an OpenTelemetry collector (**Settings → SIEM & OpenTelemetry → OpenTelemetry**), and every policy check, recorded action, LLM gateway call, delegation and incident goes there as an OTLP log record (OTLP/HTTP, JSON) within about a minute: event names `pvp.*`, PVP's own attributes (`pvp.decision`, `pvp.policy.id`, the OWASP codes) and the OpenTelemetry GenAI conventions where one fits (`gen_ai.agent.id`, `gen_ai.tool.name`, `gen_ai.request.model`, token usage). Metadata only, as in the live view: never arguments, prompts, outputs or reasons. Saving sends a test record first; one optional header (a collector's or vendor's key) is kept encrypted and never shown. The export starts when it is switched on, keeps events waiting while the collector is down, drops a batch the collector calls malformed, and shows the last success and failure. The endpoint is outbound traffic through the SSRF guard: HTTPS, or plain HTTP to a host in `OUTBOUND_PRIVATE_ALLOWLIST`. The page **SIEM export** is now **SIEM & OpenTelemetry**.
- **The agent's trace context is kept** ([docs](docs/opentelemetry.md#the-agents-trace)): a W3C `traceparent` sent with a request (or, for MCP, in `params._meta.traceparent`) is stored with the check, the recorded action and the LLM gateway call it produced, so the exported decisions appear inside the agent's own trace. Correlation only: it takes no part in a decision or in the signed evidence, and an invalid value is ignored.

### Security
- **The MCP gateway no longer sends an exception's text back to the caller.** A malformed signed-request header (`X-Provenza-Action`) is still refused with a reason, but the reason is now one of Provenza's own fixed texts (the header is not base64url JSON, the fields it may hold, which field is invalid); any other error is reported as `malformed` and stays on the server.
- **Container images take the base image's security fixes** (`apt-get upgrade` when the image is built), and the web UI now runs on **Node.js 24** (the active LTS) instead of Node.js 20.
- `pyasn1` (used by `ldap3` for directory discovery) is pinned to 0.6.5, a release without the known denial-of-service issues.

### Changed
- **Supply chain of the build** ([OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/kironovlaziz-del/provenza)): every GitHub Action is pinned to a full commit SHA, on releases that run on Node.js 24; Dependabot keeps the pins current and now also updates the sensor's and the endpoint agent's Go modules.
- **CI checks the Go programs for known vulnerabilities** (`govulncheck`, with the Go toolchain the images are built with): a vulnerability the code reaches fails the check when a fixed version exists; one without a fix yet, or in code that is imported but not called, is shown as a warning.
- **Fuzz tests** for what the egress proxy and the eBPF sensor read from outside - the canonical JSON every signature is taken over, the agent's signed request header and the release documents - run their seeds with the tests and explore for 15 seconds per target on every change.

## [0.5.0] - 2026-11-19

### Added
- **The egress self-check runs by itself** for an agent connected with **Agents → Connect an AI client**: `provenza-proxy connect` checks the machine once the client is connected and prints the verdict (`confined` or `open`), agent mode checks again when it starts and once a day, and `provenza-proxy egress-check` checks on demand. Protection coverage shows whether each agent can only go through Provenza without anyone running the check by hand.
- **Protection coverage**, next to the setup checklist (Settings, and the dashboard when something stopped working): whether each part of the protection works now, not only whether it was set up - the signed policy (in force, a release waiting for signatures, changes not signed yet), the egress proxy (online, following a signed release), agents signing their own calls, agents shown confined by the egress self-check in the last 30 days, the eBPF sensor (online, enforcing, without errors), and the endpoint agent and browser extension (machines and browsers reporting). Each part is working, needs attention or not set up, with the facts it was judged on and how to fix it (`GET /api/v1/system/setup`, `coverage`).
- **Rule packs** ([docs/policies.md](docs/policies.md#rule-packs)): a **Rule packs** tab on Policies → Policy hierarchy with 18 built-in packs - 8 profiles that replace a level's policy (strict or balanced organization, support, engineering, finance and read-only research teams, a new or external agent, lockdown) and 10 guards that only add restrictions to it (destructive actions, money, exfiltration, secrets, production, identity, code execution, mass messaging, personal data export, models). Each is applied to the organization, a team or an agent after a before-and-after preview, and every application can be undone: a guard's undo takes out exactly what it added, a profile's puts the previous policy back (asking first if the level was edited since). Applying and undoing save the level like an edit - revision, audit log naming the pack, and under a signed policy an undo applies with the next signed release. Administrators create, copy, edit, upload and download their own packs as YAML (`/api/v1/policy-packs`).
- **Try it on a computer in a minute** (`docker-compose.try.yml`): Provenza from published images, nothing to build. A release now publishes `ghcr.io/kironovlaziz-del/provenza-backend` and `provenza-web` for amd64 and arm64, with a build provenance attestation ([docs/releases.md](docs/releases.md#container-images)). The try stack makes its own keys and passwords on the first start, listens only on 127.0.0.1, and signs in as `admin@example.com` / `provenza-try-local`.
- **Example: a governed refund agent** ([examples/governed-refund-agent](examples/governed-refund-agent/)): a support agent in Streamlit whose every tool call Provenza decides. A refund over $100 waits for a person's passkey-signed approval, e-mail goes only inside the company, and a prompt injection in a ticket that asks for the customer list is refused. The shop's API runs nothing without a Provenza permit for exactly that call. Runs with OpenAI, a local model through Ollama, or a scripted model without any key.

### Changed
- **A sign-in no longer ends 30 minutes after it began while you work in it.** The console renews its token while there is activity (`POST /api/v1/auth/session/renew`, which revokes the old token): a sign-in now ends after 30 minutes without activity (`ACCESS_TOKEN_EXPIRE_MINUTES`) or 8 hours after it began (`SESSION_MAX_HOURS`), whichever comes first. The passkey certifies an administrator's or approver's session key once per sign-in, up to its 8 hours; a session certified before this release asks for the passkey again when its old certificate runs out.

## [0.4.0] - 2026-11-17

### Added
- **The quickstart, tested end to end**: on every change a fresh machine runs `install.sh`, then a browser goes through [docs/quickstart.md](docs/quickstart.md) - sign in, approve two MCP tools, register the agent, run the connect command from the page, call a tool, refuse it with one line of policy, verify the receipt offline (`.github/workflows/quickstart.yml`, `e2e/quickstart.py`).
- **Signed releases with an SBOM** ([docs/releases.md](docs/releases.md)): a tag `vX.Y.Z` publishes the source archive, an SBOM in SPDX and CycloneDX, a release record (`release.json`: tag, commit, tree, hashes) and `SHA256SUMS`, each signed with a keyless build provenance attestation (`gh attestation verify`). `install.sh` and `upgrade.sh` check a tagged release against its record and warn loudly when the tag in the checkout is not the published commit.
- **Hidden text in tool definitions** ([docs/hidden-text.md](docs/hidden-text.md)): what a person approves is now what the agent's model reads. An MCP tool, A2A agent card or HTTP tool whose definition hides text a person cannot see - Unicode tag characters spelling instructions, bidirectional controls, control characters, data in variation selectors - cannot be approved and is not served to agents, even one approved before this release. Zero-width and other invisible characters, private-use characters and long blank runs need the approver to confirm having seen them; the approval's audit record says so. The approval screens show the whole definition with every invisible character written out and hidden text decoded. Emoji, accents and other scripts are not affected.
- **Incident bundle** ([docs/incident-bundle.md](docs/incident-bundle.md)): one file to investigate an agent incident - **Incidents → Agents → Investigation file**, or `GET /api/v1/pvp/incidents/{id}/bundle` (by default from an hour before the incident to a quarter of an hour after it). It carries the agent's actions in the window shown to be all of them, the audit records about the agent and about what governs every agent (the kill switch, the behaviour monitor, policy releases), the agent's own signed request for each call it asked for - so a refused call is the agent's word, not the server's - and the tasks, approvals and release people signed with their passkeys. `tools/provenza_audit.py incident` checks every signed piece offline and prints one timeline, each line saying who vouches for it; what rests on the server's word (an unsigned check, the incident itself unless its record is in the signed log) is named, and `--require-full` makes that a failure. A quarantine is now recorded in the signed audit log (`agent` / `quarantined`) with the refusals or the signals that led to it, for automatic containment and the behaviour monitor alike.
- A completeness report now takes in the whole last second of its period: an action recorded in the fraction of a second after `until` began was left out.
- **Automatic containment** ([docs/containment.md](docs/containment.md)): an agent refused three times within ten minutes for reaching past what it was given - a tool, model, route, provider or task it has no right to, a capability it was not delegated, a call a policy denies - is quarantined at once, whatever the behaviour monitor's mode. Every later call is refused, the chains it started are tripped, the calls it left waiting for a person are closed, and a critical incident names the refusals that led to it. Refusals that are not the agent's doing (it was stopped, a chain halted, a tool changed upstream, a task ended) do not count. A **tripwire tool** - a decoy no agent has a reason to call - quarantines on the first call. **Behavior Monitor → Settings → Automatic containment** turns it off or tunes the limit, the window and the tripwires.
- Releasing an agent from quarantine is now signed with the administrator's session key and names the quarantine it ends (`POST /agent-behavior/agents/{id}/release/statement`, then `.../release` with `{statement, signature}`); an approval given before the release is not redeemed after it, nothing is approved for a quarantined agent, and the agent's edit form no longer switches a quarantined agent back on.
- **Try the demo** on the welcome page: one click signs a visitor in to the public demo. Shown only on a server where a demo is set up (`provenza demo enable`); it signs in the demo's read-only account and no other.
- **A task from a person, signed** ([docs/proof-of-authority.md](docs/proof-of-authority.md#a-task-from-a-person)): an administrator or approver gives an agent a task on its page (**Task from a person**) - what to do, which of its tools it may use for it, for how long - signed with the session key their passkey certified. The agent names the task in its signed request (`mandate_id`; SDKs: `agent.task(id)` / `withTask` / `WithTask`; agent mode names the agent's task in force on every MCP tool call by itself, so a stock MCP client needs no change - or the client names one with `X-Provenza-Mandate-Id` or `params._meta["provenza/mandate_id"]`), Provenza refuses a call outside it (another agent, another tool, ended or expired; a delegated helper acts under its chain root's task), and the action's evidence names it. Ending a task is signed as well (or it is replaced by the next signed task), so when it stopped being in force is a person's word, not the server's. A task counts only inside the agent's own signed request - named with the agent's API key alone, the call is refused. Proof of Authority then starts with the person who asked, and `tools/provenza_audit.py authority` checks the signed task like every other link. **Agent identity → Require a task from a person** refuses calls that name none (off by default). Requests that name no task are signed exactly as before.
- **Proof of Authority** ([docs/proof-of-authority.md](docs/proof-of-authority.md)): for one agent action, one file with the whole chain of authority behind it - the policy release administrators signed with their passkeys (verified back to the organization's first release), the agent's rights and key in it, each delegation hop signed by the delegating agent, the agent's own signature on the call, the approver's passkey listed in the signed manifest, and the receipt down to the signed checkpoint. `tools/provenza_audit.py authority` checks every link offline and names the links that are not proven (no signed release in force, an agent that did not sign) instead of passing them silently. **Audit Log → Evidence → Download proof of authority**, or `GET /api/v1/pvp/authority/{action_id}`.
- **Completeness report** of an agent over a period: the sealed batches now name the one before them, so a run of them shows every action Provenza recorded for the agent - a dropped action or a dropped batch is caught. `tools/provenza_audit.py completeness`; **Audit Log → Evidence → Completeness report of an agent**, or `GET /api/v1/pvp/completeness`.
- An action's evidence names the signed policy release its verdict was given under, and keeps the agent's own signed request when it sent one. Agent mode now signs each MCP tool call (`X-Provenza-Action`), so an action the MCP gateway executed is signed by the agent, not only identified by its key; the egress proxy relays the header. Evidence of older actions keeps its form and its hash.
- **A welcome page at `/`** for visitors who are not signed in (a signed-in user still goes straight to the dashboard): what Provenza does, one agent call played step by step - allowed, then refused by policy - with its audit record and receipt, the problems it solves, how it works, and the way to sign in. Black and white with a deep grid; nothing on it comes from the server, so a visitor learns nothing about the organizations there. English and Uzbek. `/login` is unchanged.
- **Quickstart** ([docs/quickstart.md](docs/quickstart.md)): from `install.sh` to Claude Code calling an MCP tool through Provenza, refused by one line of policy and proven offline with the receipt and `tools/provenza_audit.py`. `backend/tests/test_quickstart.py` walks the same steps on the server, so the guide breaks the build when it goes stale. Linked from the README, the docs index, self-hosting and the installer's last message.
- Long lists scroll in their own box, the table header on top: the incidents (platform and agents), the open incidents in Inbox (each now opens its own incident) and the tool registry. An incident's browser string shows two lines in the list, whole on its page. The tool registry's unlabeled "✕" is now **Remove**, saying what removing does in Monitor and Enforce mode.
- **Allowed tools are checked and can be edited.** Under "Allowed tools" (a new agent, and the agent's page) the console points out a name that matches no MCP server or HTTP tool (a typo, or a tool the server renamed) and a tool not approved yet; on the agent's page an admin edits them in place (**Edit tools**; not when a role sets the rights). `GET /agents/gateway-tools` lists the names, each with whether an agent holding it sees it.
- **Retiring a stopped agent ends its own stop.** A stop of that one agent had nothing left to hold once the agent was retired, yet stayed *in force* for good. It now ends with the retirement, recorded like a lift (audit `kill_switch` / `lifted`, `retired: true`, nothing given back) and shown as *Ended: agent retired*. Stops of a team or of every agent stay. On the Kill switch page, the stops in force (from four) and the history (from nine) scroll in place instead of stretching the page.
- An agent's **Recent actions** show each action's number, linking to its receipt (Audit Log → Evidence opens with it, `?action=<id>`). After Connect, a link opens the new agent.
- `provenza-proxy connect`: a client's own command (`claude mcp add`) that has not finished in 60 s is stopped and connect says what to run by hand, instead of hanging the window; on Windows the console shows `ok` instead of a check mark it cannot draw. Agents → Connect hides the other ways to use the token once Connect has spent it. On Windows, `agent-start` (run at sign-in) closes its console window at once - closing it by hand while agent mode was starting stopped it - and writes what it did to agent mode's log.
- HTTP tools: the arguments are checked against the input schema all the way down, by the server and by the egress proxy with the same rules and shared test vectors (`sdk/testdata/schema-vectors.json`): types, `enum`/`const`, nested `properties`/`required`/`additionalProperties`, `items`, lengths, ranges, `pattern` (RE2 on both sides: linear time, no ReDoS). A schema keyword the check does not understand (`$ref`, `anyOf`, ...) is refused when the tool is saved and when it is called. New backend dependency: `google-re2`.
- HTTP tools: a body can be sent as a form (`body_encoding: "form"`, string arguments only); the Python and JS SDKs' permit middleware read a form body back into the same arguments (`form_input`, `formInput`).
- Shadow AI: a finding on a local model port shows whether a model API answered there (which one, its models) or not; on Agents Found the confidence says why (hover). Documentation: what discovery does not see, collectors' HTTPS + machine key (no client certificates), the eBPF sensor enforces and does not discover.
- Endpoint agent: a local model port is checked with the model API that belongs there (`/api/tags`, `/v1/models`, `/api/config`; only on `127.0.0.1`, no proxy, no redirects, 256 KB at most). A finding says whether a model API answered (*confirmed*), which one, and its model names; a port where none answers is reported with a low risk instead of as a model server.
- CI: `connect.ps1` is tested end to end on Windows (Windows PowerShell, the real `provenza-proxy.exe`, a stand-in server): download and checksum, enrollment, the client's entry, agent mode and its sign-in entry, a second run over the running agent, removal.
- Endpoint agent on Windows: network discovery reports the DNS servers and the default gateway from the adapters' settings (the adapters that are up, the preferred one first; IPv6 placeholders and link-local addresses are not servers), and the adapters' DNS suffixes are used as domains for the Active Directory lookup, as `/etc/resolv.conf` is on Linux.
- Endpoint agent on Windows: LLM SDK libraries (`jiter`, `tiktoken`, `tokenizers`) are found among the loaded modules of likely agents (interpreters, processes connected to an LLM API), as on Linux. Only module paths are looked at, and only for those names.
- Agents → Connect for Windows: a *System* choice beside the client gives a PowerShell command (`/api/v1/agent-enrollment/connect.ps1`) that does what `connect.sh` does with `provenza-proxy-windows-*.exe`: downloads and checks it, enrolls the agent (its keys stay on that machine) and connects the client. Needs the Windows binaries of this release in the image.
- `provenza-proxy` for Windows (`provenza-proxy-windows-amd64.exe`, `-arm64.exe`, served next to the Linux ones): its `enroll` and `connect` commands run on Windows. Agent mode starts in the background and at the user's sign-in (the user's own Run key, no administrator rights). The identity file is limited to its user (`icacls`) when it is made, and refused when anyone else could read it. The one-command Connect for Windows follows.
- README: the Agent Manifest issuer is listed in AgenTrust's integrations (community tier).
- `robots.txt` and `sitemap.xml`. Closed by default: robots.txt keeps every crawler out and there is no sitemap. A public demo or project site opens the sign-in page to search engines with `ALLOW_SEARCH_INDEXING=true` and `PUBLIC_BASE_URL` in `deploy/.env`.
- Self-hosting: Provenza's Caddy can serve other applications on the same server. Site blocks go in `/etc/provenza/caddy-sites/*.caddy`, and the applications join the `provenza_sites` network, which they share only with Caddy.

- **Agent Manifest** ([docs/agent-manifest.md](docs/agent-manifest.md)). Every
  agent's page has an **Agent Manifest** button
  (`GET /agents/{id}/manifest`, `/manifest.cose`): a signed record of the agent
  in the open AgenTrust Agent Manifest v0.2 format, checkable offline with the
  `agent-manifest` SDK. It binds the agent's SPIFFE identity, its approved MCP
  tool catalog (schema and description hashes, Merkle root), the root of the
  organization's signed audit log and whether its actions need a person's
  approval; what Provenza does not see is declared unbound (`composition-only`
  profile). Signed by the organization's audit key as a hybrid Ed25519 +
  ML-DSA-65 COSE_Sign, reissued when what it binds changes, chained to the one
  before, each issue recorded in the audit log.

- **DNS and proxy logs as a Shadow AI collector**
  ([docs/shadow-ai.md](docs/shadow-ai.md#dns-and-proxy-logs)). An
  administrator uploads a log on **Shadow AI → Import logs**, or a log
  forwarder posts new lines with a Gateway ingestion key
  (`POST /shadow-ai/ingest/logs`). Squid, BIND, dnsmasq / Pi-hole, Unbound,
  the Windows DNS debug log, Zeek, JSON lines, key=value (Fortinet, CEF) and
  CSV exports with a header (Cisco Umbrella, Zscaler, Netskope, Palo Alto) are
  recognized line by line, gzip included. Only lines that reach an AI service
  (the AI Domain Catalog plus the built-in list) are kept, folded into one
  visit per service, person and computer with its line count; they become
  sightings (source *DNS log* / *Proxy log*), people per service and incidents
  for blocked services like the browser extension's visits. Nothing else of a
  log is stored; addresses in a log do not become Devices.

- **Endpoint agent for Windows and macOS** (agent 1.5,
  [docs/shadow-ai.md](docs/shadow-ai.md#endpoint-agent)). The agent now runs
  on Windows 10/11 and Server 2016+ (amd64, arm64), macOS 12+ (Intel, Apple
  silicon) and Linux, and installs itself as a service:
  `provenza-agent install --server … --key -` registers a Windows service
  (`ProvenzaAgent`, LocalSystem, restarted on failure), a LaunchDaemon or a
  systemd unit, with the key readable by administrators only; `status` and
  `uninstall [--purge]` go with it. Provenza builds and serves the six
  binaries and two installers (`install-agent.ps1`, `install-agent.sh`) next
  to the sensor; **Ingestion Sources** shows the one-line install command for
  each system when an *Endpoint agent* key is created, and the guide covers
  Intune, Group Policy, Jamf and Ansible. Processes are listed natively on
  each system (Toolhelp and the process command line on Windows, sysctl on
  macOS); unknown agents are found by their connections to LLM APIs there,
  and by API key names on macOS. **Devices** names the system (macOS,
  Windows, Linux). Not code-signed yet.
- **The endpoint agent no longer loses findings offline.** Batches the server
  does not accept (no network, 5xx, 429, 401/403) wait in a queue on disk,
  bounded at 50 MB, and are sent oldest first with a growing pause, also
  after a restart. Model files are attributed to the user whose home folder
  holds them; without `model_search_paths` the agent scans every user's
  Ollama, Hugging Face, LM Studio, GPT4All and Jan folders.

- **Who uses an AI service.** Browser extension 2.1 sends the person's
  e-mail with each visit when the organization sets it by user-level policy
  (`userEmail`; Windows logon script or Intune, a macOS profile - see
  [docs/shadow-ai.md](docs/shadow-ai.md#who-uses-the-browser-useremail)). A
  domain sighting shows how many people visited it and how many browsers did
  not say who; reviewers, auditors and compliance officers open the list:
  who, how often, how often blocked, when last
  (`GET /shadow-ai/{id}/people`). The server keeps nothing from an extension
  but a well-formed address. Plain users see the count, no longer the names.

- **Browser extension 2.0: the organization's AI policy in the browser**
  ([docs/shadow-ai.md](docs/shadow-ai.md#browser-extension)). The extension
  reloads the organization's AI Domain Catalog every hour
  (`GET /shadow-ai/extension/catalog`, with its ingestion key) instead of a
  fixed list of 15 sites: it watches every catalogued and built-in AI
  service, and **closes the blocked ones** with a "not allowed" page that
  offers the allowed services instead. Its server and key can come from
  Chrome / Edge policy (managed configuration), so that people can neither
  change nor remove them; the guide covers Windows, macOS, Linux and the
  Google Admin console. Unsent events survive the worker's restarts and are
  retried when the server cannot be reached. The secret-paste warning stays,
  in the browser only: nothing about it is reported any more.
- The built-in AI domains know ChatGPT's current address (`chatgpt.com`),
  `cursor.com`, and Grok, DeepSeek Chat, Le Chat, Qwen, Kimi, Meta AI,
  NotebookLM, Google AI Studio, v0, Bolt, Lovable, Windsurf and others.

- **A simpler console: one top bar instead of the sidebar.** Four tabs -
  **Inbox**, **AI**, **Rules**, **Evidence** - with **Search** (Ctrl K) for
  any page, **Stop all** for admins, **Help** and **Settings** behind icons
  and an account menu (profile, language, theme, sign out). The 16 sidebar
  sections are gone; every page keeps its address and sits as a tab of one
  of the four. While a stop is in force, a red line says so on every page
  ([USER_GUIDE.md](USER_GUIDE.md#2-finding-your-way-the-top-bar)).
- **Inbox**, the start page of admins, approvers, auditors and compliance
  officers: approvals (decided in the list, signed as before), open incidents
  of the organization and of agents, and shadow AI and agents found that
  nobody reviewed yet, with the last seven days beside them. Plain users
  start on the AI list. `/dashboard` now sends each role to its start page.
- **Settings** page: every setting the role may open, in groups, with what
  each is for; the setup checklist on top for admins. The checklist also
  shows the egress proxy, the network sensor and single sign-on (optional).
- **Help**: guides for administrators, approvers, auditors and compliance
  officers, and employees; an article for each feature (Inbox, approvals,
  AI inventory, agents, shadow AI, policies, kill switch, incidents, audit
  trail, compliance, account security, users and roles, notifications) and
  the FAQ - in English and Uzbek, searchable, linked to the pages they
  explain.

- **`provenza-mcp`: the MCP gateway for desktop clients** (Python SDK 0.2.0,
  [sdk/python/README.md](sdk/python/README.md#integrations)). MCP clients that
  start servers as a local command (Claude Desktop, Claude Code, Cursor,
  Gemini CLI, VS Code) run `uvx provenza-mcp` with `PROVENZA_URL` and, on the
  first start, an enrollment token: the agent enrolls with its own keys and
  every message goes to the organization's gateway as that agent.
  `server.json` describes it for the official MCP Registry, `glama.json` for
  Glama.
- **A public demo on your own installation** ([docs/self-hosting.md](docs/self-hosting.md),
  "A public demo on this installation"). `provenza demo enable` makes an
  organization of its own and fills it through the API the way real agents
  would (`backend/scripts/demo_seed.py`): agents enrolled with their own keys
  (hybrid where the image has ML-DSA), a signed delegation chain, allowed,
  denied and held actions, a refused capability escalation, Shadow AI findings.
  Visitors sign in as its auditor. `DEMO_ACCOUNTS` (comma-separated e-mails)
  keeps a shared login from changing its own password, second factor or
  passkeys (`demo.read_only`). The organization is made again every night
  (`provenza-demo.timer`); only one the demo made is ever deleted.

### Security
- Next.js 16.4.6 (from 16.4.3): GHSA-mfr8-8qww-v76h, an information disclosure through `'use cache'` with `unstable_cache()`. Provenza uses neither, so it was not exposed.

- **A plain user no longer reads the audit trail or the incidents.**
  `GET /audit-logs` and `GET /incidents` (list and one) were open to every
  signed-in user and showed who did what, from which IP address and browser.
  They now need an administrator or approver (auditor and compliance still
  read them). Anyone may still report an incident; the audit proofs, keys and
  integrity check stay open. The Incidents and Audit pages are hidden from
  plain users accordingly.
- `follow-redirects` 1.16.2 in the console (GHSA-mrwp-f3q8-3g9p).
- **A second sign-in's incident tells what became of it.** Each blocked sign-in of an administrator or approver keeps its own incident (`signing_sessions.incident_id`, migration `e1f2a3b4c5d6`), and the outcome is written into it: let in from the open session (passkey, or the password while there is none) or the other session ended with the passkey resolves it - the person confirmed it; refused, or signed out while waiting, keeps it open. A takeover no longer opens a second incident. While the sign-in waits, its incident page offers **Let in** and **Refuse**, as the banner does, and the banner links to the incident.
- Passwords are hashed with `bcrypt` 5.0.0 directly; `passlib` (unmaintained, broken with bcrypt 4.1+) is gone. Every existing hash verifies unchanged, nothing to migrate: a password over 72 bytes that passlib cut silently still signs in. A new password over 72 bytes (UTF-8) is refused - by the API, `create_admin` and the installer - instead of being cut. A missing or malformed stored hash is a wrong password, not a server error.
- Sign-in: an unknown organization or e-mail now takes as long as a wrong password (one bcrypt check against a dummy hash), so the response time no longer tells which accounts exist.

### Fixed
- `upgrade.sh` stopped with "Broken pipe" right after listing what is new when more than 15 commits came in: the list was cut with `head`, which under `pipefail` ended the script. Nothing had been changed yet.
- Agents with a post-quantum hybrid key (the default) were refused by Caddy 2.11.6 and later: their signed request travels in headers of about 16 KiB, and Caddy lowered its header limit to 16 KiB (from 1 MB). Agent mode answered `502 provenza_proxy_unreachable`. The Caddyfile now allows 64 KiB of headers. An installation that pulled a newer Caddy image was affected after its next restart. Found by the end-to-end quickstart test.
- Installing on a host whose AppArmor container profile denies signals inside a container (seen on GitHub's Ubuntu 24.04 machines): PostgreSQL's first start could not stop its temporary server and the installation failed. `install.sh` now checks this before starting anything and says how to fix it ([troubleshooting](docs/self-hosting.md#troubleshooting)). Services also wait until PostgreSQL accepts connections, not just until its port is open, so a first start or a recovery no longer fails the migrations. Found by the end-to-end quickstart test.
- PostgreSQL now runs as its own user from the start (`User=postgres`): on some Ubuntu 24.04 machines the image's switch from root with `gosu` spun at 100% CPU and the database never started ("postgres is not reachable"). Nothing in the PostgreSQL container runs as root any more. Found by the end-to-end quickstart test.
- Installing on a server where Docker is installed: Docker's FORWARD policy (DROP) with `br_netfilter` dropped even traffic between containers of one Podman network, so the backend could not reach PostgreSQL and the migrations failed. `forward.sh` now also accepts traffic bridged within one Podman network - no route between networks and none out of the internal one - and `provenza status` checks it. Found by the end-to-end quickstart test.
- AI Inventory: the page no longer shows "Could not load the inventory" on a first visit until it is reloaded. Its two requests both discover new systems; the one that lost the race failed instead of answering.
- Things made on first use no longer fail when two requests need them at the same moment (each of these was an error once, gone on a retry): an agent's behavior baseline under two calls at once, the egress sensor settings and command signing key of a new organization, a Tool Registry entry, two syncs of one MCP server. Two egress policy changes at once now get two revisions (they could get one, and a sensor holding the first would not fetch the second). An organization's first audit key is made once (two first uses at once could make two, and what one signed would not verify under the other). The same signed task sent twice at once is accepted once.
- A change that loses such a race anywhere else (a second click on a first Save) answers 409 "Someone else changed this at the same moment. Try again." instead of an unexplained 500.
- The signed-policy note at the top of every page ("N policy changes take effect only after signing") now goes away as soon as the release is signed, and appears as soon as a change is saved - it used to wait up to a minute or for a reload.

- `provenza-proxy connect` on a computer where an earlier agent of the same user was connected: the earlier agent's agent mode kept 127.0.0.1:8480 and connecting stopped with "taken by another program" (or, after the next sign-in, came back with the new identity). It is now replaced: its process stopped, its start at sign-in (Windows Run entry, systemd --user unit) and pid file removed - only for an agent mode of this user serving the same port or identity file; another agent on another port, and any other program, are left alone.
- Quickstart: DeepWiki's question tool is `ask_wiki_question` (the guide said `ask_question`, a name its server no longer has); the guide now also shows the call from a terminal, and the TLS 1.2 fix for Windows PowerShell 5.1.
- `tools/provenza_audit.py receipt`: a refused action is reported as "refused and witnessed by" the gateway, not "executed".
- In-app help: a link in bold text (**[Policies](/policy-hierarchy)**) is
  shown as a link, not as raw markdown.
- The endpoint agent's default ingest URL had `shadow_ai` instead of
  `shadow-ai`.

- Browser extension: a secret-paste warning in the same batch as a visit made
  the server refuse the whole batch, so the visit was lost. Such warnings from
  older extensions are now dropped and the rest of the batch is kept.
- Light theme: Agent observability and the audit log console stayed dark;
  both now follow the theme (the live activity terminal stays dark).
- A page a role may not open (an old link, a typed address) says "You don't
  have access to this page" instead of loading forever or failing on refused
  requests. The Compliance page is no longer offered to plain users, whom
  the server already refused.
- Phones: wide tables scroll inside their panel instead of widening the page
  and pushing action buttons off screen; long key fingerprints on Runtime
  wrap.
- Encryption keys: a table with several encrypted columns showed one row per
  column under the same name (and a duplicate React key); each row now names
  its column.
- A page whose data failed to load (a 502 while the server restarts, say)
  hung on "Loading…" or showed an error until it was reloaded. Reads are now
  retried on 502/503/504, and a page that still cannot load says so with a
  "Try again" button.
- After a sign-in that an expired session asked for, the console returns to
  the page it was on (`/login?next=…`), not to the dashboard.
- Auditor and compliance can preview a policy (`POST /policy-layers/preview`,
  which saves nothing); the approvals page shows them the requests read-only
  instead of decision buttons the server refuses.
- The dashboard counts the policies in force (non-empty policy layers and
  enabled agent policies), not only the layers.
- The sidebar shows the organization's name instead of `org-<id>`.
- Profile, passkeys: a long fingerprint wraps, so the Remove button stays
  inside the panel.
- The demo records denied and held actions in the audit trail as the SDK
  does.

## [0.3.0] - 2026-10-26

### Added

- **Agents → Connect an AI client: one command from the interface**
  ([USER_GUIDE.md](USER_GUIDE.md) 8.4.2). With an enrollment or re-key token
  the panel gives one command for the client's machine
  (`/api/v1/agent-enrollment/connect.sh`): it downloads `provenza-proxy` from
  this server and checks it against `SHA256SUMS`, enrolls the agent there with
  the token (`provenza-proxy enroll`: the keys are made on that machine and
  proven over the server's challenge; the token goes through the environment)
  and connects the client; the page shows *Connected* when the token is spent.
  Agent mode reaches Provenza's own gateways when the machine has no egress
  proxy (`--proxy auto`; upstream `https://<provenza>/api/v1`), and starts in the
  background where the user has no systemd session.
- **A client connected in one command: `provenza-proxy connect`**
  ([proxy/README.md](proxy/README.md), "Connecting a client in one command").
  `provenza-proxy connect gemini-cli` (or `claude-code`, `cursor`, `openai`),
  run as the agent's user with its identity file, runs the proxy's agent mode
  as a systemd --user service (`provenza-agent-<id>.service`, `127.0.0.1:8480`
  in front of the egress proxy) and gives the client Provenza's MCP endpoint
  through it, with no key in the client's configuration (Gemini CLI
  `~/.gemini/settings.json`, Cursor `~/.cursor/mcp.json`, Claude Code `claude
  mcp add`); the rest of the file is kept and the original saved once.
  `--remove` takes both out. Agent mode now signs with **hybrid keys** too
  (Ed25519 + ML-DSA-65, as the SDKs): the proxy needs Go 1.27
  (`crypto/mldsa`), and so does the backend image's build.

- **The edge services set themselves up** ([docs/self-hosting.md](docs/self-hosting.md),
  "The edge services of this host"). `install.sh` - and `provenza edge setup`
  on an installation made before - puts the egress proxy (`provenza-proxy`,
  `127.0.0.1:8443`, following the signed policy with `"pin": "tofu"`) and the
  endpoint agent (`provenza-agent`) on the host, with their keys: made by the
  backend (`scripts/edge_keys.py`, entrypoint role `edge-keys`) and written
  straight into their files, never shown. With `--sensor` the egress sensor
  gets its key and starts; `--sensor-guard` runs the proxy through it, pinned
  to its binary and configuration. The binaries are built into the backend
  image (stage `edge`) and also served next to the sensor's
  (`/api/v1/egress-sensor/download/provenza-{proxy,agent}-linux-{amd64,arm64}`).
  `provenza upgrade` and `provenza rebuild` refresh them (`provenza edge
  refresh`). The proxy's SHA-256 values go into the next signed release's
  settings, replacing the ones this host added before. The endpoint agent
  1.4.0 reads its key from `ingestion_key_file`, expands wildcards in
  `model_search_paths` (`/home/*/.ollama/models`) on every scan, and sends an
  `agent_heartbeat` every 15 minutes, so its device is listed even when
  nothing AI-related runs there (the server refreshes the device and records
  nothing else). CI builds and tests the agent.

- **Enforce mode and the proxy's agent mode** ([docs/pvp/edge.md](docs/pvp/edge.md),
  section 4.2). A setting of the signed policy (Policies → Signed policy →
  settings, *Mode*; the bundle's `enforcement` section): in enforce mode no
  action runs without the agent's own signature and the signed policy.
  Provenza's own gateways execute nothing; `/agents/actions/check` only
  observes (no permit, the reason says so) and what an agent records itself is
  an observation; an egress proxy with `policy.mode` "enforce" takes on every
  path - egress routes, `/_tools`, `/_llm`, `/_mcp`, `/_a2a` - only requests
  the agent signed over the HTTP request itself (`X-Provenza-Request`,
  `tool_name` "proxy.<first path segment>"), verified with the key the release
  names and again by the server with the agent's registered key; a proxy
  says `X-Provenza-Proxy-Mode: enforce` or takes part in nothing; a check the
  agent did not sign is not redeemed; an action reported without a receipt
  naming a signed release and the agent's verified signature raises a
  critical `unenforced_action` incident. Switching it on takes effect at once,
  switching it off needs a signed release. **Agent mode**: `provenza-proxy
  -agent-identity <identity> -listen unix:<path> -upstream <proxy>` (a socket of
  mode 0600; a loopback TCP address with a warning) signs
  for clients that cannot (stock OpenAI, MCP, A2A clients, plain HTTP). The
  SDKs sign `invoke` through a proxy as well. Migration `a7b8c9d0e1f2`
  (`policy_signing_settings.enforcement`, `action_checks.agent_signed`).
- **Closing the remaining bypasses** (edge.md §4.1, §5, §6-7).
  The egress proxy's configuration is pinned like its binary: the proxy
  reports the SHA-256 of the configuration it read to the sensor
  (`PROVENZA_SENSOR_SOCKET`, set by `--proxy run`), and the run stays held
  until the hash is in the signed manifest (`proxy_configs`, Policies →
  Signed policy → egress proxy configurations; or `proxy_configs` in
  sensor.json). Sealed credentials carry the sealing administrator's
  session-key signature over the envelopes (`provenza.credential.sealed`;
  `POST /egress/credentials/{object}/{id}/statement`, `.../countersign` for
  envelopes sealed from credentials the server held): an enforcing proxy
  opens only envelopes an administrator of its signed manifest vouched for,
  and such a re-seal during an outage is a signed difference. An enforcing
  proxy hashes the A2A card it fetched itself. Agent mode listens on a unix
  socket of mode 0600 (`-listen unix:<path>`). Signed sensor commands are
  valid for 4 minutes (a sensor takes at most 5); lift signatures for 12
  hours (`expires_at`); a refused key (401, for a sensor also 403) is no
  contact for the offline time. Migration `a7b8c9d0e1f2` also adds
  `policy_signing_settings.proxy_configs` and `sealed_credentials.sealer`.
- **Passkeys and one session per signer** ([docs/pvp/edge.md](docs/pvp/edge.md),
  section 2). Administrators and approvers add passkeys in My profile -
  a key kept on their phone or computer and unlocked with its PIN; Provenza
  keeps only the public key. Each sign-in is confirmed once with the
  passkey, which certifies a session key made in the browser
  (non-extractable) and deleted at sign-out; sign-out is signed by it. A
  signer has one session at a time: a second sign-in waits until the open
  session lets it in with the passkey or refuses it, the attempt opens a
  `session_conflict` incident and notification, and the waiting sign-in can
  end the other session only with the passkey. API: `/auth/session`,
  `/users/me/passkeys`. Setting `WEBAUTHN_RP_ID`.
- **Working without the server; the local kill switch** (edge.md §6-7). An
  egress proxy with `policy.mode` "enforce" sends, while Provenza is
  unreachable, the egress-route requests an agent signed itself (the SDKs
  fall back to that: `proxy_request_headers` / `proxyRequestHeaders`),
  judged by the signed release alone (the agent's key from its manifest,
  once; no approval, no delegation chain), keeps them with its receipts and
  hands them over when the server answers (`POST /egress-proxy/offline-actions`):
  they become actions, an unverifiable one with a critical incident. After the
  release's `offline_seconds` it stops - also across restarts - and, when the
  server answers, sends a reconciliation report signed with its key (the
  manifest, Tool Registry and sealed credentials compared with the release
  held before the outage; an incident per difference). The quorum of that
  release lifts it under Gateways → External APIs → Proxies with their passkeys, accepting
  every difference no signed release explains; the proxy checks them itself.
  Pinned sensors isolate every workload after `offline_seconds` without the
  server, or when the release has expired, and lift themselves when it answers.
- **The egress sensor follows the signed policy** (edge.md §5). With
  `policy.pin` (`enroll --policy-pin`, `install.sh --policy-pin`) a sensor
  verifies the signed releases itself (`GET /egress-sensor/policy-release`)
  and: runs a command only when an administrator signed it with a
  passkey-certified session key (`provenza.sensor.command`, the signer an
  administrator in the signed manifest, once per nonce); holds every
  workload to its signed version (`egress_workloads` in the bundle - the
  server can tighten, not loosen; signed patterns, users and agents first);
  and on a proxy host started with `provenza-sensor --proxy run --
  provenza-proxy ...` lets the proxy out only while every process runs a
  binary whose SHA-256 the manifest pins (`proxy_binaries`, set with the
  quorum) and none is traced. The sensor reports what it verified with its
  heartbeat; the Runtime page shows it and marks signed commands 🔏. API:
  `POST /egress-sensor/sensors/{id}/commands/statement`, `statement` and
  `signature` on `POST .../commands`, `proof` on delivered commands,
  `proxy_binaries` in `PUT /policy-releases/settings`.
- **Credentials sealed to the egress proxies** (edge.md §4.1). A
  credential typed in the interface - of an egress route, AI connection, MCP
  server, A2A peer or HTTP tool - is sealed in the browser to each proxy's
  own encryption key (X25519, HKDF-SHA256, AES-256-GCM, bound to the object
  and the proxy); the server stores envelopes it cannot open and each proxy
  opens only its own. The proxy derives its encryption key from its signing
  key, registers it signed, and its fingerprint is in the signed manifest.
  API: `/egress/proxy-keys`, `/egress/credentials/...`,
  `GET /egress-proxy/credentials`. Credential source `sealed` (formerly
  `server`), `local`, `none`. Each envelope is bound to the upstream's
  origin: an object pointed elsewhere does not take its credential along.
- **The gateways' protocols through the egress proxy** (spec.md §5.5): HTTP
  tools (`/_tools/call`; SDKs: `egress_proxy` / `egressProxy` /
  `PROVENZA_EGRESS_PROXY`), OpenAI chat completions to every connection type
  (`/_llm/v1`), MCP (`/_mcp`) and A2A (`/_a2a/<peer>`). The server decides
  each call from a plan - for LLM calls the messages' count and hash only -
  and the proxy executes it with the credential sealed to it, judges it
  under the signed policy when enforcing, and records metadata and hashes
  with its receipt. Proxies sync the MCP servers and A2A peers they serve.
  `local_secrets` take `"<object>:<id>"` keys and an optional `upstream`.
- **AI connections in the signed policy** (`ai_providers`: type, base URL,
  status): a release signed from now on fixes where a model's prompts go.
- **The egress proxy enforces the signed policy itself** (spec.md §5.5,
  edge.md §4). It verifies policy releases (quorum of the pinned manifest),
  agents' signed requests (`X-Provenza-Request`, sent by the Python and JS
  SDKs) and human approvals itself, evaluates the bundle with a Go port of
  the server's evaluator (`proxy/internal/policy`, shared vectors
  `sdk/testdata/policy-vectors.json`) and forwards only what both it and the
  server allow, to the signed route. `policy.mode: "enforce"`, `policy.pin`,
  `policy.require_agent_signature`.
- **Proxy receipts.** The proxy has its own Ed25519 key (generated on its
  host or `signing_key_file`, `provenza-proxy -genkey`), registered once;
  every forwarded or refused request carries its signed receipt, kept in
  the action's sealed evidence (`witness`) and in the proxy's hash-chained
  log; `tools/provenza_audit.py receipt --proxy-fingerprint` checks it.
  Fingerprints under Gateways → External APIs → Proxies and in the key manifest. API:
  `/egress-proxy/key`, `/egress-proxy/policy-release`, `/egress-proxy/check-info`.
- **Signed policy releases** ([docs/pvp/edge.md](docs/pvp/edge.md), section
  3.1). Administrators freeze what decides allow or deny (agents' rights,
  policies, the policy hierarchy, the Tool Registry, identity and provider
  settings, the AI domain catalog, gateway settings and routes, MCP servers,
  A2A peers, HTTP tools, egress routes) and the keys (signers' passkeys, the
  quorum, agent key fingerprints, proxies, sensors) into a release and sign
  it with their passkeys, up to a quorum. Once one is in force, an action
  needs both the working copy and the release: tightening applies at once,
  loosening only when signed; agents, agent keys and the rows that carry a
  call must be the signed ones; approvals count only from passkeys in the
  manifest. A release that does not verify or has expired allows nothing.
  The *Signed policy* panel on the Policy hierarchy page and a banner for
  administrators; API `/policy-releases`; `tools/provenza_audit.py release`
  verifies a release offline. Notification event `policy_release`.
- **Approvals are signed.** An approval of a held agent action is signed
  with the reviewer's session key (certified by their passkey); only a
  signed approval, checked again against exactly the repeated call, lets it
  run. The receipt of the call carries the signed approval, and
  `tools/provenza_audit.py receipt --approver-passkey <fingerprint>` checks
  it offline. Passkeys show their fingerprint in My profile. API:
  `POST /agents/actions/{id}/statement`.
- **Approved calls run once.** After an approver allows a held call, the
  agent repeats the same call (same agent, chain, tool and input) within
  `APPROVAL_REDEEM_MINUTES` (default 60) and it runs, once. The agent asks
  `GET /agents/actions/{id}/decision`; the SDKs wait with
  `wait_for_approval` / `waitForApproval`.
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

- **The egress proxy waits for Provenza at start**: a network failure of
  its first contact is retried for up to 30 s (a sensor holds a proxy for a
  moment until it has checked the binary) instead of exiting at once.
- **What is recorded of a call a proxy executed is metadata**: status, token
  counts, response hashes - not the tool's or the peer's answer, which the
  server gateways recorded.
- **The server no longer reads upstream credentials.** A credential sent in
  clear text is refused (`credential.plaintext_refused`) by the routes,
  AI connections, MCP servers, A2A peers and HTTP tools APIs; the proxy's
  configuration no longer carries one. The server's own LLM, MCP, A2A and
  HTTP tool gateways serve only upstreams that take no credential; one with a
  sealed credential is refused there. Listing an AI connection's models does
  not work with a sealed key.
- **LLM calls go through the protocol (PVP).** Every gateway call is an
  action `model_call` on tool `llm.<model>`: checked against the agent's
  allowed models and its deny and approval rules, issued a single-use check
  and recorded with its outcome in the sealed audit evidence. An agent can
  pass its delegation chain in `X-Provenza-Chain-Id`. Model calls are not
  counted in tool allow-lists, the Tool Registry or the behaviour baseline.
- **The LLM gateway keeps metadata only.** A call is recorded with agent,
  model, outcome, tokens and time; the prompt and the answer pass through
  and are never stored or scanned.
- **Agent observability shows metadata only.** The live feed carries no
  content; an admin opens one event's content on an explicit request that
  is written to the audit log.
- **Data retention** (Settings → Data retention, `/retention`) replaces
  Queue & Retention and keeps only the retention of agent telemetry.
  "Keep indefinitely" now stays indefinite instead of falling back to 90
  days.
- **Dashboard and AI inventory** count LLM gateway calls instead of usage
  requests; an LLM provider's signal is now `high_call_denial_rate`.
- **Notifications**: `request_blocked` and `approval_pending` are gone
  (nothing sent them any more) and are removed from existing channels.

- **The production stack runs on rootful Podman with systemd (Quadlet)
  instead of Docker compose.** `deploy/quadlet/` holds the unit templates
  (11 containers, 9 volumes, 3 networks); `deploy/scripts/units.sh install`
  renders them with the values from `deploy/.env` into
  `/etc/containers/systemd`. Every container is a systemd service
  (`provenza-backend`, ...) under `provenza.target`, which starts at boot.
  `install.sh` (now run as root) installs Podman, netavark and aardvark-dns
  when missing, builds the images, installs the units and schedules backups
  with `provenza-backup.timer` instead of cron. `upgrade.sh`, `backup.sh` and
  `restore.sh` work with Podman; `deploy/scripts/run.sh` runs one-off backend
  commands such as `create-admin`. The `provenza` command
  (`/usr/local/bin`) wraps it all: `start`, `stop`, `restart`, `status`,
  `logs <service>`, `upgrade`, `backup`, `run`. PostgreSQL, Redis and Grafana receive only
  their own password, not the whole `.env`. `deploy/docker-compose.yml` is
  removed. An existing Docker installation moves with
  `deploy/scripts/migrate-from-docker.sh`, data and TLS certificates
  included, and goes back to Docker by itself if the new stack does not come
  up. Requires Podman 4.4+ (Ubuntu 24.04+, Debian 13+, RHEL 9.3+, Fedora).

- **Navigation follows the lifecycle of an AI system:** Discovery →
  Registry → Policies → Enforcement → Audit (plus Settings), instead of
  grouping by feature type. Pages and URLs are unchanged. A few labels
  changed with it: Shadow AI Sightings, Audit Log, Notifications, and
  Playground (the governed chat with a connected provider).

### Removed

- **Content safety, the request pipeline and the Policy Center.** Provenza
  governs AI systems and agents; inspecting and rewriting prompt text is not
  its job. Removed: the Prompt Firewall with PII masking and PII rules,
  blocked terms, the intent guardrail, the prompt-injection, code-execution,
  memory and agent-message guards (with chain tainting), the Playground, the
  Usage log with its queue, request approvals and overrides, the Policy
  Center (versioned policies and their link to use cases), and the
  `CONTENT_SAFETY_ENABLED` / `PROMPT_FIREWALL_NER_*` settings (still
  accepted in an old `.env`, but unread). API prefixes `/requests`,
  `/approvals`, `/overrides`, `/policies`, `/pii`, `/blocked-terms`,
  `/guardrail`, `/injection`, `/code-exec`, `/memory`, `/a2a` and
  `/queue`, and `POST /providers/{id}/chat`, are gone. The policy
  hierarchy loses its `content` and `requests` sections; agent observability
  loses agent-to-agent messages. Dependencies dropped: spaCy (and its English
  model in the image), regex.
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

- **Sensor: cgroups created while it runs, with `cgroup_root` below the
  cgroup mount**, were matched against the patterns by their path in the
  whole hierarchy and missed; they are matched relative to `cgroup_root`. A
  pattern can no longer take a sensor's own run cgroup. The sensor README
  gave `run --agent N` in the wrong order: it is `--agent N run -- cmd`.
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
  spellings like `"PROVENZA "` and `" provenza"` share one budget; a successful
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

- **Offline time.** `offline_seconds` in the signed policy settings (default
  900, at least 60) now stops enforce-mode proxies and pinned sensors when
  Provenza is unreachable for longer: set it to what an outage may last, and
  keep administrators who can sign at hand. Migration `f5a6b7c8d9e0` can be
  downgraded (the kill switch reports and signatures go).
- **Sensors: pin the signed policy.** Upgrade the sensors, then give each
  one `policy.pin` (`provenza-sensor enroll --policy-pin <SHA-256>`, or edit
  `sensor.json`; a re-enroll keeps it). Sign a release after the upgrade: an
  earlier one does not state workloads, so it constrains none. On an
  egress proxy host, add the proxy binary's SHA-256 under *egress proxy
  binaries*, sign, set `kernel.yama.ptrace_scope=3` and start the proxy
  through `provenza-sensor --proxy run` (commented in the systemd unit);
  sign a release with the new hash before upgrading the proxy. A pinned
  sensor refuses commands the server signed alone, including
  `update-signing-key`. Migration `e4f5a6b7c8d9` can be downgraded.
- **Credentials held by the server stop being used until they are sealed.**
  After the upgrade, upgrade and start the egress proxies (they register
  their encryption key), then an administrator opens Gateways → External APIs →
  Proxies and chooses *Seal and erase*: the credentials are sealed to every
  proxy with a key and erased from the server. Until then, upstreams that
  take a credential are refused; afterwards they are reached through the
  proxies only - point agents at the proxy (`/_tools`, `/_llm/v1`, `/_mcp`,
  `/_a2a/<peer>`). A proxy added later needs the credentials entered again.
  Releases signed before this version do not state AI connections; sign a
  new one to cover them.
  Migration `d3e4f5a6b7c8` can be downgraded, but the erased credentials do
  not come back: enter them again.
- **Egress proxies need a writable `state_dir`** (default
  `/var/lib/provenza-proxy`; the systemd unit and the Docker image provide
  it, Kubernetes needs a volume and, for a stable key, `signing_key_file`).
  Migration `c2d3e4f5a6b7` can be downgraded.
- **Signed policy is opt-in until the first release is signed.** Nothing
  changes on upgrade. After the first release, a new agent, a new agent key,
  a new route or anything else that loosens the policy works only after the
  next release is signed; renew releases before `validity_days` (default 90)
  run out. Migration `b1c2d3e4f5a6` can be downgraded.
- **Approving needs a passkey.** Approvers and administrators add one in My
  profile and confirm the sign-in before approving; denying works without.
- **Administrators and approvers sign in one session at a time.** After the
  upgrade a second sign-in of the same person waits for the open session to
  let it in. Ask them to add a passkey in My profile (two devices, so a lost
  phone does not lock them out). Passkeys are bound to the site's host: the
  first `CORS_ORIGINS` entry, or `WEBAUTHN_RP_ID`; changing it later makes
  the existing passkeys unusable.
- Migrations `f9a0b1c2d3e4` (model calls and approvals) and `a0b1c2d3e4f5`
  (passkeys and signing sessions) can be downgraded.

- **Data of the removed features is deleted.** Migration `e8f9a0b1c2d3`
  drops the tables of the Prompt Firewall, blocked terms, guards, Usage log,
  approvals, overrides and policies with their data, and cannot be
  downgraded. Take a backup before upgrading if you may need them.

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

[Unreleased]: https://github.com/kironovlaziz-del/provenza/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/kironovlaziz-del/provenza/releases/tag/v0.5.0
[0.4.0]: https://github.com/kironovlaziz-del/provenza/releases/tag/v0.4.0
[0.3.0]: https://github.com/kironovlaziz-del/provenza/releases/tag/v0.3.0
