# Provenza — Administrator Guide

This guide explains how to **use** Provenza from the web
interface as an administrator. For installation, deployment, and
development, see [README.md](README.md).

> O‘zbek tilidagi qo‘llanma: **[USER_GUIDE.uz.md](USER_GUIDE.uz.md)**

---

## 1. First sign-in

1. Open the platform URL in your browser.
2. The first organization and its admin are created on the server during
   installation (`sudo provenza run create-admin --org "Company" --email
   ...`, see [self-hosting](docs/self-hosting.md)); further users are
   invited from **Settings → Users**. **Register organization** on the
   login page appears only when the server allows public sign-up.
3. To sign in, enter your **Organization** short identifier (e.g.
   `acme`), your **email**, and your **password**.
4. Use the **Language** selector (top of the login page) to switch
   between English and O‘zbekcha at any time.

### Roles

| Role | Can do |
|------|--------|
| **admin** | Everything, including user management, connections, ingestion sources, domain catalog, discovery |
| **approver** | Review and decide approval requests; everyday operations |
| **user** | Reads the everyday pages (dashboard, inventory, agents, agent activity); no reviews or settings |
| **auditor** | Read everything an admin or approver sees - inventory, policies, agents, the audit log, compliance - and change nothing; may verify the audit log and generate compliance reports |
| **compliance** | Compliance officer (DPO, Chief AI Officer): reads the same as an auditor and confirms compliance requirements |

An admin gives roles on **Settings → Users**. An organization that requires
two-factor sign-in "for reviewers" requires it for auditors and compliance
officers too.

### Passkeys and one session (admins and approvers)

Administrators and approvers confirm what they do with a **passkey**: a key
kept on their phone or computer and unlocked with its PIN or fingerprint.
Add one in **My profile → Passkeys** (your password is asked again; from
the second passkey on, an existing one confirms it). Add two, on different
devices, so a lost phone does not lock you out.

- After each sign-in the browser asks for the passkey once; until then a
  banner says the sign-in is not confirmed.
- You have **one session at a time**. If you (or someone with your
  password) sign in elsewhere while a session is open, the new sign-in
  waits and your open session shows a red banner with its time, address
  and browser: **Let in** (with the passkey) or **Refuse**. An incident is
  opened and the `session_conflict` notification goes out.
- If the open session is on a device you no longer have, the waiting
  sign-in can **end the other session** - only with a passkey.
- Signing out, or changing your password, ends the session and its key.

---

## 2. The dashboard

After sign-in you land on the **Dashboard** — a summary of LLM gateway
calls, incidents and pending approvals over a recent window.

The left sidebar has five groups; each item opens a page with tabs for
its related pages:

- **Overview** — Dashboard, Incidents, Approvals and the Kill switch.
- **Visibility** — **AI inventory** (inventory, AI providers,
  connections, use cases), **Agents** (agents, teams & roles, tool
  registry, agent identity, attestation, behavior monitor, circuit
  breaker), **Discovery** (agents found, devices, network discovery),
  **Shadow AI** (sightings, AI domain catalog) and **Agent activity**
  (agent observability, the live map, delegation chains).
- **Control** — **Policies** (policy hierarchy, agent policies),
  **Compliance** and **Gateways** (the AI gateway, Runtime with the egress
  sensors).
- **Evidence** — **Audit & evidence**: the audit log.
- **Settings** — users, your profile, notifications, system status and,
  for the server's operator, the installation's health; under **More**:
  SIEM export, encryption keys, data retention and ingestion sources.

Pages you open less often sit behind **More** on their section's tab bar.

Agent observability shows what agents do as metadata only. An admin can open
the content of one event (what the agent sent and got back) by giving a
reason, which is written to the audit log; how long that content is kept is
set under Settings → Data retention.

---

## 3. Connections (AI providers)

Before agents can call an AI provider through the gateway, add a
connection.

1. Sidebar → **AI inventory → Connections**.
2. **New provider** → choose type (OpenAI, Anthropic, Azure OpenAI, or
   Custom), give it a name, and paste the API key.
3. The key is **sealed in your browser** to the egress proxies' own keys
   (Gateways → Egress → Proxies shows each proxy's key fingerprint; compare
   it with what the proxy prints on its host). Provenza stores only what it
   cannot open, and the proxies use the key - so a connection with a key is
   called through an egress proxy. A self-hosted model server that takes no
   key works without one. The same holds for the credentials of egress
   routes, MCP servers, A2A peers and HTTP tools. Sealing asks for your
   signature (this session's key): a proxy in enforce mode opens only what
   an administrator of the signed policy sealed. A credential the server
   sealed from one it held before shows *Vouch for it*.
4. Agents then call through the egress proxy with their own key:
   `http://<proxy>/_llm/v1` as the OpenAI base URL, `/_mcp` for MCP,
   `/_a2a/<peer>` for A2A, and the SDKs' `egress_proxy` setting
   (`PROVENZA_EGRESS_PROXY`) for HTTP tools. The proxies sync MCP servers
   and A2A peers whose credential they hold; approve their tools and cards
   in Provenza as usual.

You can also set an SLA and a risk score for vendor-risk tracking.

---

## 4. Policy hierarchy

Policies → **Policy hierarchy**: one policy at three levels -
organization, team (and its sub-teams), agent - edited as a form or as
YAML. A lower level can only tighten: the smallest limit wins, every
level's allow list must allow, and all deny / approval lists apply. It
applies to the LLM gateway (limits, models, providers) and to agent
actions (tools, delegation depth). While you edit, *Effective policy*
shows every value with the level it comes from and lists what has no
effect because a level above is stricter. Every save is in the audit log.
Details: docs/policies.md.

Policies → **Agent policies** holds the rules for agent actions built
visually (deny a tool, allow only some tools, require approval, limits).

**Signed policy** (top of the Policy hierarchy page). Administrators freeze
everything that decides allow or deny - agents' rights, policies, the Tool
Registry, gateways and their routes - and the keys into a *release* and sign
it with their passkeys (**Prepare the first release**, then **Sign with
passkey**). Once a release is in force:

- a change that tightens (suspend an agent, remove a tool, a deny rule)
  takes effect at once;
- a change that loosens (a new agent or tool, a new route or MCP server, a
  higher limit) waits until the quorum signs the next release; the panel
  and a banner list what is not signed yet;
- a new agent or a new agent key acts only after signing.

Set the quorum (how many administrators must sign; 2 or more recommended),
how long a release is valid and the offline time under *Quorum, validity,
offline time, mode*: they apply from the next release. The offline time is how long an
egress proxy (in enforce mode) and the pinned sensors keep working without
this server: past it they stop - a *local kill switch*. A stopped proxy shows
under Gateways → Egress → Proxies with what changed meanwhile; the
administrators of the release it held lift it with their passkeys, accepting
every change no signed release explains. Renew the release before
it expires - after that no agent action is allowed until a new one is
signed. `tools/provenza_audit.py release` checks a release offline.

*Mode* in the same settings: **Enforce** means no action runs without the
agent's own signature and the signed policy. Provenza's own gateways then
execute nothing, and an agent's check of its own only observes: every
action goes through an egress proxy in enforce mode, signed by the agent -
the SDKs sign; for a client that cannot (a stock OpenAI or MCP client) run
the proxy's agent mode next to it (`provenza-proxy -agent-identity …`, see
`proxy/README.md`). Switching it on takes effect at once; switching it off
needs a signed release. Before you switch it on, put every agent behind a
proxy.

---

## 5. Use Cases

A use case records a purpose, its risk level and its owner.

1. Sidebar → **AI inventory → Use Cases** → **New use case**.
2. Set the name, risk level and (optionally) the owner.

### 5.1 Impact assessment

On an AI system's page (AI inventory → the system) set **Our role under the
EU AI Act** - provider, deployer, importer, distributor - and open the
**Impact assessment**. One questionnaire serves as the ISO/IEC 42005 impact
assessment, the GDPR data protection impact assessment (its personal data
part appears when the system processes personal data) and the EU AI Act
fundamental rights impact assessment. Save it as a draft while you work;
**Approve** freezes that version (admins and compliance officers), and the
next change starts a new one, so earlier decisions stay. The Compliance page
reads the approved version for EU AI Act Art. 27, GDPR Art. 35 and ISO 42001
A.5, and flags it again when its review date passes.

**Testing and assurance** on the same page records the tests the system went
through - evaluations, bias tests, red teaming, robustness tests - with the
date, who ran them, the result and a link to the report (admins, approvers
and compliance officers; records cannot be changed afterwards). A test counts
for a year: EU AI Act Art. 15 needs an evaluation and a red teaming or
robustness test, Art. 10 a bias test, ISO 42001 A.6.2.4 and NIST MEASURE 1 a
test of every system above minimal risk.

---

## 6. Approvals

An agent action that a policy marks as needing a person waits under
**Overview → Approvals**. Admins and approvers judge it by its arguments
and **Approve** or **Reject** it with a reason. An approval is signed with
your session key, which your passkey confirmed at sign-in: approve only
after confirming the sign-in (the banner at the top), and add a passkey in
**My profile** first. The receipt of the action that ran carries the signed
approval, and `tools/provenza_audit.py receipt --approver-passkey` checks it
offline (the fingerprints are in My profile → Passkeys). Approving runs
nothing by itself: the agent repeats exactly the same call (same arguments, same
chain) and it runs once, within an hour of the approval - through any
gateway or the SDK (`wait_for_approval` waits for the decision). All
decisions are audit-logged.

---

## 7. Incident Tracker

1. Sidebar → **Overview → Incidents**.
2. Incidents can be created manually or automatically (e.g. when a
   blocked AI domain is detected — see Shadow AI Monitor).
3. Move an incident through **Open → Investigating → Resolved**, and
   record root cause. Everything is audit-logged.

---

## 8. Shadow AI Monitor

Shadow AI Monitor surfaces unsanctioned AI usage across your
organization. Data arrives from three collectors — the **endpoint
agent**, the **browser extension**, and **network discovery** — and all
of them feed one **Sightings** list.

### 8.1 Ingestion Sources (machine keys)

Collectors authenticate with a machine key, not a user login.

1. Sidebar → **Settings → Ingestion Sources** (admin only).
2. **New source** → choose type (Gateway, Endpoint agent, Browser
   extension) and name it.
3. The **ingestion key is shown once** — copy it now. It is stored
   hashed and cannot be retrieved later. If lost, revoke the source and
   create a new one.

### 8.2 AI Domain Catalog

The catalog decides how a detected domain is treated.

1. Sidebar → **Discovery → AI Domain Catalog** (admin only).
2. Add a domain and set its policy: **Allowed** (only logged),
   **Blocked** (raises an automatic incident), or **Unknown** (raises a
   sighting for review). Anything not in the catalog is treated as
   Unknown.
3. When you type a well-known domain (e.g. `chat.openai.com`) the form
   offers to auto-fill the tool name and category.

### 8.3 Sightings

Sidebar → **Discovery → Shadow AI Sightings**. Each sighting shows the tool, the
source (browser extension, endpoint agent, local process/network/model
file, or manual), the employee hint if known, the status, and a
"seen N times" counter for repeat detections. For each one you can:

- **Take** it for review,
- **Register** it as a sanctioned provider (turns it into a real
  connection),
- **Dismiss** it.

You can also **Report a sighting** manually.

### 8.4 Deploying the endpoint agent

The agent is a small native program installed on a machine you want to
monitor (a server, or an employee workstation via your MDM). It detects
local AI tools (running processes, listening ports, model files) and, if
enabled, discovers network services.

1. Create an **Ingestion Source** of type *Endpoint agent* and copy the
   key.
2. Put the key and your server URL into the agent's `config.json`
   (see `agent/config.example.json`), then build and run it — full steps
   are in [Shadow AI collectors](docs/shadow-ai.md).
3. New findings appear within a minute: local AI tools under
   **Discovery → Shadow AI Sightings**, AI agents under **Discovery →
   Agents Found**, and the machine itself under **Discovery → Devices**.

### 8.4.1 Agents Found and Devices

The endpoint agent (v1.2.0 or later) recognizes AI agents running on the
machine — coding agents (Claude Code, Cursor, GitHub Copilot, Codex CLI,
Gemini CLI, Aider, …), agent frameworks (CrewAI, LangGraph, AutoGen
Studio, Letta) and agent platforms (n8n, Flowise, Langflow). It sends
only which product it found and how it recognized it; the process
command line, which can contain API keys, never leaves the machine.

- **Discovery → Agents Found** lists each agent per device, newest to
  review first. **Register** opens agent registration (an enrollment token,
  see below) with the name and
  type filled in; once registered, the finding is linked to the governed
  agent and comes under its policies. **Ignore** hides a finding (it can
  be restored).
- **Discovery → Devices** lists every machine and browser that reports,
  with its user, OS, collector version, last activity and the agents
  found on it. A device that has been silent for a day is marked *quiet*.

Agents that are not known products — a company's own bots and scripts —
are found by behavior (endpoint agent v1.3.0 or later) and listed as
**Unrecognized agent**, named after the script or program that runs:

- the process has a connection to an LLM API (OpenAI, Anthropic, Google
  Gemini, Mistral, Groq, DeepSeek, OpenRouter, AWS Bedrock, …);
- or it has an LLM SDK loaded (the OpenAI / Anthropic Python SDKs,
  tiktoken, Hugging Face tokenizers).

LLM API key variables in its environment (`OPENAI_API_KEY`, …) raise the
confidence; only their names are reported, never the values. A finding
from an API connection alone is *medium confidence*: some providers share
CDN addresses with other sites. To see the processes of every user on a
machine, run the endpoint agent as root; as a regular user it sees only
that user's processes. Services on the same machine that call LLMs on
purpose (for example Provenza's own backend) appear here too — ignore
them once.

Both pages are visible to admins and approvers; only admins register or
ignore findings.

### 8.4.2 Enrolling an agent

Agents → **New agent**: fill in what the agent may do
(capabilities, tools, models, delegation depth, team) and **Issue
enrollment token**. Give the token to whoever runs the agent; on that
machine they run the command shown, e.g.

    python tools/provenza_sign.py enroll --server https://provenza.example.com --token pvz_enr_...

Or press **Enroll in this browser**: the keys are made on the page and
downloaded as `provenza-agent.json` (never sent to the server); move that
file to the agent's machine. The command needs Python and
`pip install cryptography`; the page warns about it.

The agent's keys are generated there and never leave it; it proves it holds
them by signing a challenge, and only then appears in the registry - with
exactly the rights you set. The token works once and expires (1 hour to
7 days). Open and used tokens are listed on Agent Identity.

Keys rotate with `python tools/provenza_sign.py rotate` (the old key
consents, the new one proves itself). If a key is lost, revoke it on the
agent's page and **Issue re-key token**.

### 8.4.3 Teams and role templates

Agents → **Teams & Roles**. Teams form a tree (organization → team →
sub-team → agent); an agent belongs to a team by its id, so renaming a team
renames it everywhere.

A **role template** is a named set of rights: capabilities, tools, models,
delegation depth, and whether a hybrid key (and, later, attestation) is
required. An agent with a role has exactly the role's rights - you cannot
edit them on the agent - and editing the role updates every agent that has
it (the page tells you how many). An org-wide role can be given to any
agent, a team's role only to agents of that team.

Pick the team and role on **New agent** (the rights fields are replaced by
the role's), or change them on the agent's page (**Team and role →
Change**). Taking an agent off its role keeps its current rights, now
editable per agent. A team or role still in use (agents, sub-teams, open
tokens) is not deleted. Existing `owner_team` names become teams when you
upgrade.

### 8.4.4 Workload attestation

Agents → **Attestation**. A policy says where agents must prove they run:
your Kubernetes cluster (its issuer and signing keys - `kubectl get --raw
/openid/v1/jwks`), the token audience (the same value goes into the pod
spec), the allowed namespaces / service accounts, and how long a proof lasts.
In Teams & Roles tick **Require attestation** on a role and pick the policy:
its agents cannot act until they attest. **Setup** on a policy shows the pod
spec fragment and the command the agent runs (`provenza_sign.py attest
--every 10`); **Test a token** checks a token without recording anything.
Every attempt is listed on the page and written to the audit log; the
agent's page shows whether it is attested and why not. Details:
docs/attestation.md.

A **retired** agent (agent page → Retire) is final: it cannot act, does not
count toward its team or role, and cannot be switched back on. A suspended
(killed) agent can be reactivated - unless a kill-switch stop still holds
it: then lift that stop (8.4.5).

### 8.4.5 Kill switch

Overview → **Kill switch** stops AI in four steps: one **agent**, a
**team** (with its sub-teams), **all agents**, or **all AI traffic** (every
agent plus every call through the gateway). Each stop needs a
reason; the two organization-wide levels also ask you to type `STOP`.
Stopped agents are suspended and, unless you untick it, their delegation
chains end. While a stop is in force, whatever it covers stays stopped:
agents created or moved into its scope start suspended, and an agent it
holds cannot be switched back on by hand.

**Lift** undoes one stop and gives back exactly what it stopped: agents
that were stopped earlier for another reason stay stopped, agents changed
since (e.g. retired) are left alone, and an agent still held by another
stop is handed over to it. Ended delegation chains are not resumed. Every
stop and lift is in the history on the page, in the audit log and - if you
subscribe a channel to `kill_switch` - in your notifications. **Kill** on an
agent's page is the same as an agent-level stop. Details:
docs/kill-switch.md.

### 8.5 Deploying the browser extension

1. On the **Ingestion Sources** page, click **Download extension**. The
   server packages the extension preconfigured with your server URL and
   a fresh key for your organization.
2. Distribute the downloaded `.zip` to employees (or push it via
   Chrome policy / MDM).
3. Manual install: unzip it, open `chrome://extensions`, turn on
   **Developer mode**, click **Load unpacked**, and select the unzipped
   folder.

The extension warns the user in-page before they paste or type secrets
(API keys, credit cards, private keys) into a known AI tool, and reports
that an attempt happened — **without** ever sending the secret itself.

---

## 9. Network Discovery (explicit-connect)

Sidebar → **Discovery → Network Discovery** (admin only).

When the endpoint agent runs with discovery enabled, it **passively**
finds network services (DNS, gateway, Active Directory, and — with the
right permissions — hosts via ARP and DHCP servers). They appear here as
read-only observations.

**Nothing is connected automatically.** To connect a discovered service
(e.g. read users from Active Directory), click **Connect** and provide
read-only credentials for that specific service. If a service type has
no connector yet, the platform tells you so honestly instead of
pretending it connected. You can also **Ignore** services you don't care
about.

---

## 10. Notifications

Sidebar → **Settings → Notifications**. Add **email** or **webhook**
channels and subscribe each to the events you care about
(`incident_created`, `shadow_ai_reported`, `shadow_ai_blocked_domain`, `kill_switch`,
`egress_sensor_offline`, `alert` - the server's monitoring alerts - and
more). If email
(SMTP) is not configured on the server, email channels are skipped
silently; webhooks always work.

---

## 11. Audit & Reporting

Sidebar → **Audit & evidence → Audit Log**. Every change made through the platform
— who did what, to which entity, when — is recorded in an append-only
log you can filter and review.

The log is tamper-evident (details in `docs/audit-proofs.md`):

- **Integrity** panel: how many records the chain holds, the last signed
  checkpoint and whether its signature verifies in your browser.
  **Download checkpoint** and keep the file outside Provenza (with the
  auditor, in a repository) — later logs can then be proven to extend it.
- **Check** on a row verifies that record in your browser: its hash, its
  place in the signed log and the signature. **Download proof** gives a
  file anyone can verify offline:
  `python tools/provenza_audit.py verify proof.json --fingerprint <audit key>`.
- Admins: **Sign now** signs a checkpoint immediately (otherwise every
  5 minutes); **Verify whole log** recomputes the entire chain and lists
  any record that was changed or removed.
- **Audit key**: pin it in your browser once; after a key change the page
  tells you whether the old key handed over to the new one. To change the
  key, an admin proposes it, the new fingerprint is published outside
  Provenza, enough admins approve by typing that published fingerprint, and
  after the announcement period (24 h by default) the old key hands over.
  Any admin can cancel before that.

---

## 12. Runtime: egress sensors

Gateways → **Runtime** (admin only). The egress sensor runs on a Linux
host and enforces, in the kernel, where each workload (an agent's
processes, matched by cgroup) may connect.

1. **Register sensor** gives a key and the one-line install command for
   the host; the server hands out the sensor itself, so the host needs no
   build tools.
2. Define **workloads**: which processes, the allowed destinations, and
   the mode - **observe** (record only), **alert** or **enforce** (block).
3. The sensor's row shows its last heartbeat, attached hooks and
   warnings; expand it to **Dump state**, **Restart** or **Detach** the
   sensor with a command your session signs ([details](docs/sensor-commands.md)).

Give each sensor the signed policy's pin (`install.sh --policy-pin <SHA-256>`,
the value shown under **Signed policy**). It then checks the releases
itself: it runs only commands an administrator signed (🔏 in the
history), holds every workload to its signed version (the server can
tighten one at once, loosening waits for the next release), and on the
host of an egress proxy started with `provenza-sensor --proxy run` lets
the proxy out only while it runs a binary listed under *egress proxy
binaries* in the signed policy settings, with a configuration listed
under *egress proxy configurations* (`sha256sum proxy.json`). The expanded row shows the
release the sensor verified and each proxy's state
([details](sensor/README.md#the-signed-policy)).

The settings set how often sensors fetch the policy (30-300 s) and send a
heartbeat (30-120 s). A sensor counts as offline after three missed heartbeats, and
not before 5 minutes; subscribe a channel to `egress_sensor_offline` to
hear about it.

---

## 13. Monitoring the installation

Settings → **Observability** is for the server's operator: the
administrators of the organization that runs it. It answers "is
everything working": the API, the database and queue, background jobs,
egress sensors, audit evidence and data retention, each with what to do
when it is not ok, then the trends and the busiest endpoints. Grafana and
the alert rules behind it are described in
[monitoring](docs/monitoring.md).

---

## 14. SIEM export

Settings → **SIEM export** (admin only) makes read-only keys a SIEM or
SOAR uses to pull the egress sensor events (violations and allowed
connections). The key is shown once; revoke it there when it is no longer
needed. The page shows the request to make; see
[SIEM export](docs/siem-export.md).

---

## 15. Tips

- **Keep the domain catalog current** — it is what turns raw telemetry
  into meaningful "allowed / blocked / unknown" signals.
- **One ingestion source per collector deployment** — so you can revoke
  a single agent or extension rollout without affecting others.
- **Review sightings regularly** and either sanction (Register) or
  Dismiss them, so the "Active" tab reflects only what still needs
  attention.
- **Least privilege** — give the endpoint agent `CAP_NET_RAW` only if
  you want ARP/DHCP discovery; everything else works without it.
