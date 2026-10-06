# Provenza — Administrator Guide

This guide explains how to **use** Provenza from the web
interface as an administrator. For installation, deployment, and
development, see [README.md](README.md).

> O‘zbek tilidagi qo‘llanma: **[USER_GUIDE.uz.md](USER_GUIDE.uz.md)**

---

## 1. First sign-in

1. Open the platform URL in your browser.
2. If your organization does not exist yet, click **Register
   organization** and create it — the first user becomes the **admin**.
3. To sign in, enter your **Organization** short identifier (e.g.
   `acme`), your **email**, and your **password**.
4. Use the **Language** selector (top of the login page) to switch
   between English and O‘zbekcha at any time.

### Roles

| Role | Can do |
|------|--------|
| **admin** | Everything, including user management, connections, ingestion sources, domain catalog, discovery |
| **approver** | Review and decide approval requests; everyday operations |
| **user** | Submit requests, view their own data |

---

## 2. The dashboard

After sign-in you land on the **Dashboard** — a summary of requests,
incidents and pending approvals over a recent window.

The left sidebar follows the life of an AI system in your organization:

- **Discovery** — what Provenza found on its own: the live agent map,
  shadow-AI sightings, network discovery and the collectors that feed it.
- **Registry** — the single list of AI in use: inventory, agents,
  provider connections, agent identities and the tool registry.
- **Policies** — the rules: policy versions, agent policies, use cases
  and compliance mapping.
- **Enforcement** — control at runtime: the AI gateway, approvals,
  circuit breaker, the agent guards and the governed playground.
- **Audit** — the evidence: usage registry, audit log, incidents and
  signed delegation chains.

---

## 3. Connections (AI providers)

Before the platform can send prompts to an AI provider, add a
connection.

1. Sidebar → **Registry → Connections**.
2. **New provider** → choose type (OpenAI, Anthropic, Azure OpenAI, or
   Custom), give it a name, and paste the API key.
3. The key is **encrypted at rest** and never shown again — the UI only
   indicates whether credentials are set.

You can also set an SLA and a risk score for vendor-risk tracking.

---

## 4. Policy Center

Policies define what is allowed and how prompts are filtered.

1. Sidebar → **Policies → Policy Center** → **New policy**.
2. Open the policy and **create a version**. A version holds the JSON
   rules: masking settings and a list of **blocked terms**.
3. **Approve** the version to make it active. Versions are immutable —
   to change rules, create and approve a new version.
4. Bind the active version to a **use case** (see below).

**Prompt Firewall:** when a request runs under a policy, PII (emails,
credit cards, SSNs, phone numbers, IP addresses, API keys) is masked
before storage and before the provider ever sees it. Any prompt
containing a blocked term is rejected and never sent.

### 4.1 Policy hierarchy

Policies → **Policy hierarchy**: one policy at three levels -
organization, team (and its sub-teams), agent - edited as a form or as
YAML. A lower level can only tighten: the smallest limit wins, every
level's allow list must allow, all deny / approval lists and blocked terms
apply, and a switch turned on anywhere stays on. It applies to the gateway
(limits, models, providers, blocked terms), to agent actions (tools,
delegation depth) and - the organization level - to user requests
(providers, blocked terms, approval). While you edit, *Effective policy*
shows every value with the level it comes from and lists what has no
effect because a level above is stricter. Every save is in the audit log.
Details: docs/policies.md.

---

## 5. Use Cases

A use case ties together a purpose, a risk level, and an approved policy
version.

1. Sidebar → **Policies → Use Cases** → **New use case**.
2. Set the name, risk level, and (optionally) the approved policy
   version and owner.

---

## 6. Usage Registry & Approvals

- **Usage Registry** lists every AI request with its purpose, status,
  and full request → response trace.
- If a request requires sign-off, it appears under **Approval
  Workflow**. Approvers open it and **Approve** or **Reject** with a
  reason. All decisions are audit-logged.
- **Overrides** let an admin manually stop, edit, or roll back a
  request when needed.

---

## 7. Incident Tracker

1. Sidebar → **Audit → Incident Tracker**.
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

1. Sidebar → **Discovery → Ingestion Sources** (admin only).
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
   are in the [README](README.md#7-endpoint-agent-optional).
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

Registry → Agents → **New agent**: fill in what the agent may do
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

Registry → **Teams & Roles**. Teams form a tree (organization → team →
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

Registry → **Attestation**. A policy says where agents must prove they run:
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

Enforcement → **Kill switch** stops AI in four steps: one **agent**, a
**team** (with its sub-teams), **all agents**, or **all AI traffic** (every
agent plus the gateway, AI requests and the playground). Each stop needs a
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
(`incident_created`, `approval_pending`, `request_blocked`,
`shadow_ai_reported`, `shadow_ai_blocked_domain`, and more). If email
(SMTP) is not configured on the server, email channels are skipped
silently; webhooks always work.

---

## 11. Audit & Reporting

Sidebar → **Audit → Audit Log**. Every change made through the platform
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

## 12. Tips

- **Keep the domain catalog current** — it is what turns raw telemetry
  into meaningful "allowed / blocked / unknown" signals.
- **One ingestion source per collector deployment** — so you can revoke
  a single agent or extension rollout without affecting others.
- **Review sightings regularly** and either sanction (Register) or
  Dismiss them, so the "Active" tab reflects only what still needs
  attention.
- **Least privilege** — give the endpoint agent `CAP_NET_RAW` only if
  you want ARP/DHCP discovery; everything else works without it.
