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
  review first. **Register** opens agent registration with the name and
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
