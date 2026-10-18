<p align="center">
  <img src="docs/hero-graph.svg" width="720" alt="Provenza — live delegation graph with in-browser signature verification">
</p>

<p align="center">
  <img src="provenza-logo-full.png" width="330" alt="Provenza">
</p>

<p align="center">
  <b>Provenance for every AI action.</b><br>
  <sub>See and govern every AI in your company — with provable accountability.</sub><br>
  From an employee pasting into ChatGPT to autonomous agents acting on their own —<br>
  watch it, control it, and <b>prove</b> every decision was authorized. Self-hosted, no external SaaS.
</p>

<p align="center">
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/kironovlaziz-del/provenza/actions/workflows/ci.yml"><img src="https://github.com/kironovlaziz-del/provenza/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/github/stars/kironovlaziz-del/provenza?style=flat&color=yellow" alt="Stars">
  <a href="CODE_OF_CONDUCT.md"><img src="https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg" alt="Contributor Covenant"></a>
  <a href="CONTRIBUTING.md"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome"></a>
  <a href="https://pypi.org/project/provenza/"><img src="https://img.shields.io/pypi/v/provenza?label=PyPI&color=blue" alt="PyPI"></a>
  <a href="https://pypi.org/project/provenza/"><img src="https://img.shields.io/pypi/pyversions/provenza?label=Python" alt="Python versions"></a>
  <a href="https://pypi.org/project/provenza/"><img src="https://img.shields.io/pypi/dm/provenza?label=Downloads" alt="Downloads"></a>
</p>

<p align="center">
  <a href="#-deploy-on-your-server"><b>🚀 Deploy</b></a> &nbsp;·&nbsp;
  <a href="#-what-makes-it-different"><b>✨ Why it's different</b></a> &nbsp;·&nbsp;
  <a href="#-features"><b>🧩 Features</b></a> &nbsp;·&nbsp;
  <a href="docs/README.md"><b>📖 Docs</b></a>
</p>

---

> **AI entered your company through every door at once** — shadow AI on laptops,
> autonomous agents delegating to each other, and no way to *prove* who authorized
> what. Most governance tools watch one door. **Provenza covers them all,
> under one set of rules.**

## 🚀 Deploy on your server

**Requirements:** Linux with systemd (Ubuntu 24.04+, Debian 13+, RHEL/Rocky 9.3+
or Fedora), 4 GB RAM, a domain pointing at the server. The installer sets up
Podman itself.

```bash
git clone https://github.com/kironovlaziz-del/provenza.git /opt/provenza
cd /opt/provenza
sudo ./install.sh
```

The installer asks for your domain and the first administrator, generates every
secret, runs the stack as rootful Podman containers managed by systemd (Quadlet),
gets an HTTPS certificate and schedules a daily backup.
Upgrades are one command, `sudo ./upgrade.sh`: it backs up first and rolls back if the
new version does not come up. Full guide: [docs/self-hosting.md](docs/self-hosting.md).

**Just looking?** `docker compose -f docker-compose.dev.yml up --build`, then
http://localhost:3000 with organization `demo`, `admin@demo.com` / `demo12345`
([development guide](docs/development.md)).

## ✨ What makes it different

### 🔐 Verifiable Agent Governance

When one AI agent delegates a task to another, the delegating agent **signs** the
handoff — the delegated capabilities, the TTL, a single-use nonce and a timestamp —
with **Ed25519**, or with a **post-quantum hybrid key (Ed25519 *and* ML-DSA-65,
FIPS 204)**, where both signatures must verify. With **agent-held keys**, Provenza
stores only the public key, so it cannot sign in the agent's name. Recorded agent
actions are signed the same way and bound to the policy check that allowed them.

**Proof that does not depend on trusting Provenza:** download the evidence for any
delegation or action and check it offline with `tools/provenza_sign.py` or plain
OpenSSL, against the key fingerprint the agent's owner gave you. On the live
delegation map, click an edge to run the same check in your browser.

This is the kind of *verifiable accountability* the EU AI Act asks for — made
**clickable** ([how it works](docs/agent-signing.md)). What it does and does not
guarantee is spelled out in the [security model](docs/security-model.md).

> 🟦 active agent &nbsp; 🟥 policy violation &nbsp; — verified delegation &nbsp; ┈ blocked chain &nbsp; ✓ verified in your browser

## 📸 Screenshots

<table>
  <tr>
    <td width="50%">
      <b>Live delegation map</b><br>
      <sub>Agents, delegations, violations — signatures verified in-browser</sub><br>
      <img src="docs/screenshots/live-map.png" alt="Live delegation map">
    </td>
    <td width="50%">
      <b>Dashboard</b><br>
      <sub>Requests, incidents, approvals, action trace at a glance</sub><br>
      <img src="docs/screenshots/dashboard.png" alt="Dashboard">
    </td>
  </tr>
  <tr>
    <td width="50%">
      <b>Provider Chat</b><br>
      <sub>Chat any LLM through the governance layer — secrets masked, logged</sub><br>
      <img src="docs/screenshots/provider-chat.png" alt="Governed provider chat">
    </td>
    <td width="50%">
      <b>Connections</b><br>
      <sub>Manage AI providers — keys encrypted, mock-mode without a key</sub><br>
      <img src="docs/screenshots/connections.png" alt="Connections — AI providers">
    </td>
  </tr>
</table>

## 🧩 Features

### 🎯 Governance — default

- **Governed access to any LLM** — chat with OpenAI, Anthropic, Groq, Azure OpenAI
  or a self-hosted model through the same rules; agents use an OpenAI-compatible
  gateway. Every call is logged. "Self-hosted providers only" is one switch.
- **Policies and approvals** — versioned policies built visually, a hierarchy
  (organization → team → agent; lower levels only tighten), and approval workflows
  ([policy hierarchy](docs/policies.md)).

### 🛡️ Content safety — optional add-on

Hidden by default. Set `CONTENT_SAFETY_ENABLED=true` in `deploy/.env` to show these pages. Useful
for regulated industries (finance, healthcare) where the provider's own content
filtering is not enough.

- **Prompt Firewall** — secrets and personal data (cards, keys, e-mails, IDs, your
  own patterns such as ПИНФЛ or contract numbers) are masked before a prompt is
  stored or leaves, even when disguised (spaced out, look-alike letters, base64).
  Each type is set to mask or block ([PII rules](docs/pii-rules.md)).
- **Blocked terms** — one list with scopes (organization, team, agent, policy),
  matching that sees through disguises ([docs](docs/blocked-terms.md)).
- **Intent guardrail** — a classifier model on your own connection (Llama Guard or
  any instruction model with your categories) flags or refuses what a prompt asks
  for, whatever the words ([docs](docs/intent-guardrail.md)).
- **Injection, memory and code-exec guards** — detect prompt injection, control
  code execution, and check memory / message content (Control → Protection).

### 👁️ Shadow AI — unsanctioned AI

- **Endpoint agent** finds local models and AI agents (Claude Code, Cursor,
  Copilot, Aider, CrewAI, n8n, …), including unknown ones by their behavior.
- **Browser extension** warns before a secret is pasted into an AI tool.
- **Passive network discovery** — read-only; nothing is connected automatically.
- Everything lands in one Sightings list, with an AI domain catalog and device
  inventory ([collectors](docs/shadow-ai.md)).

### 🤖 Agents — autonomous AI

- **Registry** with scoped tools, delegation limits, teams and role templates.
- **Signed delegations and actions**, offline-verifiable (above).
- **Workload attestation** — Kubernetes, GitHub Actions, Google Cloud, Azure,
  GitLab, SPIFFE: each agent bound to its workload ([docs](docs/attestation.md)).
- **One way out** — an egress proxy that holds the credentials and checks every
  outbound call ([egress lockdown](docs/egress-lockdown.md)), and an eBPF sensor
  daemon that contains each governed workload's network in the kernel: allowed
  destinations only, DNS filtered, blocks reported ([sensor](sensor/README.md)).
- **Behavior and circuit breakers** — baselines and self-protection
  (the prompt-injection, memory and code-exec guards are part of the optional
  content-safety add-on above).
- **Kill switch** in levels: agent → team → all agents → all AI traffic, with
  exact undo ([docs](docs/kill-switch.md)).
- **SDKs** for [Python](sdk/python/README.md), [JavaScript](sdk/js/README.md) and
  [Go](sdk/go/README.md).

### 📜 Identity and evidence

- **Single sign-on** (OpenID Connect) and **SCIM** — people switched off at the
  identity provider lose their sessions, and their agents' keys are revoked
  ([docs](docs/identity-provider.md)).
- **Tamper-evident audit log** — append-only, hash-chained, signed Merkle
  checkpoints with RFC 3161 time-stamps; any record provable offline with
  `tools/provenza_audit.py` ([docs](docs/audit-proofs.md)).
- **Incidents, notifications** (e-mail, webhooks) and a compliance view.

## 📖 Documentation

Start at **[docs/README.md](docs/README.md)**. The [user guide](USER_GUIDE.md)
([oʻzbekcha](USER_GUIDE.uz.md)) walks through the UI; the
[development guide](docs/development.md) covers running from source, configuration
and tests.

## Contributing

Bug reports, feature requests and pull requests are welcome. Please read
[CONTRIBUTING.md](CONTRIBUTING.md) first.

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security policy](SECURITY.md) — report vulnerabilities privately
- [Changelog](CHANGELOG.md)

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Copyright 2026 Laziz Kironov.

## Featured in

- [![Awesome AI Governance](https://img.shields.io/badge/Awesome-AI%20Governance-blue?logo=github)](https://github.com/agentrust-io/awesome-ai-governance)
- [![Awesome AI Agent Governance](https://img.shields.io/badge/Awesome-AI%20Agent%20Governance-blue?logo=github)](https://github.com/systempromptio/awesome-ai-agent-governance)

### Govern egress on any Linux host

The sensor is a separate, per-host install. It loads the eBPF programs that watch outbound connections, then reports to this control plane.

    git clone https://github.com/kironovlaziz-del/provenza.git
    cd provenza/sensor
    sudo ./install.sh --url https://your-provenza-domain

It asks for the sensor key: in the UI, Runtime -> Register sensor, copy the
pvz_sensor_... key and paste it (the input is hidden and stays out of the shell
history). Press Enter instead to only prepare the host and enroll later with
`sudo provenza-sensor enroll --url https://your-provenza-domain`.

