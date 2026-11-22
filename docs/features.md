# What Provenza does

Everything Provenza does, in one place. The [README](../README.md) has the short
version; each item links to its own guide.

## Live demo

**[stickstock.lol](https://stickstock.lol)** — click **Try the demo** (or sign in: organization
`demo`, e-mail `demo@stickstock.lol`, password `provenza-demo`). A read-only login to a demo bank: agents with their own
keys, a signed delegation chain, denied and held actions, a refused privilege
escalation, AI tools found on employees' laptops. In **Agent activity → Live Map**,
click a delegation and check its signature in your browser. The data is made
again every night.

## Verifiable agent governance

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

**Agent Manifest.** Provenza also issues a signed [Agent Manifest](agent-manifest.md)
for every agent (AgenTrust specification v0.2, hybrid Ed25519 + ML-DSA-65, both
signers required), binding the agent's approved MCP tools and the audit-log root.
It is listed in [AgenTrust's integrations](https://github.com/agentrust-io/integrations/tree/main/integrations/provenza-agent-manifest),
with a verifier you can run offline.

This is the kind of *verifiable accountability* the EU AI Act asks for — made
**clickable** ([how it works](agent-signing.md)). What it does and does not
guarantee is spelled out in the [security model](security-model.md).

<p align="center">
  <img src="hero-graph.svg" width="720" alt="Provenza: live delegation graph with in-browser signature verification">
</p>

> 🟦 active agent &nbsp; 🟥 policy violation &nbsp; — verified delegation &nbsp; ┈ blocked chain &nbsp; ✓ verified in your browser

## Try it on your own computer

From the published images, about a minute, nothing to build:

```bash
curl -fsSLO https://raw.githubusercontent.com/kironovlaziz-del/provenza/main/docker-compose.try.yml
docker compose -f docker-compose.try.yml up -d        # or: podman compose
```

(On Windows, in PowerShell: `curl.exe` instead of `curl`.)

Then http://localhost:8080 with organization `provenza`, `admin@example.com` /
`provenza-try-local`. Its ports listen only on this computer and that password is
public. **[A governed refund agent](../examples/governed-refund-agent/)** runs against
it: a refund over $100 waits for a person, a prompt injection that asks for the
customer list is refused.

## On a server

`sudo ./install.sh` asks for your domain and the first administrator, generates every
secret, runs the stack as rootful Podman containers managed by systemd (Quadlet),
gets an HTTPS certificate and schedules a daily backup. It also puts the egress
proxy and the endpoint agent on the server, with their keys - nothing to copy from
the interface; add `--sensor` for the eBPF egress sensor. Upgrades are one command,
`sudo provenza upgrade`: it backs up first and rolls back if the new version does
not come up ([self-hosting](self-hosting.md)).

- **Connect an agent** from the interface: AI agents → **Connect an agent**. Tick
  the tools it may use, and it gives one command for the machine where Gemini CLI,
  Claude Code, Cursor or any OpenAI-compatible client runs. The agent's keys are
  made there and never leave it.
- **Govern egress on another Linux host:** Runtime → **Register sensor** gives a
  one-line command that downloads the sensor from your Provenza (no Go, no git there).

## Governance

- **Governed LLM gateway** — agents reach OpenAI, Anthropic, Groq, Azure OpenAI
  or a self-hosted model through one OpenAI-compatible gateway, under the same
  rules. Every call is recorded as metadata (model, outcome, tokens, time) — the
  prompt and the answer are never stored. "Self-hosted providers only" is one switch.
- **Policy hierarchy and approvals** — one policy at three levels (organization →
  team → agent; lower levels only tighten), visual agent rules, and a person's
  approval for risky agent actions ([policy hierarchy](policies.md)).

## Shadow AI: unsanctioned AI

- **Endpoint agent** for Linux, Windows and macOS finds local models and AI
  agents (Claude Code, Cursor, Copilot, Aider, CrewAI, n8n, …), including unknown
  ones by their behavior. One command from the console installs it as a service;
  Intune, Group Policy and Jamf are covered.
- **Browser extension** (Chrome, Edge) reports visits to AI services, closes the
  ones your organization blocks and offers the approved ones instead. Deployed by
  policy, it also tells who uses what.
- **DNS and proxy logs** — upload a log (Squid, BIND, dnsmasq, Windows DNS, Zeek,
  Cisco Umbrella, Zscaler, …) or stream it with a log forwarder: AI use on every
  device on the network, without installing anything. Only the lines that reach
  an AI service are kept.
- **Passive network discovery** — read-only; nothing is connected automatically.
- Everything lands in one Sightings list, with an AI domain catalog, who uses each
  service, and device inventory ([collectors](shadow-ai.md)).

## Agents: autonomous AI

- **Registry** with scoped tools, delegation limits, teams and role templates.
- **Governed MCP gateway** — clients see only the tools an admin approved, and
  every call is checked and recorded. Desktop clients (Claude, Cursor, Gemini CLI,
  VS Code) start it as `uvx --from provenza provenza-mcp` ([SDK](../sdk/python/README.md#integrations)).
- **Agent frameworks** — LangChain, LangGraph, the OpenAI Agents SDK, CrewAI and
  AutoGen: wrap the tools in one line; every call is checked, recorded, and can
  wait for a person, a LangGraph graph pausing until the decision
  ([docs](integrations.md)).
- **Signed delegations and actions**, offline-verifiable ([above](#verifiable-agent-governance)).
- **Workload attestation** — Kubernetes, GitHub Actions, Google Cloud, Azure,
  GitLab, SPIFFE: each agent bound to its workload ([docs](attestation.md)).
- **One way out** — an egress proxy that holds the credentials and checks every
  outbound call ([egress lockdown](egress-lockdown.md)), and an eBPF sensor
  daemon that contains each governed workload's network in the kernel: allowed
  destinations only, DNS filtered, blocks reported ([sensor](../sensor/README.md)).
- **Behavior and circuit breakers** — baselines and self-protection.
- **Kill switch** in levels: agent → team → all agents → all AI traffic, with
  exact undo ([docs](kill-switch.md)).
- **SDKs** for [Python](../sdk/python/README.md), [JavaScript](../sdk/js/README.md) and
  [Go](../sdk/go/README.md).

## Identity and evidence

- **Single sign-on** (OpenID Connect) and **SCIM** — people switched off at the
  identity provider lose their sessions, and their agents' keys are revoked
  ([docs](identity-provider.md)).
- **Tamper-evident audit log** — append-only, hash-chained, signed Merkle
  checkpoints with RFC 3161 time-stamps; any record provable offline with
  `tools/provenza_audit.py` ([docs](audit-proofs.md)).
- **Proof of Authority** — for any agent action, one file shows who allowed
  it, every link signed: the task a person gave the agent, signed with their
  passkey; the policy release administrators signed with their
  passkeys, the agent's rights and key in it, each delegation hop, the
  agent's signature on the call, the approver's passkey. Checked offline,
  with a completeness report of everything an agent did over a period
  ([docs](proof-of-authority.md)).
- **Incidents, notifications** (e-mail, webhooks) and a compliance view.

