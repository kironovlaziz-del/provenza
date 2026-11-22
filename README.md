<p align="center">
  <img src="provenza-logo-full.png" width="300" alt="Provenza">
</p>

<p align="center">
  <b>Provenance for every AI action.</b><br>
  Find the AI in your company, decide what each agent may do,<br>
  and prove what it did - to anyone, offline.
</p>

<p align="center">
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/kironovlaziz-del/provenza/actions/workflows/ci.yml"><img src="https://github.com/kironovlaziz-del/provenza/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://www.bestpractices.dev/projects/16963"><img src="https://www.bestpractices.dev/projects/16963/badge" alt="OpenSSF Best Practices"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/kironovlaziz-del/provenza"><img src="https://api.scorecard.dev/projects/github.com/kironovlaziz-del/provenza/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://pypi.org/project/provenza/"><img src="https://img.shields.io/pypi/v/provenza?label=PyPI&color=blue" alt="PyPI"></a>
</p>

<p align="center">
  <a href="https://stickstock.lol"><b>Live demo</b></a> &nbsp;·&nbsp;
  <a href="docs/quickstart.md"><b>Quickstart</b></a> &nbsp;·&nbsp;
  <a href="https://youtu.be/me8UsPf4Ndw"><b>4-minute video</b></a> &nbsp;·&nbsp;
  <a href="docs/README.md"><b>Docs</b></a>
</p>

**Provenza** is an open-source, self-hosted AI governance platform for AI agents
and shadow AI. No external SaaS: your data stays on your server.

## What it does

- **Finds shadow AI.** An endpoint agent (Linux, Windows, macOS), a browser
  extension and your DNS or proxy logs show which AI tools people and machines
  use. [Shadow AI](docs/shadow-ai.md)
- **Controls AI agents.** Every tool call goes through an MCP gateway or a
  one-line wrapper (LangChain, LangGraph, OpenAI Agents SDK, CrewAI, AutoGen) and
  is checked against your policy before it runs. Risky calls wait for a person;
  a kill switch stops one agent or all of them.
  [Policies](docs/policies.md) · [Frameworks](docs/integrations.md)
- **Proves what happened.** A signed, tamper-evident audit log, published to
  Sigstore Rekor, and a signed proof of who allowed each agent action. Anyone can
  check them offline, without trusting your server.
  [Audit log](docs/audit-proofs.md) · [Proof of Authority](docs/proof-of-authority.md)

Works with Claude Code, Cursor, Gemini CLI, VS Code and any OpenAI-compatible
client. Everything else: **[what Provenza does](docs/features.md)**.

## Try it

**In the browser:** [stickstock.lol](https://stickstock.lol) → **Try the demo**
(read-only).

**On your computer** (about a minute, Docker or Podman):

```bash
curl -fsSLO https://raw.githubusercontent.com/kironovlaziz-del/provenza/main/docker-compose.try.yml
docker compose -f docker-compose.try.yml up -d
```

Open http://localhost:8080: organization `provenza`, `admin@example.com` /
`provenza-try-local` (a public password; the ports listen only on this computer).

**On a server** (Linux with systemd, 4 GB RAM, a domain):

```bash
git clone https://github.com/kironovlaziz-del/provenza.git /opt/provenza
cd /opt/provenza && sudo ./install.sh
```

Then the [quickstart](docs/quickstart.md) connects Claude Code and shows a tool
call checked, refused and proven offline.

## Documentation

- [What Provenza does](docs/features.md): every feature in one place
- [Quickstart](docs/quickstart.md) · [Self-hosting](docs/self-hosting.md) · [User guide](USER_GUIDE.md) ([oʻzbekcha](USER_GUIDE.uz.md))
- SDKs: [Python](sdk/python/README.md) · [JavaScript](sdk/js/README.md) · [Go](sdk/go/README.md)
- [Security model](docs/security-model.md): what is guaranteed, and what is not
- [All documentation](docs/README.md)

## Contributing

Bug reports and pull requests are welcome: [CONTRIBUTING.md](CONTRIBUTING.md) ·
[Code of Conduct](CODE_OF_CONDUCT.md) · [Security policy](SECURITY.md) ·
[Changelog](CHANGELOG.md)

Apache License 2.0, see [LICENSE](LICENSE). Copyright 2026 Laziz Kironov.

## Featured in

- [AgenTrust integrations](https://github.com/agentrust-io/integrations/tree/main/integrations/provenza-agent-manifest): Provenza Agent Manifest issuer
- [Awesome AI Governance](https://github.com/agentrust-io/awesome-ai-governance) · [Awesome AI Agent Governance](https://github.com/systempromptio/awesome-ai-agent-governance)
- MCP: [Glama](https://glama.ai/mcp/servers/kironovlaziz-del/provenza) · [mcpservers.org](https://mcpservers.org/servers/kironovlaziz-del/provenza) · [GitHub MCP Registry](https://github.com/mcp/kironovlaziz-del/provenza)
