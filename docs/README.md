# Provenza documentation

## Running it

- [Quickstart](quickstart.md): install, connect Claude Code, see a tool call checked, refused and proven offline
- [Self-hosting](self-hosting.md): install, HTTPS, backups, upgrades, troubleshooting
- [Releases](releases.md): what a release publishes - source, SBOM, a signed record - and how to verify it
- [Production stack](../deploy/README.md): the containers `install.sh` runs
- [Monitoring](monitoring.md): the Observability page, Grafana, alert rules and where alerts go
- [Development](development.md): running from source, tests, configuration, repository layout
- [User guide](../USER_GUIDE.md) ([oʻzbekcha](../USER_GUIDE.uz.md)): the UI, page by page

## Policies and models

- [Policy hierarchy](policies.md): organization → team → agent; lower levels only tighten

## Agents

- [Agent signatures](agent-signing.md): signing delegations and actions, verifying without trusting the server
- [Workload attestation](attestation.md): binding an agent to a Kubernetes or CI workload
- [Agent Manifest](agent-manifest.md): a signed, offline-checkable record of an agent (AgenTrust Agent Manifest v0.2)
- [Hidden text in tool definitions](hidden-text.md): what a person approves is what the agent's model reads
- [Egress lockdown](egress-lockdown.md): leaving an agent one way out
- [Kill switch](kill-switch.md): stopping an agent, a team, all agents or all AI traffic
- [Automatic containment](containment.md): an agent that keeps reaching past its boundaries is quarantined on its own
- [Agent frameworks](integrations.md): LangChain, LangGraph, OpenAI Agents SDK, CrewAI and AutoGen - tools governed, held calls waiting for a person
- SDKs: [Python](../sdk/python/README.md), [JavaScript](../sdk/js/README.md), [Go](../sdk/go/README.md)
- [Egress proxy](../proxy/README.md) and [egress sensor](../sensor/README.md)
- [Sensor commands](sensor-commands.md): dump state, restart or detach a sensor with a signed command
- [SIEM export](siem-export.md): a SIEM or SOAR pulling the egress sensor events with a read-only key

## Shadow AI

- [Collectors](shadow-ai.md): endpoint agent, network discovery, browser extension

## Identity and evidence

- [Identity provider](identity-provider.md): single sign-on (OIDC), SCIM provisioning and offboarding
- [Tamper-evident audit log](audit-proofs.md): hash chain, signed checkpoints, RFC 3161 time-stamps, offline proofs
- [Incident bundle](incident-bundle.md): one file to investigate an agent incident - what the agent did, asked for and was refused, and who vouches for each line
- [Proof of Authority](proof-of-authority.md): who allowed an agent action, every link signed, checked offline; completeness of an agent's actions
- [Security model](security-model.md): what is guaranteed, and what is not
