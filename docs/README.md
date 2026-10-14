# Provenza documentation

## Running it

- [Self-hosting](self-hosting.md): install, HTTPS, backups, upgrades, troubleshooting
- [Production stack](../deploy/README.md): the containers `install.sh` runs
- [Development](development.md): running from source, tests, configuration, repository layout
- [User guide](../USER_GUIDE.md) ([oʻzbekcha](../USER_GUIDE.uz.md)): the UI, page by page

## Prompts and models

- [PII rules](pii-rules.md): what the Prompt Firewall masks or blocks, and your own patterns
- [Blocked terms](blocked-terms.md): one list with scopes, matching that sees through disguises
- [Intent guardrail](intent-guardrail.md): a classifier model that flags or refuses forbidden intents
- [Policy hierarchy](policies.md): organization → team → agent; lower levels only tighten

## Agents

- [Agent signatures](agent-signing.md): signing delegations and actions, verifying without trusting the server
- [Workload attestation](attestation.md): binding an agent to a Kubernetes or CI workload
- [Egress lockdown](egress-lockdown.md): leaving an agent one way out
- [Kill switch](kill-switch.md): stopping an agent, a team, all agents or all AI traffic
- SDKs: [Python](../sdk/python/README.md), [JavaScript](../sdk/js/README.md), [Go](../sdk/go/README.md)
- [Egress proxy](../proxy/README.md) and [egress sensor](../sensor/README.md)

## Shadow AI

- [Collectors](shadow-ai.md): endpoint agent, network discovery, browser extension

## Identity and evidence

- [Identity provider](identity-provider.md): single sign-on (OIDC), SCIM provisioning and offboarding
- [Tamper-evident audit log](audit-proofs.md): hash chain, signed checkpoints, RFC 3161 time-stamps, offline proofs
- [Security model](security-model.md): what is guaranteed, and what is not
