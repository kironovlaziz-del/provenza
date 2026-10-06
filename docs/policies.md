# Policy hierarchy

One policy, three levels: **organization → team (its parent teams first) →
agent**. Each level is the same kind of document, edited as a form or as
YAML under Policies → Policy hierarchy.

```yaml
version: 1
description: Engineering defaults
limits:
  requests_per_minute: 30      # gateway calls per agent per minute
  max_tokens: 2000             # gateway completion cap
  max_delegation_depth: 2
models:
  allow: ["gpt-4o-mini", "claude-*"]
providers:
  allow: ["openai"]            # connection name or type
tools:
  allow: ["kb.*", "email.*"]
  deny: ["shell.*"]
  require_approval: ["email.send"]
content:
  scan_output: true
requests:
  require_approval: true       # user requests (organization level)
```

Every key is optional; an unknown key is an error (a misspelt rule that
silently applied nothing would be worse). Lists take `*` patterns. YAML
anchors and aliases are refused, a level is at most 32 KiB and 10 levels of
brackets deep. The `requests` section belongs to the organization level only
(user requests are not tied to a team or agent).

## A lower level can only tighten

| Field kind | How levels combine |
|---|---|
| limits (`requests_per_minute`, `max_tokens`, `max_delegation_depth`) | the smallest wins |
| allow lists (`models`, `providers`, `tools.allow`) | every level that has one must allow the value; a level without one does not restrict; `allow: []` allows nothing |
| deny / approval lists | all of them apply |
| switches (`scan_output`, `requests.require_approval`) | on at any level = on |

A team or agent level that tries to loosen — a higher limit, a switch turned
off, a model the organization does not allow — has no effect. The editor
lists such entries under *No effect* and names the stricter level. Every
value of the effective policy shows the level it comes from.

## Where it applies

| | levels | fields |
|---|---|---|
| **Gateway** (agents' LLM calls) | gateway settings → organization → teams → agent | limits, models, providers, output scanning |
| **Agent actions** (`/agents/actions/check`, delegation) | organization → teams → agent | tools allow / deny / approval, models of model-invoking tools, delegation depth |
| **User requests** (Policy Center) | organization | providers, approval required — on top of the use case's policy |

The gateway settings take part as the topmost level, so nothing changes on
upgrade: until an admin writes a level, the effective policy is exactly the
gateway settings. Agent policies (Agent Policies page) and use-case policies
keep applying as before; the hierarchy only adds restrictions to them.

A refusal names the level: `Blocked by policy 'team support policy'`,
`Model 'gpt-4o' is not allowed by the team ml policy`.

## Editing

* **Form or YAML** — the same document. The YAML tab keeps the text you wrote,
  comments included; the form writes a clean YAML when saved from it.
* **Preview** — while you type, the effective policy for the level (and, for a
  team or agent, everything above it) is recomputed, nothing saved.
* **Concurrent edits** — saving sends the revision you started from; if
  someone saved in between, the save is refused (`policy.stale`) instead of
  overwriting their change.
* **History** — *Clear this level* empties a level rather than deleting it.
  Every save is in the audit log (`policy_layer_org` / `_team` / `_agent`)
  with the document before and after. A team whose level still has rules is
  not deleted; once its level is cleared, deleting the team removes the empty
  level with it.
* **Who** — admins edit; admins and approvers read.
* **Blocked terms** are not part of a level: they are kept on the Blocked
  terms page with the same levels and more ([blocked-terms.md](blocked-terms.md));
  `content.blocked_terms` in a document is refused (`policy.blocked_terms_moved`).
* **Form or YAML** — an empty allow list (`allow: []`, "allow nothing") can
  only be written and edited as YAML.

## API

| | |
|---|---|
| `GET /policy-layers/overview` | which levels have rules |
| `GET /policy-layers?scope=org\|team\|agent&target_id=` | one level |
| `PUT /policy-layers` `{scope, target_id, yaml \| document, revision}` | save (admin) |
| `POST /policy-layers/preview` | a draft and the effective policy it gives |
| `GET /policy-layers/effective?agent_id=` / `?team_id=` | the combined policy with sources |
| `GET /policy-layers/schema` | the fields and how they combine |
