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
  arguments:                   # what a tool may be called WITH
    - {tool: "payments.refund", arg: amount, op: max, value: 100, effect: require_approval}
    - {tool: "email.send", arg: to, op: domain_in, value: ["provenza.dev"]}
```

Every key is optional; an unknown key is an error (a misspelt rule that
silently applied nothing would be worse). Lists take `*` patterns. YAML
anchors and aliases are refused, a level is at most 32 KiB and 10 levels of
brackets deep.

## A lower level can only tighten

| Field kind | How levels combine |
|---|---|
| limits (`requests_per_minute`, `max_tokens`, `max_delegation_depth`) | the smallest wins |
| allow lists (`models`, `providers`, `tools.allow`) | every level that has one must allow the value; a level without one does not restrict; `allow: []` allows nothing |
| deny / approval lists | all of them apply |
| argument rules (`tools.arguments`) | all of them apply; a lower level adds its own |

A team or agent level that tries to loosen — a higher limit, a model the
organization does not allow — has no effect. The editor
lists such entries under *No effect* and names the stricter level. Every
value of the effective policy shows the level it comes from.

## Where it applies

| | levels | fields |
|---|---|---|
| **Gateway** (agents' LLM calls) | gateway settings → organization → teams → agent | limits, models, providers |
| **Agent actions** (`/agents/actions/check`, delegation) | organization → teams → agent | tools allow / deny / approval, argument rules, models of model-invoking tools, delegation depth |

The gateway settings take part as the topmost level, so nothing changes on
upgrade: until an admin writes a level, the effective policy is exactly the
gateway settings. Agent policies (Agent Policies page) keep applying as
before; the hierarchy only adds restrictions to them.

A refusal names the level: `Blocked by policy 'team support policy'`,
`Model 'gpt-4o' is not allowed by the team ml policy`.

## Argument rules

A tool list says *which* tools an agent may call; `tools.arguments` says
*what with*. Each rule is a condition the call's arguments must meet; when
they do not, its `effect` applies: `deny` (the default) or
`require_approval` (the call waits for a person).

| Key | |
|---|---|
| `tool` | the tool, `*` patterns allowed (`payments.*`) |
| `arg` | the argument, a dotted path for a nested one (`options.cc`) |
| `op` | `max`, `min`, `max_length`, `equals`, `in`, `not_in`, `starts_with` (paths), `domain_in` (e-mail addresses), `matches`, `not_matches` (regular expressions) |
| `value` | a number, a text, or a list for `in`, `not_in`, `starts_with`, `domain_in` |
| `effect` | `deny` or `require_approval` |

They fail closed, as on the Agent Policies page (the same rules, the same
checks): an argument the rule names but the call leaves out breaks the rule;
in a list *every* element must meet it; a path is normalized before
`starts_with` (`/sandbox/../etc` is `/etc`); a number written as text counts
as a number, anything else that is not a number breaks `max` / `min`; a
regular expression is at most 300 characters and refused with nested
quantifiers such as `(a+)+`. A rule with an unknown key or operator is
refused when saved (`policy.bad_argument_rule`, `policy.unknown_key`), and
a level holds at most 100. A refusal names the level and the rule:
`Blocked by policy 'organization policy': argument 'amount' must satisfy max 100`.

Every level's rules apply, so a team or agent level can only add rules, and
under a [signed policy](#signed-policy) a rule taken out keeps applying
until the next signed release. The rules travel in the signed policy to the
egress proxy, which applies them itself (`sdk/testdata/policy-vectors.json`
holds the cases the server and the proxy decide alike).

In the form, **Argument constraints** under the tool lists edits them; a rule
that is not complete keeps the level from being saved, and a level with a
value the form would change (`in: [1, 2]`, `equals: true`) opens as YAML.

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
* **Form or YAML** — an empty allow list (`allow: []`, "allow nothing") can
  only be written and edited as YAML.

## Signed policy

What is edited here is the working copy. Once administrators have signed a
policy release ([pvp/edge.md](pvp/edge.md), section 3.1), every level must
also pass in the release: a level made stricter applies at once, a level
loosened applies after the quorum signs the next release. *Effective
policy* and the editor show the working copy; the *Signed policy* panel on
this page lists what is not signed yet.

## Rule packs

The **Rule packs** tab on this page holds ready-made sets of rules for a
level, built-in and your own, applied with one click after seeing what they
change.

* **Profiles** replace the whole policy of the level they are applied to:
  `org-strict`, `org-balanced`, `team-support`, `team-engineering`,
  `team-finance`, `team-research-readonly`, `agent-new-or-external` and
  `lockdown-allow-nothing` (an empty allow list: no tool at all until undone).
  The level gets the pack's text, comments included.
* **Guards** only add restrictions to what the level already has:
  `guard-destructive`, `guard-money`, `guard-exfiltration`, `guard-secrets`,
  `guard-production`, `guard-identity`, `guard-code-exec`,
  `guard-mass-messaging`, `guard-pii-export`, `guard-models`. A guard adds
  entries to `tools.deny` and `tools.require_approval`, lowers a limit the
  level has higher or not at all, and sets `models.allow` /
  `providers.allow` only on a level without its own list. It never allows a
  tool (`tools.allow` is refused in a guard). What the level already has, or
  has stricter, is left as it is and named in the preview.
* **Preview first** — applying shows each field before and after; the apply
  sends the revision the preview was made from, so a level saved by someone
  in between is not overwritten (`policy.stale`).
* **Undo** — every application is listed under *Applied*. Undoing a guard
  takes out exactly the entries and limits it added; anything added by hand,
  before or since, stays, and a limit changed by hand since keeps its value.
  Undoing a profile puts back the policy the level had before it; if the
  level was edited after the profile, the undo says so and asks to confirm,
  since those edits go with it.
* **Like an edit** — applying and undoing save the level exactly as the
  editor does: a new revision, an audit log entry (`policy_layer_*`) that
  names the pack (`pack`, `pack_ref`, `pack_application` or
  `pack_application_undone`). Under a [signed policy](#signed-policy) a
  pack that tightens applies at once; an undo, which loosens, applies after
  the next signed release.
* **Your own packs** — *New pack*, *Copy* of any pack, or *Upload YAML*;
  *Download* gives the YAML of any pack. A pack is written like a level's
  YAML. Deleting a pack leaves the levels it was applied to as they are.
  Up to 200 per organization.
* Guards may add argument rules (`tools.arguments`), and their undo takes
  out exactly those. The built-in packs have none: argument names differ
  from one tool to another, and a rule on an argument a tool does not have
  would refuse every call of it.

## API

| | |
|---|---|
| `GET /policy-layers/overview` | which levels have rules |
| `GET /policy-layers?scope=org\|team\|agent&target_id=` | one level |
| `PUT /policy-layers` `{scope, target_id, yaml \| document, revision}` | save (admin) |
| `POST /policy-layers/preview` | a draft and the effective policy it gives |
| `GET /policy-layers/effective?agent_id=` / `?team_id=` | the combined policy with sources |
| `GET /policy-layers/schema` | the fields and how they combine |
| `GET /policy-packs` | the built-in packs and the organization's own |
| `POST /policy-packs`, `PUT` / `DELETE /policy-packs/{id}` | an own pack `{name, description, kind: profile\|guard, level, yaml}` (admin) |
| `POST /policy-packs/preview` `{pack, scope, target_id}` | what applying would change (admin); `pack` is `builtin:<slug>` or `own:<id>` |
| `POST /policy-packs/apply` `{pack, scope, target_id, revision}` | apply it (admin) |
| `GET /policy-packs/applications` | what was applied where, and what was undone |
| `POST /policy-packs/applications/{id}/preview-undo` | what undoing would change (admin) |
| `POST /policy-packs/applications/{id}/undo` `{revision, confirm_edited}` | undo it (admin) |
