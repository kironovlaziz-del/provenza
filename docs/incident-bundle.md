# Incident bundle

When an agent is stopped - by [automatic containment](containment.md), the
behaviour monitor, the circuit breaker - someone has to work out what it
did, what it tried, and on whose authority. The incident bundle puts that
in one file, and says for each piece who vouches for it.

**Incidents → Agents → Investigation file**, or

    GET /api/v1/pvp/incidents/{id}/bundle[?since=&until=]

for administrators, approvers and the oversight roles. The window (Unix
seconds) is by default an hour before the incident to a quarter of an hour
after it (or until now), at most seven days.

## What it holds

| Section | What | Who vouches for it |
|---------|------|--------------------|
| `completeness` | every action Provenza recorded for the agent in the window, shown to be all of them ([completeness report](proof-of-authority.md)) | the audit key: chained seals in the signed log |
| `audit` | the audit records about the agent (registered, quarantined with the refusals or signals that led to it, released, stopped, its key, its tasks) and about what governs every agent (the kill switch, the behaviour monitor's settings, policy releases, agent identity, the Tool Registry), each with its inclusion proof | the audit key |
| `checks` | every verdict the agent got in the window: tool, verdict, reason, whether it reached past its boundaries; for a call the agent asked for itself, its signed `action.request` | the agent's key, for a signed request; otherwise the server |
| `tasks` | the tasks a person gave the agent in the window, and what ended them | the person's passkey |
| `approvals` | decisions people signed on its held calls | the person's passkey |
| `release` | the signed release from quarantine | the person's passkey |
| `delegation` | the hops of the chains it is part of, and their state | the delegating agent's key (hops); the server (state) |
| `incident`, `other_incidents`, `agent` | the incident, the agent's other incidents in the window, the agent as it is now | the server - except a quarantine, whose record is in the signed log |

Like a receipt it holds ids, hashes, verdicts and reasons - never the input
or output of a call, never a check's token.

The `checks` matter most for an agent that was probing: when the agent
signs its requests (the SDKs and agent mode do), each refused call carries
the agent's own signature on exactly that tool and input hash. "The agent
asked for `files.delete` three times" is then the agent's word, not the
server's.

## Checking it

    python3 tools/provenza_audit.py incident incident-42.json \
        --fingerprint SHA256:<audit key> --agent-fingerprint SHA256:<agent key> \
        --passkey SHA256:<a person's passkey> [--list N] [--require-full]

It checks every signed piece offline (no code shared with the server) and
prints one timeline:

    VERIFIED  incident #42 (rogue_agent_quarantined, critical) of agent 7 "billing-bot"
              window 2026-11-16 09:40:00 UTC - 2026-11-16 10:55:00 UTC
              actions: 12 recorded in the window, and no other (seals 310..318)
              incident #42 (rogue_agent_quarantined): its record is in the signed audit log
              checks: 15 in the window, 15 asked for in the agent's own signed request; 3 refused for reaching past its boundaries (files.delete)
              the quarantine names 3 refusal(s) that led to it; the agent signed the request of 3 of them
    timeline (who vouches for each line):
      2026-11-16 09:41:02 UTC  person's passkey  task #5 given by user 2: Reconcile the October invoices
      ...
      2026-11-16 10:40:11 UTC  agent's key       check #981 files.delete denied [past its boundaries]: Tool 'files.delete' is not in the agent's allowed tools
      2026-11-16 10:40:12 UTC  signed log        agent quarantined - boundary_refusals
      2026-11-16 10:52:30 UTC  person's passkey  released from quarantine (incident #42) by user 1

A change to any signed piece fails the check. What rests on the server's
word is listed under `not proven:` - checks the agent did not sign, an
incident whose record is not in the signed log, a window the seals do not
reach - and `--require-full` turns that into a failure (exit 1).

Without `--agent-fingerprint` the signed requests prove that one key signed
them, and the file names it as the agent's; pin it with the fingerprint from
the agent's page. Without `--passkey`, what people signed verifies, but not
that those passkeys are the ones you trust.

## Limits

- Actions Provenza never saw (an agent calling a tool directly, without the
  [egress lockdown](egress-lockdown.md) or the sensor) are in no bundle.
- Checks are not chained in the audit log: a check the agent did not sign
  could be left out of the file without a trace. Signed ones cannot be made
  up, but could be left out too; actions cannot (completeness).
- Up to 5000 checks and 1000 audit records; the file says when the window
  held more.
