# Automatic containment

A refused call is not a problem by itself: an agent learns what it may do
by trying. An agent that is refused for reaching past what it was given,
again and again in a few minutes, is looking for another way in. While a
person reads the alert it keeps trying. Provenza stops such an agent on its
own, without waiting for anyone.

## What counts

A refusal counts when the agent reached past a boundary it was given:

- a tool not among its allowed tools, a model not among its allowed models;
- a delegation chain it is not part of, a delegation deeper than its limit,
  a capability it was not delegated;
- a call a policy denies (an organization, team or agent policy, an argument rule);
- an AI provider the organization blocks, or a cloud provider where only
  self-hosted ones are allowed;
- an egress proxy route: a method it does not allow, a path outside it, a
  `..` segment or an encoded separator in the path;
- a task from a person ([Proof of Authority](proof-of-authority.md#a-task-from-a-person)):
  a tool outside the task, a task given to another agent, a task that does
  not exist, a task named without the agent's own signature.

These do not count, because they are not the agent's doing: the agent
being stopped, a chain halted by the circuit breaker, a delegation that
expired, a tool that changed upstream or is not approved yet in the Tool
Registry, a task that ended or ran out, a call that waits for a person, a
malformed request.

Each check says whether it counted (`boundary` on the check).

## What happens

**Behavior Monitor → Settings → Automatic containment** (on by default):

| Setting | Default | |
|---------|---------|---|
| Refusals before quarantine | 3 | 1-100 |
| Within, minutes | 10 | 1-1440 |
| Tripwire tools | none | tool names, `*` allowed, up to 50 |

When the agent reaches the limit, it is quarantined at once, whatever the
behaviour monitor's mode:

- its status becomes `quarantined` and every later call is refused, on every gateway and SDK;
- the delegation chains it started are tripped, so the agents it delegated to stop too;
- the calls it left waiting for a person are closed (denied, the approval
  recorded as `expired`); an approval already given and not used yet is not
  redeemed after the release either;
- a critical `rogue_agent_quarantined` incident names the refusals that led
  to it (the last ten: tool, reason, time), and so does the agent's
  `agent` / `quarantined` record in the signed audit log - so the reason is
  not only the database's word. The [incident bundle](incident-bundle.md)
  carries it with the agent's own signed requests for those calls.

A **tripwire tool** is a name no agent has a reason to call - a decoy such
as `secrets.dump` or `admin.delete_*`. One call quarantines the agent, and
that call is already refused. It works also for a tool in the agent's own
allowed tools.

The Behavior Monitor lists the quarantined agents with the reason: the
refusals, the tripwire, or the behaviour score.

## Release

Only an administrator releases an agent, and the release is signed with the
session key their passkey certified, like a task or an approval:

    {"type": "provenza.agent.release", "v": 1, "org_id", "user_id", "session_id",
     "agent_id", "incident_id", "issued_at"}

`incident_id` is the quarantine it ends: a signed release cannot be kept
and used for a later quarantine. The proof is kept with the agent's
baseline and the audit log records `quarantine_released` with the
statement's hash. Counting starts again from the release.

`POST /api/v1/agent-behavior/agents/{id}/release/statement` returns the
statement, `POST .../release` takes `{statement, signature}`. A quarantined
agent cannot be switched back on through its edit form (not by way of
`suspended` either), and a stop of the [kill switch](kill-switch.md) that
holds it must be lifted first.
