# Proof of Authority

An audit log answers *what happened*. Proof of Authority answers the
question that matters after something goes wrong: **who allowed it**. For
one agent action, one file shows the whole chain of authority behind it,
every link signed, and a standalone tool checks the file offline without
trusting the Provenza server.

```
administrators' passkeys ──sign──► the policy release in force
                                     (its bundle: the agent's rights;
                                      its manifest: the agent's key)
the delegating agents' keys ─sign─► each hop of the delegation chain
the agent's key ─────────sign─────► the request for this very call
a person's passkey ──────certify──► the approval, when one let it run
the audit key ───────────sign─────► the checkpoint the action is sealed under
```

A **completeness report** goes with it: every action of one agent over a
period, shown to be all of them.

## Get one

**Audit Log → Evidence.** Show an action's receipt, then press **Download
proof of authority**. For a completeness report, give the agent's ID and
the period under **Completeness report of an agent**.

Through the API (administrators, approvers, auditors and compliance
officers; the file holds the whole signed policy):

```
GET /api/v1/pvp/authority/{action_id}
GET /api/v1/pvp/completeness?agent_id=5&since=<unix>&until=<unix>
```

## Check it

```bash
python3 tools/provenza_audit.py authority authority-41.json \
    --fingerprint SHA256:…        # the organization's audit key
    --passkey SHA256:…            # an administrator passkey you trust (repeatable)
    --agent-fingerprint SHA256:…  # the agent's key, from its owner
```

```
VERIFIED  proof of authority for action 41 (db.read, allowed) of agent 2
          policy:     release #4 (bundle v4 b587c3c109f5e4e7) signed by administrator 1 (passkey SHA256:jLXU…); history verified from release #1
          rights:     the signed policy gives agent 2 the tool db.read; its key SHA256:MnJ8… is the one in the signed manifest
          delegation: agent 1 -> agent 2 (hop 7, signed by SHA256:NDWC…)
          agent:      agent 2 signed the request for this call with key SHA256:MnJ8…
          approval:   approved by approver 3 with passkey SHA256:Q2xk… (listed in the signed manifest)
          record:     sealed in seal 12; checkpoint of 2048 records of organization 1 signed by SHA256:3kJC…
```

What each line checks:

| Link | Checked |
|---|---|
| **policy** | The release the action names (number and bundle hash, part of its sealed evidence) is in the file, and so is every release before it, back to the organization's first. Each one hashes to what was signed, carries its governing quorum's passkey signatures (WebAuthn, the person verified), and is governed by the release before it. `--passkey`: one of your passkeys signed the release the action was decided under. |
| **rights** | For an allowed action, the signed bundle has the agent active and the tool in its allowed tools. The agent's key is the one the signed manifest lists. |
| **delegation** | Each hop that brought the agent into its chain is signed by the delegating agent's key, and that key is in the signed manifest. A hop that names its tools passes this one on. |
| **agent** | The agent's own signature: on its action record (SDKs), or on the request for this call when a Provenza gateway executed it (agent mode signs each MCP call). |
| **approval** | When a person approved the call: the receipt's signed approval (session key certified by passkey), and that passkey is listed in the signed manifest. |
| **record** | Everything in the receipt: the evidence is a leaf of its seal, the seal a record of the audit log, the log signed by the audit key. |

A link that is **absent** rather than broken is reported as `not proven`,
and the first line reads `VERIFIED, WITH GAPS`:

- `policy` - the organization had no signed release in force (signing is
  optional), or the action was recorded before Proof of Authority. The
  agent's rights then rest on the server's word. Sign a release
  (**Rules → Policy hierarchy → Signed policy**) to close it.
- `agent` - a Provenza gateway executed the call and the agent did not
  sign it: an MCP client connected without agent mode, identified only by
  its key. `provenza-proxy connect` sets up agent mode.
- `delegation` - a hop by a keyless agent (only where the organization
  allows keyless agents).

`--require-full` turns gaps into a failure (exit status 1). A changed
document, a missing release, a forged hop or a signature that does not
verify is always a failure.

## Completeness

```bash
python3 tools/provenza_audit.py completeness completeness-agent-2.json --fingerprint SHA256:…
```

```
VERIFIED  seals 18..23 are unbroken: 5120 action(s) recorded between 2026-11-08 00:00:31 UTC and 2026-11-15 23:59:12 UTC, signed by SHA256:3kJC…
          agent 2: 214 action(s) in the period 2026-11-09 00:00:00 UTC - 2026-11-15 23:59:59 UTC, and no other in these seals
          201 allowed, 11 denied, 2 pending_approval
```

Actions are sealed in batches, and each seal's audit record names the seal
before it. The report carries a run of consecutive seals covering the
period, one more on each side, each with every action it holds (all
agents': an action's evidence is ids, hashes and signatures, never its
input or output). The tool checks that each seal's record is in the signed
log, that its root is exactly the Merkle root of the actions given (none
added, dropped or changed), and that each seal names the one before it
(none left out between them). The agent's actions in those seals are then
all the actions Provenza recorded for it in that stretch.

**What it cannot show.**
- An action Provenza never saw: an agent calling a tool directly. Where
  that matters, close the other paths: [egress lockdown](egress-lockdown.md)
  and the [egress sensor](../sensor/README.md).
- Anything before the seal chain began. Seals written before this version
  name no predecessor; the report starts after them.
- The stretch after the last sealed action: when the period runs past it,
  the tool says the report rests on the server's word for the rest.

A report covers at most 20,000 actions; choose a shorter period for a busy
organization.

## Limits

- **Trust anchors are yours to give.** The file proves the chain is
  intact and signed by the keys it names. That those are *your*
  organization's keys comes from outside: the audit key fingerprint you
  saved or published, an administrator's passkey fingerprint (*My profile →
  Passkeys*), the agent's key from its owner.
- **The history starts at the first release.** Whoever signed the first
  release defined the first quorum; the tool shows it, and `--passkey`
  pins what you trust.
- **Server-generated keys are not evidence** of the agent
  ([security model](security-model.md)). Re-enroll such agents with their
  own keys.

Formats: [PVP specification](pvp/spec.md), section 3.4 (the evidence's
`release` and `requested`, the seal chain) and section 5.1 (agent mode's
`X-Provenza-Action`).
