# Egress sensor commands

How the control plane tells a sensor to detach, restart, or dump its
state — and what stops a stolen control plane key from doing anything
worse.

## What a command is

A command is a small, signed instruction queued for exactly one sensor.
It has three parts:

- a **kind** — one of `detach`, `restart`, `dump-state`;
- a **payload** — the ids and timestamps that make this command
  unambiguous;
- an **Ed25519 signature** over the canonical form of the payload.

The sensor verifies the signature and every field of the payload before
doing anything. There is no channel back to the sensor other than the
heartbeat it already sends: the control plane never connects to a host,
never runs a shell, and cannot ask for anything outside the three kinds.

## Threat model

**What a signed command can do.** Uninstall the sensor from the host it
is queued for, restart its systemd unit, or ask it to report its own
status (the same JSON `provenza-sensor status --json` prints locally).

**What a stolen control plane signing key cannot do:**

- Run arbitrary commands. The three kinds are fixed in the sensor's
  binary; an unknown kind is refused.
- Target a different sensor. The payload names the sensor id, and the
  sensor refuses a command addressed elsewhere. The signing key is per
  organization, so the id is what tells commands apart.
- Replay an old command. Every command has an expiry of five minutes,
  and the sensor refuses one whose `expires_at` has passed.
- Trick the sensor into accepting a command from another organization.
  The signature verifies against the organization's own public key,
  which the sensor caches at enroll and never replaces on its own.

**What is out of scope.** An attacker with root on the sensor host is
already past everything here: they control the daemon, the kernel
program, and the key files. A compromised sensor key (`pvz_sensor_...`)
lets an attacker read the policy and post violations, but not issue
commands — the sensor key is not the signing key.

## The three commands

### `dump-state`

Ask the sensor to send back its own snapshot: host, config, hooks,
warnings, errors, current policy, governed cgroups, DNS counters.

Equivalent to running `provenza-sensor status --json` on the host, with
the result stored on the command row and shown in the UI under
*Show result*. It changes nothing on the host.

### `restart`

Ask systemd to restart the unit. The sensor acknowledges the command
before calling `systemctl restart`, because waiting for `systemctl`
would deadlock: systemctl waits for the process to exit, the process
waits for systemctl to return.

Enforcement pauses for about a second while the new daemon starts. The
pinned BPF links stay attached across the restart, so containment is not
lost; the new process reattaches to the same programs at startup.

### `detach`

Uninstall the sensor from the host: stop the systemd unit, detach the
pinned BPF links, remove `/etc/provenza-sensor`,
`/var/lib/provenza-sensor` and `/run/provenza-sensor`, then exit.

The ack is sent **before** the uninstall, because uninstall removes the
sensor key file the next ack would need. If the uninstall fails halfway
through, the command row shows `done` — the admin can then run
`provenza-sensor --uninstall` by hand on the host, or issue another
command.

Detach is irreversible from the sensor side: the daemon exits and there
is no code left to answer more commands. Re-enroll the host to bring a
sensor back.

## How the signature works

The control plane and the sensor must agree on the exact bytes that are
signed. Both use RFC 8785 (JSON Canonicalization Scheme, JCS): keys
sorted, no whitespace, UTF-8, numbers without exponent. In Python that
is `app.core.agent_signing.canonical_text`; in Go it is a struct with
fields in alphabetical order, marshalled by `encoding/json`.

Example payload:

    {
      "id": 42,
      "kind": "detach",
      "org_id": 7,
      "sensor_id": 3,
      "issued_at": "2026-10-16T09:00:00Z",
      "expires_at": "2026-10-16T09:05:00Z"
    }

The bytes signed are exactly:

    {"expires_at":"2026-10-16T09:05:00Z","id":42,"issued_at":"2026-10-16T09:00:00Z","kind":"detach","org_id":7,"sensor_id":3}

This string is pinned by a test on both sides
(`test_canonical_command_payload_bytes` in the backend,
`TestCanonicalBytesMatchPython` in the sensor). If either side ever
changes its JSON writer, both tests fail — that is the point.

## Flow

    Admin                Backend                        Sensor
      |                     |                             |
      |  POST /commands     |                             |
      |-------------------->|                             |
      |                     | create row (pending)        |
      |                     | sign payload with org key   |
      |                     |                             |
      |                     |<--- POST /heartbeat --------|
      |                     |     (every refresh_seconds) |
      |                     | deliver pending commands ---|
      |                     |                             |
      |                     |<--- POST /commands/N/ack ---|
      |                     |     status=executing        |
      |                     |                             |
      |                     |                             | verify signature
      |                     |                             | check payload
      |                     |                             | dispatch by kind
      |                     |                             |
      |                     |<--- POST /commands/N/ack ---|
      |                     |     status=done, result=... |

For `detach`, the second ack never arrives — the daemon is gone. The
command row stays at `executing` after the sensor exits, which is the
expected terminal state for that kind.

## Statuses

| Status      | Meaning                                                         |
|-------------|-----------------------------------------------------------------|
| `pending`   | Created; not yet delivered to the sensor.                       |
| `delivered` | Included in a heartbeat response; no ack yet. Re-sent next beat.|
| `executing` | The sensor acked that it accepted the command.                  |
| `done`      | The sensor finished and acked `done`.                           |
| `failed`    | The sensor reported an error; `error` explains it.              |
| `expired`   | Five minutes passed without an ack; the sweeper set this.       |

A command re-sends on every heartbeat until it is acked or expires,
because a sensor that crashed between receiving and acking should still
see it when it comes back.

## Setup

Enroll pulls three things and writes three files:

    sudo provenza-sensor enroll --url https://provenza.example.com --key pvz_sensor_...

- `/etc/provenza-sensor/key` — the sensor key (0600).
- `/etc/provenza-sensor/signing-key.pub` — the organization's public
  command signing key, base64 Ed25519 (0644).
- `/etc/provenza-sensor/sensor-id` — this sensor's own id (0644).

A missing endpoint (older backend) is a warning, not an error: the
sensor keeps enforcing policy, it just refuses every command until it
is re-enrolled against a backend that has the feature.

## Rotating or revoking the signing key

There is no automatic rotation. If the organization's signing key is
suspected compromised, generate a new one and re-enroll every sensor:
the sensors of the old key will refuse signatures made with the new
key, and vice versa. This is the same trade as the audit key: a simple
mechanism that is easy to reason about, at the cost of a manual step
when the trust root changes.

## Troubleshooting

**Command stuck at `pending` for more than `refresh_seconds`.**

- Check `provenza-sensor status` on the host: does `signing_key_file`
  and `sensor_id` show up under `Config`? If not, the sensor has not
  been re-enrolled since the feature was added.
- Check the sensor's log for `command refused`. A signature mismatch
  means the sensor is enrolled against a different organization's key.
- Check the sensor's log for `heartbeat err`. If heartbeats fail, the
  command cannot be delivered.

**Command goes straight to `expired`.**

Five minutes passed between issue and the sensor's next heartbeat. With
`refresh_seconds` above 300 (not possible through the UI, but possible
through the API) this would be normal; otherwise the sensor is not
reaching the control plane.

**The sensor answers `done` but nothing happens on the host.**

`dump-state` sends its answer back; `restart` schedules a systemd
restart; `detach` calls the same uninstall the `--uninstall` flag does.
For `restart`, look at `systemctl status provenzasensor` on the host: a
new process with a newer PID should be running.

**The signature does not verify.**

The canonical bytes must match exactly. If you have modified either the
Python canonicalization or the Go struct, the pinned tests will fail
long before this reaches a real host.
