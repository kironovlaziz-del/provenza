# Tamper-evident audit log

Every change made through Provenza is written to the audit log
(`ai_audit_logs`). This document describes how that log is protected and
how anyone can check it without trusting the Provenza server.

## What it guarantees

| Layer | Protects against | Does not protect against |
|-------|------------------|--------------------------|
| **Append-only trigger** in PostgreSQL | application bugs, SQL injection through the app, an operator "fixing" a record by hand: `UPDATE` is refused always, `DELETE`/`TRUNCATE` unless the transaction sets `provenza.allow_purge` (only `scripts/delete_org.py` does) | the table owner or a superuser, who can switch the trigger off |
| **Hash chain** per organization | silent changes: altering, removing or reordering one record breaks every link after it, and **Verify whole log** reports where | someone who rewrites the record *and* recomputes every hash after it |
| **Signed checkpoints** (Merkle root, Ed25519 + ML-DSA-65) | that, too - once a checkpoint is kept outside the server. Any later checkpoint must be provably an extension of it (consistency proof); a rewritten history cannot produce one | records written after the last checkpoint you kept; a compromised server signing a *different* history for someone who never saw the old checkpoint |

In short: keep a checkpoint somewhere the server cannot reach (download it,
email it to the auditor, commit it to a repository). From then on, nobody -
including whoever runs the server - can change or delete what it covers
without being caught by `tools/provenza_audit.py`.

## Records and the chain

Each organization has its own chain. A record gets the next sequence
number `seq` (1, 2, 3, ...) and

```
record_hash = hex(SHA-256(canonical(payload)))
payload = {
  "v": 1,
  "org_id": 7,
  "seq": 42,
  "prev_hash": "<record_hash of seq 41, or 64 zeros for seq 1>",
  "created_at": "2026-10-05T09:15:02.123456Z",
  "actor_user_id": 3,            // null for system actions
  "entity_type": "policy",
  "entity_id": 12,               // may be null
  "action": "approved",
  "metadata": { ... }            // the record's details, may be null
}
```

`canonical()` is the same form Provenza uses for every signed payload
(docs/agent-signing.md): `json.dumps(payload, sort_keys=True,
separators=(",", ":"))` - keys sorted at every level, no whitespace,
non-ASCII escaped as `\uXXXX`.

Metadata is normalized before it is stored so it hashes the same after a
round trip through PostgreSQL JSONB: integral floats become integers,
NaN/Infinity become strings, values JSON cannot encode become their text.

Appends of one organization are serialized by a transaction-level advisory
lock; `(org_id, seq)` is unique. Existing records were chained by the
migration in the order they were written.

## Merkle tree and checkpoints

The record hashes, in `seq` order, are the leaves of a Merkle tree with the
hashing of RFC 9162 (Certificate Transparency v2):

```
leaf = SHA-256(0x00 || record_hash bytes)
node = SHA-256(0x01 || left || right)
```

A **checkpoint** is the server's signature over

```json
{"algorithm":"ed25519+ml-dsa-65","issued_at":"2026-10-05T09:20:00.000000Z",
 "key_fingerprint":"SHA256:...","org_id":7,"root_hash":"<hex>",
 "tree_size":42,"type":"provenza.audit.checkpoint","v":1}
```

(canonical form, signed as is). Each organization has its own audit key,
created with its first checkpoint and kept by the server encrypted with
`ENCRYPTION_KEY` (`scripts/rotate_encryption_key.py` re-encrypts it with
everything else). It is Ed25519 plus ML-DSA-65 (FIPS 204) when the server's
`cryptography` is 48 or newer - both signatures must verify. Its
fingerprint is SHA-256 over the raw Ed25519 key followed by the ML-DSA key,
like agent keys. Organizations whose logs were signed before
per-organization keys existed keep the server-wide key until they rotate.

Celery beat signs a checkpoint every 5 minutes for each log that grew;
admins can also press **Sign now**. Checkpoints are append-only too.

## Changing the audit key

A key change is the one moment a forged history could be slipped in, so it
needs two independent things, and verifiers require both:

1. **The old key consents.** The change ends with a *handover*: a statement
   naming the old and the new fingerprint and the log position
   (`tree_size`, `root_hash`), signed by the old key and countersigned by
   the new one (append-only table `audit_key_handovers`).
2. **The new fingerprint is published outside Provenza** - to the auditor,
   a repository, the company site - and confirmed from there. A stolen old
   key could sign a handover to the thief's key; it cannot also make the
   thief's fingerprint appear where the organization publishes its own.

How it runs (Audit Log -> Integrity -> Audit key, or the API):

| Step | Who | API |
|------|-----|-----|
| Propose: a new key pair is created, its fingerprint shown and announced | an admin | `POST /audit-logs/keys/rotations` |
| Publish the fingerprint outside Provenza | the organization | - |
| Approve, **typing the fingerprint as found where it was published** | `AUDIT_KEY_ROTATION_QUORUM` distinct active admins (default 2, the proposer counts) | `POST .../{id}/approve` |
| Wait for the announcement period | `AUDIT_KEY_ROTATION_NOTICE_HOURS` (default 24) | - |
| Hand over: the old key signs a last checkpoint and the handover, checkpoints switch to the new key | any admin, or the scheduler | `POST .../{id}/complete` |
| Cancel at any point before | any single admin | `POST .../{id}/cancel` |

Only the organization's active admins at the moment of the proposal may
approve (promoting or creating an admin afterwards does not help reach the
quorum), and only while they are still active admins; a proposal is refused
when the organization has fewer active admins than the quorum. every step
is in the audit log and sent to channels subscribed to
`audit_key_rotation`. The old key's private half stays encrypted in the
database (old checkpoints carry their public keys and keep verifying) but is
never used again.

A key whose old half is lost (e.g. `ENCRYPTION_KEY` lost) cannot be handed
over; that is a reset of trust - verifiers must pin the new fingerprint from
scratch - and is deliberately not offered as a button.

## Proofs

**Inclusion proof** - `GET /audit-logs/{id}/proof`, or **Proof → Download
proof** on the Audit Log page:

```json
{
  "format": "provenza.audit.proof/1",
  "record": {"id": 913, "payload": {...}, "canonical": "<exact text>", "record_hash": "<hex>"},
  "leaf_index": 41,
  "tree_size": 57,
  "inclusion_path": ["<hex>", "..."],
  "checkpoint": {"org_id": 7, "tree_size": 57, "root_hash": "...", "statement": "...",
                 "signature": "...", "pq_signature": "...", "public_key": "...",
                 "pq_public_key": "...", "key_fingerprint": "SHA256:...", "algorithm": "...",
                 "issued_at": "..."}
}
```

It shows one record is in the signed log without revealing any other
record.

**Consistency proof** - `GET /audit-logs/consistency?from_size=N[&to_size=M]`:
the checkpoint of `N` records, a later one (the latest by default) and the
RFC 9162 consistency path between them.

## Verifying offline

`tools/provenza_audit.py` needs only Python and `cryptography`, does not
contact the server and shares no code with it.

```bash
# a record is in the log, signed by the audit key you expect
python tools/provenza_audit.py verify proof.json --fingerprint SHA256:...

# a checkpoint on its own
python tools/provenza_audit.py checkpoint checkpoint.json --fingerprint SHA256:...

# today's log extends the checkpoint you saved last month
python tools/provenza_audit.py consistency consistency.json --pinned saved-checkpoint.json
```

Exit status 0 = verified, 1 = not verified, 2 = bad input. Take the
fingerprint from a checkpoint you saved earlier or got through another
channel - not from the file you are checking. `--fingerprint` can be given
several times.

After a key change, proofs and consistency files carry the handovers
(`key_handovers`). A fingerprint you pass with `--fingerprint` is trusted
directly. History that crosses the change - a consistency proof from a
checkpoint signed by the old key, or a proof checked against your old pin -
is accepted only if a chain of valid handovers leads from the key you
trusted to the new one **and** you pass the new fingerprint with
`--fingerprint`, confirmed where it was published. A key handed over twice
(a fork) is always refused:

```bash
python tools/provenza_audit.py consistency consistency.json \
    --pinned checkpoint-before-rotation.json --fingerprint SHA256:<new, as published>
```

### When verification fails after a rotation

Look at the trust chain before the signatures. The tool prints it first:
which fingerprints you trust and where each came from (`--fingerprint`,
the pinned file), the handovers linking them, and the key the file names.
The usual causes, in order:

1. the pinned fingerprint is outdated or came from the file itself rather
   than an independent source;
2. the new fingerprint was not passed, or differs from the published one
   (a typo, a different organization's key);
3. the file lacks the handovers (an old export) - download it again;
4. only then: a signature that does not verify, i.e. a forged file.

The Audit Log page does the same in the browser: pin the key once
("Pin this key in this browser"), and after a change it says whether the
old key handed over to the current one.

The Audit Log page runs the same checks in the browser (record hash,
inclusion path, both signatures, fingerprint) when you press **Check**.

## Verifying on the server

**Verify whole log** (admin, `POST /audit-logs/verify`) recomputes every
record hash and link, the root of every checkpoint and every checkpoint
signature, and lists the problems it finds: `record_altered`,
`broken_link`, `sequence_gap`, `checkpoint_mismatch`,
`checkpoint_signature`, `checkpoint_beyond_log`, and for key changes
`handover_signature`, `handover_mismatch`, `handover_broken_chain`,
`checkpoint_unexpected_key` (a checkpoint signed by a key nobody handed
over to). The run itself is
recorded in the audit log.

## Operations

- **Deleting an organization** (`scripts/delete_org.py`) removes its audit
  log and checkpoints; it sets `provenza.allow_purge` for its own
  transaction only. Nothing else can delete audit records.
- **Raw inserts are not possible**: `seq`, `prev_hash` and `record_hash`
  are required, so records must be written through the application
  (`AuditService.log`). The demo seed no longer inserts audit records.
- **Stronger separation**: run the application as a database role that does
  not own `ai_audit_logs` (it needs only `SELECT` and `INSERT` on it), so
  even the application cannot switch the trigger off.
- **Cost**: proofs read all record hashes of the organization (32 bytes
  each) - fine for millions of records.
