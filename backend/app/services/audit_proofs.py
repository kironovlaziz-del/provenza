# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Checkpoints, proofs and verification for the tamper-evident audit log
(app/core/audit_chain.py has the hashing, docs/audit-proofs.md the formats).

  - checkpoint(): sign the Merkle root of an organization's whole log
    (Celery beat runs it every 5 minutes for logs that grew);
  - inclusion_proof(): one record + the path to a signed checkpoint, the
    file tools/provenza_audit.py verifies offline;
  - consistency(): proof that a later checkpoint extends an earlier one;
  - verify_chain(): recompute everything from the stored records.

Proofs read all record hashes of the organization (32 bytes each), so they
cost O(n); fine for millions of records, not for billions.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import agent_signing as sig
from app.core import audit_chain as ac
from app.core.agent_signing import canonical_text
from app.core.crypto import decrypt_secret, encrypt_secret
from app.models.audit_log import (AIAuditLog, AuditCheckpoint, AuditKeyHandover, AuditKeyRotation,
                                  AuditSigningKey)

PROOF_FORMAT = "provenza.audit.proof/1"
CONSISTENCY_FORMAT = "provenza.audit.consistency/1"

# decrypted private keys by key id (they never change for an id)
_KEY_CACHE: Dict[int, Dict[str, Optional[str]]] = {}


class ProofError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# key
# ---------------------------------------------------------------------------

async def new_key(db: AsyncSession, org_id: int) -> AuditSigningKey:
    """A fresh audit key pair for the organization (Ed25519, plus ML-DSA-65
    when available). Flushed, not committed."""
    priv, pub = sig.generate_keypair()
    pq_seed = pq_pub = None
    if sig.pq_available():
        pq_seed, pq_pub = sig.generate_pq_keypair()
    key = AuditSigningKey(
        org_id=org_id,
        algorithm=sig.scheme_of(pq_pub),
        public_key=pub,
        pq_public_key=pq_pub,
        private_key_enc=encrypt_secret(priv),
        pq_seed_enc=encrypt_secret(pq_seed) if pq_seed else None,
        fingerprint=sig.key_fingerprint(pub, pq_pub),
        active=True,
    )
    db.add(key)
    await db.flush()
    return key


async def current_key(db: AsyncSession, org_id: int, create: bool = True) -> Optional[AuditSigningKey]:
    """The key that signs for the organization now:
      1. the new key of its latest key handover;
      2. otherwise the key of its latest checkpoint (this is how organizations
         keep the server-wide key from before per-organization keys);
      3. otherwise its own first key (never the new key of a pending rotation);
      4. otherwise a new key, when `create`.
    Callers hold the organization's checkpoint lock when they sign."""
    h = (await db.execute(
        select(AuditKeyHandover).where(AuditKeyHandover.org_id == org_id)
        .order_by(AuditKeyHandover.id.desc()).limit(1)
    )).scalar_one_or_none()
    if h:
        return await db.get(AuditSigningKey, h.new_key_id)
    cp = await latest_checkpoint(db, org_id)
    if cp:
        return await db.get(AuditSigningKey, cp.key_id)
    rotating = select(AuditKeyRotation.new_key_id).where(AuditKeyRotation.org_id == org_id)
    key = (await db.execute(
        select(AuditSigningKey).where(AuditSigningKey.org_id == org_id, AuditSigningKey.id.not_in(rotating))
        .order_by(AuditSigningKey.id).limit(1)
    )).scalar_one_or_none()
    if key or not create:
        return key
    return await new_key(db, org_id)


def sign_with(key: AuditSigningKey, payload: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    priv = _private(key)
    return sig.sign_payload(payload, priv["ed"]), (sig.sign_payload_pq(payload, priv["pq"]) if priv["pq"] else None)


async def lock_org(db: AsyncSession, org_id: int) -> None:
    """Serializes checkpoints and key changes of one organization (until commit)."""
    await db.execute(text("SELECT pg_advisory_xact_lock(:ns, :org)"),
                     {"ns": ac.LOCK_CHECKPOINT, "org": int(org_id)})


def _private(key: AuditSigningKey) -> Dict[str, Optional[str]]:
    if key.id not in _KEY_CACHE:
        _KEY_CACHE[key.id] = {
            "ed": decrypt_secret(key.private_key_enc),
            "pq": decrypt_secret(key.pq_seed_enc) if key.pq_seed_enc else None,
        }
    return _KEY_CACHE[key.id]


# ---------------------------------------------------------------------------
# reading the log
# ---------------------------------------------------------------------------

async def head(db: AsyncSession, org_id: int) -> int:
    return int((await db.execute(
        select(func.coalesce(func.max(AIAuditLog.seq), 0)).where(AIAuditLog.org_id == org_id)
    )).scalar_one())


async def leaves_of(db: AsyncSession, org_id: int, size: int) -> List[bytes]:
    rows = (await db.execute(
        select(AIAuditLog.seq, AIAuditLog.record_hash)
        .where(AIAuditLog.org_id == org_id, AIAuditLog.seq <= size)
        .order_by(AIAuditLog.seq)
    )).all()
    if len(rows) != size or any(r.seq != i + 1 for i, r in enumerate(rows)):
        raise ProofError("audit.chain_broken", "the audit log has a gap in its sequence; run a full verification")
    return [bytes.fromhex(r.record_hash) for r in rows]


async def latest_checkpoint(db: AsyncSession, org_id: int) -> Optional[AuditCheckpoint]:
    return (await db.execute(
        select(AuditCheckpoint).where(AuditCheckpoint.org_id == org_id)
        .order_by(AuditCheckpoint.tree_size.desc()).limit(1)
    )).scalar_one_or_none()


async def checkpoint_for(db: AsyncSession, org_id: int, size: int) -> Optional[AuditCheckpoint]:
    return (await db.execute(
        select(AuditCheckpoint).where(AuditCheckpoint.org_id == org_id, AuditCheckpoint.tree_size == size)
    )).scalar_one_or_none()


# ---------------------------------------------------------------------------
# checkpoints
# ---------------------------------------------------------------------------

async def checkpoint(db: AsyncSession, org_id: int) -> Optional[AuditCheckpoint]:
    """Sign the current log of the organization (no-op when the latest
    checkpoint already covers it). Commits. None for an empty log."""
    await lock_org(db, org_id)
    cp = await checkpoint_locked(db, org_id)
    await db.commit()
    if cp is not None:
        await db.refresh(cp)
    return cp


async def checkpoint_locked(db: AsyncSession, org_id: int) -> Optional[AuditCheckpoint]:
    """checkpoint() for a caller that holds lock_org and commits itself."""
    size = await head(db, org_id)
    latest = await latest_checkpoint(db, org_id)
    if size == 0 or (latest and latest.tree_size >= size):
        return latest
    leaves = await leaves_of(db, org_id, size)
    root = ac.merkle_root(leaves).hex()
    key = await current_key(db, org_id)
    issued_at = ac.now_utc()
    statement = ac.checkpoint_statement(org_id=org_id, tree_size=size, root_hash=root, issued_at=issued_at,
                                        key_fingerprint=key.fingerprint, algorithm=key.algorithm)
    signature, pq_signature = sign_with(key, statement)
    cp = AuditCheckpoint(
        org_id=org_id,
        tree_size=size,
        root_hash=root,
        issued_at=issued_at,
        statement=canonical_text(statement),
        algorithm=key.algorithm,
        signature=signature,
        pq_signature=pq_signature,
        key_id=key.id,
        public_key=key.public_key,
        pq_public_key=key.pq_public_key,
        key_fingerprint=key.fingerprint,
    )
    db.add(cp)
    await db.flush()
    return cp


async def stale_orgs(db: AsyncSession) -> List[int]:
    """Organizations whose log grew past their latest checkpoint."""
    heads = select(AIAuditLog.org_id, func.max(AIAuditLog.seq).label("n")).group_by(AIAuditLog.org_id).subquery()
    signed = (select(AuditCheckpoint.org_id, func.max(AuditCheckpoint.tree_size).label("n"))
              .group_by(AuditCheckpoint.org_id).subquery())
    rows = await db.execute(
        select(heads.c.org_id).select_from(heads.outerjoin(signed, signed.c.org_id == heads.c.org_id))
        .where(func.coalesce(signed.c.n, 0) < heads.c.n)
    )
    return [r[0] for r in rows]


def checkpoint_out(cp: AuditCheckpoint) -> Dict[str, Any]:
    """A checkpoint as a self-contained, verifiable JSON object."""
    return {
        "org_id": cp.org_id,
        "tree_size": cp.tree_size,
        "root_hash": cp.root_hash,
        "issued_at": ac.format_ts(cp.issued_at),
        "algorithm": cp.algorithm,
        "statement": cp.statement,
        "signature": cp.signature,
        "pq_signature": cp.pq_signature,
        "public_key": cp.public_key,
        "pq_public_key": cp.pq_public_key,
        "key_fingerprint": cp.key_fingerprint,
    }


def checkpoint_valid(cp: AuditCheckpoint) -> bool:
    """The stored statement says what the columns say and the signatures verify."""
    try:
        statement = ac.checkpoint_statement(
            org_id=cp.org_id, tree_size=cp.tree_size, root_hash=cp.root_hash, issued_at=cp.issued_at,
            key_fingerprint=cp.key_fingerprint, algorithm=cp.algorithm)
    except Exception:  # noqa: BLE001
        return False
    if canonical_text(statement) != cp.statement:
        return False
    if sig.key_fingerprint(cp.public_key, cp.pq_public_key) != cp.key_fingerprint:
        return False
    if cp.algorithm != sig.scheme_of(cp.pq_public_key):
        return False
    return sig.verify_agent_signature(statement, cp.signature, cp.pq_signature, cp.public_key, cp.pq_public_key)


def handover_out(h: AuditKeyHandover) -> Dict[str, Any]:
    """A key handover as a self-contained, verifiable JSON object."""
    return {
        "org_id": h.org_id,
        "rotation_id": h.rotation_id,
        "tree_size": h.tree_size,
        "root_hash": h.root_hash,
        "issued_at": ac.format_ts(h.issued_at),
        "statement": h.statement,
        "old_key_fingerprint": h.old_fingerprint,
        "old_public_key": h.old_public_key,
        "old_pq_public_key": h.old_pq_public_key,
        "old_signature": h.old_signature,
        "old_pq_signature": h.old_pq_signature,
        "new_key_fingerprint": h.new_fingerprint,
        "new_public_key": h.new_public_key,
        "new_pq_public_key": h.new_pq_public_key,
        "new_signature": h.new_signature,
        "new_pq_signature": h.new_pq_signature,
    }


def handover_valid(h: AuditKeyHandover) -> bool:
    """Statement canonical and matching the columns; fingerprints match the
    keys; BOTH keys' signatures verify (each hybrid when the key is)."""
    try:
        st = json.loads(h.statement)
    except ValueError:
        return False
    if canonical_text(st) != h.statement or st.get("type") != ac.HANDOVER_TYPE:
        return False
    expect = {"org_id": h.org_id, "rotation_id": h.rotation_id, "tree_size": h.tree_size, "root_hash": h.root_hash,
              "issued_at": ac.format_ts(h.issued_at), "old_key_fingerprint": h.old_fingerprint,
              "new_key_fingerprint": h.new_fingerprint,
              "old_algorithm": sig.scheme_of(h.old_pq_public_key), "new_algorithm": sig.scheme_of(h.new_pq_public_key)}
    if any(st.get(k) != v for k, v in expect.items()):
        return False
    if sig.key_fingerprint(h.old_public_key, h.old_pq_public_key) != h.old_fingerprint:
        return False
    if sig.key_fingerprint(h.new_public_key, h.new_pq_public_key) != h.new_fingerprint:
        return False
    if h.old_fingerprint == h.new_fingerprint:
        return False
    return (sig.verify_agent_signature(st, h.old_signature, h.old_pq_signature, h.old_public_key, h.old_pq_public_key)
            and sig.verify_agent_signature(st, h.new_signature, h.new_pq_signature, h.new_public_key,
                                           h.new_pq_public_key))


async def handovers(db: AsyncSession, org_id: int) -> List[AuditKeyHandover]:
    return list((await db.execute(
        select(AuditKeyHandover).where(AuditKeyHandover.org_id == org_id).order_by(AuditKeyHandover.id)
    )).scalars())


# ---------------------------------------------------------------------------
# proofs
# ---------------------------------------------------------------------------

def _record_out(row: AIAuditLog) -> Dict[str, Any]:
    payload = ac.payload_of(row)
    return {"id": row.id, "payload": payload, "canonical": canonical_text(payload), "record_hash": row.record_hash}


async def inclusion_proof(db: AsyncSession, org_id: int, log_id: int) -> Dict[str, Any]:
    row = (await db.execute(
        select(AIAuditLog).where(AIAuditLog.id == log_id, AIAuditLog.org_id == org_id)
    )).scalar_one_or_none()
    if row is None:
        raise ProofError("audit.not_found", "audit record not found")
    cp = await latest_checkpoint(db, org_id)
    if cp is None or cp.tree_size < row.seq:
        cp = await checkpoint(db, org_id)
    if cp is None or cp.tree_size < row.seq:  # pragma: no cover - the record exists, so the log is not empty
        raise ProofError("audit.no_checkpoint", "no checkpoint covers this record yet")
    leaves = await leaves_of(db, org_id, cp.tree_size)
    proof = ac.inclusion_proof(row.seq - 1, leaves)
    return {
        "format": PROOF_FORMAT,
        "record": _record_out(row),
        "leaf_index": row.seq - 1,
        "tree_size": cp.tree_size,
        "inclusion_path": ac.hexes(proof),
        "checkpoint": checkpoint_out(cp),
        "key_handovers": [handover_out(h) for h in await handovers(db, org_id)],
    }


async def consistency(db: AsyncSession, org_id: int, old_size: int, new_size: Optional[int] = None) -> Dict[str, Any]:
    old = await checkpoint_for(db, org_id, old_size)
    if old is None:
        raise ProofError("audit.checkpoint_not_found", f"no checkpoint of size {old_size}")
    new = await (checkpoint_for(db, org_id, new_size) if new_size else latest_checkpoint(db, org_id))
    if new is None:
        raise ProofError("audit.checkpoint_not_found", f"no checkpoint of size {new_size}")
    if new.tree_size < old.tree_size:
        raise ProofError("audit.bad_range", "the newer checkpoint must not be smaller than the older one")
    leaves = await leaves_of(db, org_id, new.tree_size)
    return {
        "format": CONSISTENCY_FORMAT,
        "old": checkpoint_out(old),
        "new": checkpoint_out(new),
        "consistency_path": ac.hexes(ac.consistency_proof(old.tree_size, leaves)),
        "key_handovers": [handover_out(h) for h in await handovers(db, org_id)],
    }


# ---------------------------------------------------------------------------
# full verification
# ---------------------------------------------------------------------------

async def verify_chain(db: AsyncSession, org_id: int, max_problems: int = 20) -> Dict[str, Any]:
    """Recompute every record hash, every link, and the root of every
    checkpoint; check every checkpoint signature."""
    checkpoints = list((await db.execute(
        select(AuditCheckpoint).where(AuditCheckpoint.org_id == org_id).order_by(AuditCheckpoint.tree_size)
    )).scalars())
    by_size: Dict[int, List[AuditCheckpoint]] = {}
    for cp in checkpoints:
        by_size.setdefault(cp.tree_size, []).append(cp)
    hos = await handovers(db, org_id)
    ho_by_size: Dict[int, List[AuditKeyHandover]] = {}
    for h in hos:
        ho_by_size.setdefault(h.tree_size, []).append(h)

    problems: List[Dict[str, Any]] = []
    total = 0

    def problem(kind: str, **kw):
        nonlocal total
        total += 1
        if len(problems) < max_problems:
            problems.append({"kind": kind, **kw})

    frontier = ac.Frontier()
    prev = ac.GENESIS_HASH
    expected_seq = 1
    records = 0
    roots_checked = 0
    result = await db.stream(
        select(AIAuditLog).where(AIAuditLog.org_id == org_id).order_by(AIAuditLog.seq)
        .execution_options(yield_per=1000, populate_existing=True)  # what the database holds, not the session's copies
    )
    async for row in result.scalars():
        records += 1
        if row.seq != expected_seq:
            problem("sequence_gap", seq=row.seq, id=row.id, expected=expected_seq)
            expected_seq = row.seq
        if row.prev_hash != prev:
            problem("broken_link", seq=row.seq, id=row.id)
        if ac.record_hash(ac.payload_of(row)) != row.record_hash:
            problem("record_altered", seq=row.seq, id=row.id)
        prev = row.record_hash
        expected_seq += 1
        frontier.append(bytes.fromhex(row.record_hash))
        for cp in by_size.get(frontier.size, ()):
            roots_checked += 1
            if frontier.root().hex() != cp.root_hash:
                problem("checkpoint_mismatch", tree_size=cp.tree_size, checkpoint_id=cp.id)
        for h in ho_by_size.get(frontier.size, ()):
            if frontier.root().hex() != h.root_hash:
                problem("handover_mismatch", tree_size=h.tree_size, rotation_id=h.rotation_id)

    signatures_checked = 0
    for cp in checkpoints:
        signatures_checked += 1
        if not checkpoint_valid(cp):
            problem("checkpoint_signature", tree_size=cp.tree_size, checkpoint_id=cp.id)
        if cp.tree_size > frontier.size:
            problem("checkpoint_beyond_log", tree_size=cp.tree_size, checkpoint_id=cp.id)

    # the key in use over time: every checkpoint is signed by the key the
    # previous handover handed to (or, before any, by the first key used),
    # and every handover starts from the key in use
    # (a handover at tree size T comes after every checkpoint up to T - the
    # old key signs those - and before every later one, signed by the new key)
    events = sorted([(cp.tree_size, 0, cp) for cp in checkpoints] + [(h.tree_size, 1, h) for h in hos],
                    key=lambda e: (e[0], e[1]))
    in_use: Optional[str] = None
    for _, kind, obj in events:
        if kind == 0:  # checkpoint
            if in_use is None:
                in_use = obj.key_fingerprint
            elif obj.key_fingerprint != in_use:
                problem("checkpoint_unexpected_key", tree_size=obj.tree_size, checkpoint_id=obj.id)
        else:
            if not handover_valid(obj):
                problem("handover_signature", tree_size=obj.tree_size, rotation_id=obj.rotation_id)
            if in_use is not None and obj.old_fingerprint != in_use:
                problem("handover_broken_chain", tree_size=obj.tree_size, rotation_id=obj.rotation_id)
            if obj.tree_size > frontier.size:
                problem("checkpoint_beyond_log", tree_size=obj.tree_size, rotation_id=obj.rotation_id)
            in_use = obj.new_fingerprint

    latest = checkpoints[-1] if checkpoints else None
    return {
        "ok": total == 0,
        "records": records,
        "head_seq": frontier.size,
        "head_hash": prev if records else None,
        "root_hash": frontier.root().hex() if records else None,
        "checkpoints": len(checkpoints),
        "checkpoint_roots_checked": roots_checked,
        "checkpoint_signatures_checked": signatures_checked,
        "key_handovers": len(hos),
        "latest_checkpoint_size": latest.tree_size if latest else 0,
        "problem_count": total,
        "problems": problems,
    }

