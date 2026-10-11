# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Seals - recorded actions committed to the signed audit log in batches.

Writing one audit record per agent action would serialize every action of an
organization on the audit log's lock, and grow a log whose proofs cost O(n).
Instead, a Celery beat task (every minute) takes the organization's actions
whose evidence is not sealed yet, in id order, and writes ONE audit record:

    entity_type "pvp_action_seal", action "sealed",
    metadata {"root": <hex>, "size": n, "first_action_id", "last_action_id",
              "leaf_format": "pvp.action.evidence/1"}

root is the RFC 9162 Merkle root (app/core/audit_chain.py, the same hashing
as the audit log) over the actions' evidence hashes. The audit record is
covered by the next signed checkpoint, so an action is provable offline:

    evidence -> leaf in the seal -> seal record in the log -> signed checkpoint

A receipt asked for before the next run seals on the spot.
"""

import logging
from typing import List, Optional

from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit_chain as ac
from app.models.agent_action import AgentAction
from app.models.pvp_seal import PVPActionSeal
from app.services.audit_service import AuditService

log = logging.getLogger(__name__)

LOCK_SEAL = 0x50565A53   # advisory lock namespace (audit_chain uses ...41 and ...43)
MAX_BATCH = 10_000
ENTITY = "pvp_action_seal"
LEAF_FORMAT = "pvp.action.evidence/1"


def _unsealed(org_id: int):
    return (AgentAction.org_id == org_id, AgentAction.evidence_sha256.is_not(None), AgentAction.seal_id.is_(None))


async def seal_org(db: AsyncSession, org_id: int) -> Optional[PVPActionSeal]:
    """Seal the organization's unsealed actions (up to MAX_BATCH). Returns the
    seal, or None when there was nothing to seal. Commits."""
    await db.execute(text("SELECT pg_advisory_xact_lock(:ns, :org)"), {"ns": LOCK_SEAL, "org": int(org_id)})
    rows = (await db.execute(
        select(AgentAction.id, AgentAction.evidence_sha256).where(*_unsealed(org_id))
        .order_by(AgentAction.id).limit(MAX_BATCH)
    )).all()
    if not rows:
        await db.commit()
        return None
    ids = [r[0] for r in rows]
    root = ac.merkle_root([bytes.fromhex(r[1]) for r in rows]).hex()
    seal = PVPActionSeal(org_id=org_id, first_action_id=ids[0], last_action_id=ids[-1], size=len(ids), root=root)
    db.add(seal)
    await db.flush()
    seal_id = seal.id
    await db.execute(update(AgentAction).where(AgentAction.id.in_(ids)).values(seal_id=seal_id)
                     .execution_options(synchronize_session=False))
    # the audit record commits everything above together with itself
    record = await AuditService(db).log(org_id, None, ENTITY, seal_id, "sealed", {
        "root": root, "size": len(ids), "first_action_id": ids[0], "last_action_id": ids[-1],
        "leaf_format": LEAF_FORMAT,
    })
    seal = await db.get(PVPActionSeal, seal_id)
    seal.audit_log_id = record.id
    await db.commit()
    return seal


async def orgs_with_unsealed(db: AsyncSession) -> List[int]:
    return list((await db.execute(
        select(AgentAction.org_id).where(AgentAction.evidence_sha256.is_not(None), AgentAction.seal_id.is_(None))
        .group_by(AgentAction.org_id)
    )).scalars())


async def seal_all(db: AsyncSession) -> dict:
    sealed, actions, failed = 0, 0, 0
    orgs = await orgs_with_unsealed(db)
    await db.commit()  # end the read; nothing to keep or discard
    for org_id in orgs:
        try:
            while True:  # a large backlog is sealed in several batches
                seal = await seal_org(db, org_id)
                if seal is None:
                    break
                sealed, actions = sealed + 1, actions + seal.size
                if seal.size < MAX_BATCH:
                    break
        except Exception:  # noqa: BLE001 - one organization must not stop the others
            await db.rollback()
            failed += 1
            log.exception("sealing actions failed for org %s", org_id)
    return {"seals": sealed, "actions": actions, "failed": failed}


async def members(db: AsyncSession, seal_id: int) -> List[str]:
    """The evidence hashes of a seal, in leaf order."""
    return list((await db.execute(
        select(AgentAction.evidence_sha256).where(AgentAction.seal_id == seal_id).order_by(AgentAction.id)
    )).scalars())


async def unsealed_count(db: AsyncSession, org_id: int) -> int:
    return (await db.execute(select(func.count()).select_from(AgentAction).where(*_unsealed(org_id)))).scalar_one()
