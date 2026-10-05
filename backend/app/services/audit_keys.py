# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Rotation of an organization's audit key (docs/audit-proofs.md).

A new key never takes effect quietly:
  1. an admin proposes it; the new key pair is created and its fingerprint
     shown - to be published OUTSIDE Provenza (to the auditor, a repository,
     the company site) before anything is signed with it;
  2. a quorum of distinct admins approves (AUDIT_KEY_ROTATION_QUORUM, the
     proposer counts as one); each approver must type the fingerprint as
     they found it published, not copy it from this server;
  3. after the notice period (AUDIT_KEY_ROTATION_NOTICE_HOURS) the change
     completes: the OLD key signs a handover naming the new key, the new
     key countersigns, and from then on checkpoints are signed by the new key.

Verifiers (tools/provenza_audit.py, the browser) accept a new key only when
BOTH hold: the handover chain from a key they trusted, and the new
fingerprint confirmed from the independent publication. Neither alone is
enough: a stolen old key could sign a handover, and a published fingerprint
says nothing about which history it continues.

Any single admin can cancel a pending rotation: stopping is easy, changing
the trust root is hard.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit_chain as ac
from app.core.agent_signing import canonical_text
from app.core.config import settings
from app.models.audit_log import AuditKeyHandover, AuditKeyRotation, AuditKeyRotationApproval, AuditSigningKey
from app.models.user import User, UserRole
from app.services import audit_proofs as ap
from app.services.audit_service import AuditService

log = logging.getLogger(__name__)

EVENT = "audit_key_rotation"


class RotationError(Exception):
    def __init__(self, code: str, status: int = 409, **context: Any):
        super().__init__(code)
        self.code, self.status, self.context = code, status, context


def required_quorum(rot: Optional[AuditKeyRotation] = None) -> int:
    """The stricter of the quorum at proposal time and the current setting."""
    q = settings.AUDIT_KEY_ROTATION_QUORUM
    return max(q, rot.quorum) if rot else q


async def _rotation(db: AsyncSession, org_id: int, rotation_id: int) -> AuditKeyRotation:
    rot = (await db.execute(
        select(AuditKeyRotation).where(AuditKeyRotation.id == rotation_id, AuditKeyRotation.org_id == org_id)
    )).scalar_one_or_none()
    if rot is None:
        raise RotationError("audit.rotation_not_found", 404)
    return rot


async def _pending(db: AsyncSession, org_id: int) -> Optional[AuditKeyRotation]:
    return (await db.execute(
        select(AuditKeyRotation).where(AuditKeyRotation.org_id == org_id, AuditKeyRotation.status == "pending")
    )).scalar_one_or_none()


async def _active_admins(db: AsyncSession, org_id: int) -> List[int]:
    rows = await db.execute(select(User.id).where(
        User.org_id == org_id, User.role == UserRole.admin.value, User.status == "active").order_by(User.id))
    return [r[0] for r in rows]


async def _valid_approvals(db: AsyncSession, rot: AuditKeyRotation) -> List[int]:
    """Approvals that count: by users who were active admins when the
    rotation was proposed AND still are."""
    eligible = set(rot.eligible_admins or []) & set(await _active_admins(db, rot.org_id))
    rows = await db.execute(
        select(AuditKeyRotationApproval.user_id)
        .where(AuditKeyRotationApproval.rotation_id == rot.id)
        .order_by(AuditKeyRotationApproval.user_id)
    )
    return [r[0] for r in rows if r[0] in eligible]


async def _notify(db: AsyncSession, org_id: int, subject: str, message: str, metadata: Dict[str, Any]) -> None:
    try:
        from app.services import notification_service

        await notification_service.notify(db, org_id, EVENT, subject, message, metadata)
    except Exception:  # noqa: BLE001 - a notification never blocks the rotation
        log.exception("audit key rotation notification failed")


# ---------------------------------------------------------------------------
# actions
# ---------------------------------------------------------------------------

async def propose(db: AsyncSession, org_id: int, user_id: int, reason: Optional[str]) -> AuditKeyRotation:
    await ap.lock_org(db, org_id)
    if await _pending(db, org_id):
        raise RotationError("audit.rotation_pending")
    # the old key must have signed something - otherwise there is nothing to hand over from
    if await ap.checkpoint_locked(db, org_id) is None:
        raise RotationError("audit.nothing_to_rotate")
    admins = await _active_admins(db, org_id)
    if user_id not in admins:
        raise RotationError("audit.rotation_not_eligible", 403)
    if len(admins) < required_quorum():
        raise RotationError("audit.quorum_unreachable", have=len(admins), need=required_quorum())
    old = await ap.current_key(db, org_id, create=False)
    new = await ap.new_key(db, org_id)
    now = ac.now_utc()
    rot = AuditKeyRotation(
        org_id=org_id, old_key_id=old.id, new_key_id=new.id, proposed_by=user_id, proposed_at=now,
        activate_after=now + timedelta(hours=settings.AUDIT_KEY_ROTATION_NOTICE_HOURS),
        quorum=required_quorum(), eligible_admins=admins, reason=(reason or "").strip()[:500] or None, status="pending",
    )
    db.add(rot)
    await db.flush()
    db.add(AuditKeyRotationApproval(rotation_id=rot.id, user_id=user_id, approved_at=now))
    meta = {"rotation_id": rot.id, "old_fingerprint": old.fingerprint, "new_fingerprint": new.fingerprint,
            "activate_after": ac.format_ts(rot.activate_after), "quorum": rot.quorum}
    await AuditService(db).log(org_id, user_id, "audit_key", rot.id, "rotation_proposed", meta)  # commits
    await _notify(db, org_id, "Audit key change proposed",
                  f"A new audit key was proposed: {new.fingerprint}. Publish this fingerprint outside Provenza; "
                  f"{rot.quorum} admins must approve it, and it cannot take effect before "
                  f"{ac.format_ts(rot.activate_after)}. If you did not expect this, cancel it.", meta)
    return rot


async def approve(db: AsyncSession, org_id: int, rotation_id: int, user_id: int, fingerprint: str) -> AuditKeyRotation:
    await ap.lock_org(db, org_id)
    rot = await _rotation(db, org_id, rotation_id)
    if rot.status != "pending":
        raise RotationError("audit.rotation_not_pending")
    new = await db.get(AuditSigningKey, rot.new_key_id)
    if user_id not in (rot.eligible_admins or []):
        raise RotationError("audit.rotation_not_eligible", 403)
    if (fingerprint or "").strip() != new.fingerprint:
        raise RotationError("audit.fingerprint_mismatch", 422)
    exists = (await db.execute(select(AuditKeyRotationApproval.id).where(
        AuditKeyRotationApproval.rotation_id == rot.id, AuditKeyRotationApproval.user_id == user_id))).first()
    if exists:
        raise RotationError("audit.rotation_already_approved")
    db.add(AuditKeyRotationApproval(rotation_id=rot.id, user_id=user_id, approved_at=ac.now_utc()))
    await db.flush()
    approvals = await _valid_approvals(db, rot)
    meta = {"rotation_id": rot.id, "new_fingerprint": new.fingerprint, "approvals": len(approvals),
            "quorum": required_quorum(rot)}
    await AuditService(db).log(org_id, user_id, "audit_key", rot.id, "rotation_approved", meta)
    await _notify(db, org_id, "Audit key change approved",
                  f"Approval {len(approvals)} of {required_quorum(rot)} for audit key {new.fingerprint}.", meta)
    return rot


async def cancel(db: AsyncSession, org_id: int, rotation_id: int, user_id: int) -> AuditKeyRotation:
    await ap.lock_org(db, org_id)
    rot = await _rotation(db, org_id, rotation_id)
    if rot.status != "pending":
        raise RotationError("audit.rotation_not_pending")
    rot.status, rot.decided_by, rot.decided_at = "cancelled", user_id, ac.now_utc()
    new = await db.get(AuditSigningKey, rot.new_key_id)
    meta = {"rotation_id": rot.id, "new_fingerprint": new.fingerprint}
    await AuditService(db).log(org_id, user_id, "audit_key", rot.id, "rotation_cancelled", meta)
    await _notify(db, org_id, "Audit key change cancelled",
                  f"The proposed audit key {new.fingerprint} was cancelled and will never be used.", meta)
    return rot


async def complete(db: AsyncSession, org_id: int, rotation_id: int, user_id: Optional[int]) -> AuditKeyHandover:
    """Hand over from the old key to the new one. user_id None = the scheduler."""
    await ap.lock_org(db, org_id)
    rot = await _rotation(db, org_id, rotation_id)
    if rot.status != "pending":
        raise RotationError("audit.rotation_not_pending")
    now = ac.now_utc()
    if now < rot.activate_after:
        raise RotationError("audit.rotation_notice", activate_after=ac.format_ts(rot.activate_after))
    approvals = await _valid_approvals(db, rot)
    need = required_quorum(rot)
    if len(approvals) < need:
        raise RotationError("audit.rotation_quorum", have=len(approvals), need=need)
    old = await ap.current_key(db, org_id, create=False)
    if old is None or old.id != rot.old_key_id:
        raise RotationError("audit.rotation_stale")
    new = await db.get(AuditSigningKey, rot.new_key_id)

    # the handover is tied to the log as it is now: the old key signs a last
    # checkpoint over everything so far, and the handover names that tree
    cp = await ap.checkpoint_locked(db, org_id)
    now = ac.now_utc()
    statement = ac.handover_statement(
        org_id=org_id, rotation_id=rot.id, tree_size=cp.tree_size, root_hash=cp.root_hash, issued_at=now,
        proposed_at=rot.proposed_at, quorum=need, approvals=approvals,
        old_key_fingerprint=old.fingerprint, old_algorithm=old.algorithm,
        new_key_fingerprint=new.fingerprint, new_algorithm=new.algorithm)
    old_sig, old_pq = ap.sign_with(old, statement)
    new_sig, new_pq = ap.sign_with(new, statement)
    h = AuditKeyHandover(
        org_id=org_id, rotation_id=rot.id, tree_size=cp.tree_size, root_hash=cp.root_hash, issued_at=now,
        statement=canonical_text(statement), old_key_id=old.id, new_key_id=new.id,
        old_fingerprint=old.fingerprint, new_fingerprint=new.fingerprint,
        old_public_key=old.public_key, old_pq_public_key=old.pq_public_key,
        new_public_key=new.public_key, new_pq_public_key=new.pq_public_key,
        old_signature=old_sig, old_pq_signature=old_pq, new_signature=new_sig, new_pq_signature=new_pq,
    )
    db.add(h)
    rot.status, rot.decided_by, rot.decided_at = "completed", user_id, now
    await db.flush()
    meta = {"rotation_id": rot.id, "old_fingerprint": old.fingerprint, "new_fingerprint": new.fingerprint,
            "tree_size": cp.tree_size, "approvals": approvals}
    await AuditService(db).log(org_id, user_id, "audit_key", rot.id, "rotation_completed", meta)  # commits
    await ap.checkpoint(db, org_id)  # the first checkpoint under the new key
    await _notify(db, org_id, "Audit key changed",
                  f"Checkpoints are now signed by {new.fingerprint} (was {old.fingerprint}). "
                  "Verifiers must confirm the new fingerprint from where it was published.", meta)
    await db.refresh(h)
    return h


async def complete_due(db: AsyncSession) -> Dict[str, int]:
    """Scheduler: complete pending rotations whose notice period is over and
    that have their quorum. Others are left alone."""
    due = (await db.execute(
        select(AuditKeyRotation.id, AuditKeyRotation.org_id)
        .where(AuditKeyRotation.status == "pending", AuditKeyRotation.activate_after <= ac.now_utc())
    )).all()
    await db.rollback()
    done = 0
    for rid, org_id in due:
        try:
            await complete(db, org_id, rid, None)
            done += 1
        except RotationError:
            await db.rollback()
        except Exception:  # noqa: BLE001
            await db.rollback()
            log.exception("audit key rotation %s failed", rid)
    return {"completed": done}


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

def _key_out(k: Optional[AuditSigningKey]) -> Optional[Dict[str, Any]]:
    if k is None:
        return None
    return {"fingerprint": k.fingerprint, "algorithm": k.algorithm, "public_key": k.public_key,
            "pq_public_key": k.pq_public_key, "organization_key": k.org_id is not None,
            "created_at": ac.format_ts(k.created_at)}


async def status(db: AsyncSession, org_id: int) -> Dict[str, Any]:
    current = await ap.current_key(db, org_id, create=False)
    pending = await _pending(db, org_id)
    pending_out = None
    if pending:
        new = await db.get(AuditSigningKey, pending.new_key_id)
        rows = (await db.execute(
            select(AuditKeyRotationApproval.user_id, AuditKeyRotationApproval.approved_at, User.email)
            .join(User, User.id == AuditKeyRotationApproval.user_id)
            .where(AuditKeyRotationApproval.rotation_id == pending.id)
            .order_by(AuditKeyRotationApproval.approved_at)
        )).all()
        valid = set(await _valid_approvals(db, pending))
        need = required_quorum(pending)
        pending_out = {
            "id": pending.id,
            "new_key": _key_out(new),
            "proposed_by": pending.proposed_by,
            "proposed_at": ac.format_ts(pending.proposed_at),
            "activate_after": ac.format_ts(pending.activate_after),
            "reason": pending.reason,
            "quorum": need,
            "approvals": [{"user_id": r.user_id, "email": r.email, "approved_at": ac.format_ts(r.approved_at),
                           "counts": r.user_id in valid} for r in rows],
            "eligible_admins": len(pending.eligible_admins or []),
            "ready": len(valid) >= need and ac.now_utc() >= pending.activate_after,
        }
    return {
        "current": _key_out(current),
        "pending": pending_out,
        "handovers": [ap.handover_out(h) for h in await ap.handovers(db, org_id)],
        "quorum": settings.AUDIT_KEY_ROTATION_QUORUM,
        "notice_hours": settings.AUDIT_KEY_ROTATION_NOTICE_HOURS,
    }
