"""
Audit log: list, plus the tamper-evidence endpoints (docs/audit-proofs.md).

    GET  /audit-logs/                       records, newest first
    GET  /audit-logs/integrity              head of the chain + latest signed checkpoint
    GET  /audit-logs/checkpoints            signed checkpoints, newest first
    POST /audit-logs/checkpoints            sign the current log now (admin)
    GET  /audit-logs/consistency?from_size= proof that the latest checkpoint extends an older one
    GET  /audit-logs/{id}/proof             inclusion proof of one record, verifiable offline
    POST /audit-logs/verify                 recompute the whole chain (admin)

    GET  /audit-logs/keys                                 current audit key, handovers, pending change
    POST /audit-logs/keys/rotations                       propose a new key (admin)
    POST /audit-logs/keys/rotations/{id}/approve          approve, typing the published fingerprint (admin)
    POST /audit-logs/keys/rotations/{id}/cancel           cancel (any admin)
    POST /audit-logs/keys/rotations/{id}/complete         hand over once quorum + notice are met (admin)
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.core.errors import api_error
from app.core.pagination import PaginationParams
from app.models.audit_log import AuditCheckpoint
from app.models.user import User, UserRole
from app.schemas.audit_log import AuditLogOut
from app.schemas.pagination import Page
from app.services import audit_keys, audit_proofs
from app.services.audit_keys import RotationError
from app.services.audit_proofs import ProofError
from app.services.audit_service import AuditService

router = APIRouter()
_admin = require_role(UserRole.admin)

_STATUS = {
    "audit.not_found": status.HTTP_404_NOT_FOUND,
    "audit.checkpoint_not_found": status.HTTP_404_NOT_FOUND,
    "audit.bad_range": status.HTTP_422_UNPROCESSABLE_ENTITY,
    "audit.chain_broken": status.HTTP_409_CONFLICT,
    "audit.no_checkpoint": status.HTTP_409_CONFLICT,
}


def _err(e: ProofError):
    return api_error(_STATUS.get(e.code, status.HTTP_400_BAD_REQUEST), e.code)


@router.get("/", response_model=Page[AuditLogOut])
async def list_audit_logs(
    entity_type: Optional[str] = None,
    entity_id: Optional[int] = None,
    actor_user_id: Optional[int] = None,
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = AuditService(db)
    items = await service.list_logs(
        current_user.org_id,
        entity_type=entity_type,
        entity_id=entity_id,
        actor_user_id=actor_user_id,
        skip=pagination.skip,
        limit=pagination.limit,
    )
    # Audit service returns only items (no total) - count is expensive on
    # large logs, so we return len(items) as the visible-total. A dedicated
    # count endpoint can be added later if needed.
    return Page(
        items=items,
        total=len(items),
        skip=pagination.skip,
        limit=pagination.limit,
    )


@router.get("/integrity")
async def integrity(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    head = await audit_proofs.head(db, current_user.org_id)
    cp = await audit_proofs.latest_checkpoint(db, current_user.org_id)
    return {
        "head_seq": head,
        "checkpoint": audit_proofs.checkpoint_out(cp) if cp else None,
        "unsigned_records": head - (cp.tree_size if cp else 0),
    }


@router.get("/checkpoints")
async def list_checkpoints(
    limit: int = Query(20, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    rows = (await db.execute(
        select(AuditCheckpoint).where(AuditCheckpoint.org_id == current_user.org_id)
        .order_by(AuditCheckpoint.tree_size.desc()).limit(limit)
    )).scalars()
    return [audit_proofs.checkpoint_out(cp) for cp in rows]


@router.post("/checkpoints")
async def create_checkpoint(db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    try:
        cp = await audit_proofs.checkpoint(db, current_user.org_id)
    except ProofError as e:
        raise _err(e)
    return audit_proofs.checkpoint_out(cp) if cp else None


@router.get("/consistency")
async def consistency(
    from_size: int = Query(..., ge=1),
    to_size: Optional[int] = Query(None, ge=1),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        return await audit_proofs.consistency(db, current_user.org_id, from_size, to_size)
    except ProofError as e:
        raise _err(e)


@router.post("/verify")
async def verify(db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    report = await audit_proofs.verify_chain(db, current_user.org_id)
    await AuditService(db).log(current_user.org_id, current_user.id, "audit_log", None, "chain_verified",
                               {"ok": report["ok"], "records": report["records"],
                                "problem_count": report["problem_count"]})
    return report


class RotationIn(BaseModel):
    reason: Optional[str] = Field(None, max_length=500)


class ApproveIn(BaseModel):
    # typed from where the fingerprint was published, not copied from this server
    fingerprint: str = Field(..., min_length=10, max_length=100)


def _rot_err(e: RotationError):
    return api_error(e.status, e.code, **e.context)


def _rot_out(rot) -> Dict[str, Any]:
    return {"id": rot.id, "status": rot.status}


@router.get("/keys")
async def key_status(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return await audit_keys.status(db, current_user.org_id)


@router.post("/keys/rotations")
async def propose_rotation(data: RotationIn, db: AsyncSession = Depends(get_db),
                           current_user: User = Depends(_admin)):
    try:
        return _rot_out(await audit_keys.propose(db, current_user.org_id, current_user.id, data.reason))
    except RotationError as e:
        raise _rot_err(e)


@router.post("/keys/rotations/{rotation_id}/approve")
async def approve_rotation(rotation_id: int, data: ApproveIn, db: AsyncSession = Depends(get_db),
                           current_user: User = Depends(_admin)):
    try:
        return _rot_out(await audit_keys.approve(db, current_user.org_id, rotation_id, current_user.id,
                                                 data.fingerprint))
    except RotationError as e:
        raise _rot_err(e)


@router.post("/keys/rotations/{rotation_id}/cancel")
async def cancel_rotation(rotation_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    try:
        return _rot_out(await audit_keys.cancel(db, current_user.org_id, rotation_id, current_user.id))
    except RotationError as e:
        raise _rot_err(e)


@router.post("/keys/rotations/{rotation_id}/complete")
async def complete_rotation(rotation_id: int, db: AsyncSession = Depends(get_db),
                            current_user: User = Depends(_admin)):
    try:
        h = await audit_keys.complete(db, current_user.org_id, rotation_id, current_user.id)
    except RotationError as e:
        raise _rot_err(e)
    return audit_proofs.handover_out(h)


@router.get("/{log_id}/proof")
async def proof(log_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        return await audit_proofs.inclusion_proof(db, current_user.org_id, log_id)
    except ProofError as e:
        raise _err(e)
