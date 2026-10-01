# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""BYOK: organization encryption keys (enable, rotate, disable, shred, check)."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
from app.models.user import User, UserRole
from app.schemas.byok import KeyConfigIn, ShredIn
from app.services.audit_service import AuditService
from app.services.byok_service import ByokService

router = APIRouter()


@router.get("/")
async def overview(db: AsyncSession = Depends(get_db),
                   current_user: User = Depends(require_role(UserRole.admin, UserRole.approver))):
    return await ByokService(db).overview(current_user.org_id)


@router.post("/keys")
async def new_key(data: KeyConfigIn, db: AsyncSession = Depends(get_db),
                  current_user: User = Depends(require_role(UserRole.admin))):
    """Enable BYOK, or rotate: a new data key under the given KEK; existing secrets are re-encrypted."""
    svc = ByokService(db)
    key, job = await svc.new_key(current_user.org_id, data.provider, data.config(), current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "org_key", key.id,
                               "byok_rotated" if job.kind == "rotate" else "byok_enabled",
                               {"provider": key.provider, "version": key.version, "config": key.config_public})
    return {"key_id": key.id, "version": key.version, **(await svc.start(job))}


@router.post("/disable")
async def disable(db: AsyncSession = Depends(get_db), current_user: User = Depends(require_role(UserRole.admin))):
    """Move the organization's secrets back to the server key."""
    svc = ByokService(db)
    job = await svc.disable(current_user.org_id, current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "org_key", 0, "byok_disabled", {})
    return await svc.start(job)


@router.post("/check")
async def check(db: AsyncSession = Depends(get_db), current_user: User = Depends(require_role(UserRole.admin))):
    return await ByokService(db).check(current_user.org_id)


@router.post("/jobs/{job_id}/retry")
async def retry(job_id: int, db: AsyncSession = Depends(get_db),
                current_user: User = Depends(require_role(UserRole.admin))):
    from fastapi import HTTPException
    from app.models.org_key import ByokJob
    job = await db.get(ByokJob, job_id)
    if job is None or job.org_id != current_user.org_id:
        raise HTTPException(status_code=404, detail="Job not found")
    return await ByokService(db).start(job)


@router.post("/shred")
async def shred(data: ShredIn, db: AsyncSession = Depends(get_db),
                current_user: User = Depends(require_role(UserRole.admin))):
    """Crypto-shredding: wipe every wrapped data key of the organization. Irreversible."""
    r = await ByokService(db).shred(current_user.org_id, data.confirm)
    await AuditService(db).log(current_user.org_id, current_user.id, "org_key", 0, "byok_shredded", r)
    return r
