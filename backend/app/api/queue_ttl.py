# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Request pipeline time limits: overview, settings, sweep now."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
from app.models.user import User, UserRole
from app.schemas.queue_ttl import QueueSettingsIn
from app.services import queue_ttl
from app.services.audit_service import AuditService

router = APIRouter()


@router.get("/")
async def overview(db: AsyncSession = Depends(get_db),
                   current_user: User = Depends(require_role(UserRole.admin, UserRole.approver))):
    return await queue_ttl.overview(db, current_user.org_id)


@router.put("/settings")
async def update_settings(data: QueueSettingsIn, db: AsyncSession = Depends(get_db),
                          current_user: User = Depends(require_role(UserRole.admin))):
    before, after = await queue_ttl.save_settings(db, current_user.org_id, data.model_dump(exclude_unset=True), current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "queue_settings", 0, "settings_updated",
                               {"before": before, "after": after})
    return after


@router.post("/sweep")
async def sweep_now(db: AsyncSession = Depends(get_db),
                    current_user: User = Depends(require_role(UserRole.admin))):
    counts = await queue_ttl.sweep_org(db, current_user.org_id, trigger="manual")
    await AuditService(db).log(current_user.org_id, current_user.id, "queue_settings", 0, "sweep_run", counts)
    return counts
