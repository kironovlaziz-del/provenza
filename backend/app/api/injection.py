# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Prompt-injection guard (ASI01): settings, overview, tester, chain taint."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.user import User, UserRole
from app.schemas.injection import InjectionScanIn, InjectionSettingsIn
from app.services.audit_service import AuditService
from app.services.injection_detector import scan_text
from app.services.injection_guard import InjectionGuard

router = APIRouter()


@router.get("/")
async def overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.approver)),
):
    return await InjectionGuard(db).overview(current_user.org_id)


@router.put("/settings")
async def update_settings(
    data: InjectionSettingsIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    before, after = await InjectionGuard(db).save_settings(current_user.org_id, data.model_dump(), current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "injection_guard", 0, "settings_updated",
                               {"before": before, "after": after})
    return after


@router.post("/scan")
async def scan(
    data: InjectionScanIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Test a text against the detector with the organization's threshold. Nothing is stored."""
    cfg = await InjectionGuard(db).settings(current_user.org_id)
    return scan_text(data.text, cfg["threshold"])


@router.post("/chains/{chain_id}/clear")
async def clear_taint(
    chain_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    result = await InjectionGuard(db).clear_taint(current_user.org_id, chain_id, current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "delegation_chain", chain_id,
                               "injection_taint_cleared", {})
    return result
