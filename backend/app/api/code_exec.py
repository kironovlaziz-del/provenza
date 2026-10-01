# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Code-execution guard (ASI05): settings, overview, tester."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.user import User, UserRole
from app.schemas.code_exec import CodeExecScanIn, CodeExecSettingsIn
from app.services.audit_service import AuditService
from app.services.code_exec_guard import CodeExecGuard

router = APIRouter()


@router.get("/")
async def overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.approver)),
):
    return await CodeExecGuard(db).overview(current_user.org_id)


@router.put("/settings")
async def update_settings(
    data: CodeExecSettingsIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    before, after = await CodeExecGuard(db).save_settings(current_user.org_id, data.model_dump(), current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "code_exec_guard", 0, "settings_updated",
                               {"before": before, "after": after})
    return after


@router.post("/scan")
async def scan(
    data: CodeExecScanIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """What the guard would do with these arguments for this tool. Nothing is stored."""
    if data.arguments is None and not data.text:
        raise HTTPException(status_code=422, detail="arguments or text is required")
    args = data.arguments if data.arguments is not None else {"text": data.text}
    return await CodeExecGuard(db).scan(current_user.org_id, data.tool_name, args)
