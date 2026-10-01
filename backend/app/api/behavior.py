# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Behaviour monitor (ASI10): settings, overview, baseline refresh, release."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.user import User, UserRole
from app.schemas.behavior import BehaviorSettingsIn
from app.services.audit_service import AuditService
from app.services.behavior_monitor import BOUNDS, WEIGHTS, BehaviorMonitor

router = APIRouter()


@router.get("/")
async def overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.approver)),
):
    data = await BehaviorMonitor(db).overview(current_user.org_id)
    return {**data, "bounds": BOUNDS, "weights": WEIGHTS}


@router.put("/settings")
async def update_settings(
    data: BehaviorSettingsIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    before, after = await BehaviorMonitor(db).save_settings(current_user.org_id, data.model_dump(), current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "behavior_monitor", 0, "settings_updated",
                               {"before": before, "after": after})
    return after


@router.post("/agents/{agent_id}/baseline")
async def refresh_baseline(
    agent_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """Recompute an agent's baseline now (normally done lazily, hourly)."""
    from sqlalchemy import select
    from fastapi import HTTPException
    from app.models.agent import Agent

    ok = (await db.execute(select(Agent.id).where(Agent.id == agent_id, Agent.org_id == current_user.org_id))).scalar_one_or_none()
    if not ok:
        raise HTTPException(status_code=404, detail="Agent not found")
    b = await BehaviorMonitor(db).baseline(current_user.org_id, agent_id, force=True)
    result = {"agent_id": agent_id, "mature": b.mature, "samples": b.sample_count, "span_days": b.span_days,
              "p95_per_5min": b.p95_per_5min, "denial_rate": b.denial_rate}
    await db.commit()
    return result


@router.post("/agents/{agent_id}/release")
async def release_agent(
    agent_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    await BehaviorMonitor(db).release(current_user.org_id, agent_id)
    await AuditService(db).log(current_user.org_id, current_user.id, "agent", agent_id, "quarantine_released", {})
    return {"agent_id": agent_id, "status": "active"}
