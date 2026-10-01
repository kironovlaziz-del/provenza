# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Circuit breaker (ASI08): settings, per-agent overrides, tripped chains."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.user import User, UserRole
from app.schemas.breaker import BreakerConfig, OrgBreakerUpdate
from app.services.audit_service import AuditService
from app.services.circuit_breaker import BOUNDS, DEFAULTS, FIELDS, CircuitBreaker

router = APIRouter()


@router.get("/settings")
async def get_settings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    breaker = CircuitBreaker(db)
    return {
        "defaults": DEFAULTS,
        "bounds": BOUNDS,
        "org": await breaker.org_config(current_user.org_id),
        "overrides": await breaker.overrides(current_user.org_id),
    }


@router.put("/settings")
async def update_org_settings(
    data: OrgBreakerUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    if not data.enabled and not data.confirm_disable:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Disabling the circuit breaker requires confirm_disable=true",
        )
    cfg = {f: getattr(data, f) for f in FIELDS}
    before, after = await CircuitBreaker(db).save(current_user.org_id, None, cfg, current_user.id)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "agent_breaker", 0, "settings_updated",
        {"scope": "org", "before": before, "after": after},
    )
    return await CircuitBreaker(db).org_config(current_user.org_id)


@router.put("/settings/agents/{agent_id}")
async def set_agent_override(
    agent_id: int,
    data: BreakerConfig,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    cfg = {f: getattr(data, f) for f in FIELDS}
    before, after = await CircuitBreaker(db).save(current_user.org_id, agent_id, cfg, current_user.id)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "agent_breaker", agent_id, "override_updated",
        {"scope": "agent", "agent_id": agent_id, "before": before, "after": after},
    )
    return {**after, "agent_id": agent_id}


@router.delete("/settings/agents/{agent_id}")
async def delete_agent_override(
    agent_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    before = await CircuitBreaker(db).delete_override(current_user.org_id, agent_id)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "agent_breaker", agent_id, "override_removed",
        {"scope": "agent", "agent_id": agent_id, "before": before},
    )
    return {"deleted": True}


@router.get("/chains")
async def list_breaker_chains(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return await CircuitBreaker(db).breaker_chains(current_user.org_id)


@router.post("/chains/{chain_id}/resume")
async def resume_chain(
    chain_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    await CircuitBreaker(db).resume(current_user.org_id, chain_id)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "delegation_chain", chain_id, "breaker_resumed", {},
    )
    return {"chain_id": chain_id, "status": "active"}


@router.post("/chains/{chain_id}/terminate")
async def terminate_chain(
    chain_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    previous = await CircuitBreaker(db).terminate(current_user.org_id, chain_id)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "delegation_chain", chain_id, "terminated",
        {"from": previous},
    )
    return {"chain_id": chain_id, "status": "terminated"}
