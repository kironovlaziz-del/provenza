# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Agent identity: who-am-I for agents, key rotation / revocation, settings."""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.user import User, UserRole
from app.schemas.agent_identity import AgentIdentitySettingsIn
from app.services.agent_identity import AgentIdentityService
from app.services.audit_service import AuditService

router = APIRouter()


@router.get("/me")
async def me(request: Request, current_user: User = Depends(get_current_user)):
    """Called with X-Agent-Key: which agent the key belongs to."""
    agent = getattr(request.state, "agent", None)
    if agent is None:
        raise HTTPException(status_code=400, detail="Call this endpoint with an agent key (X-Agent-Key)")
    return {"agent_id": agent.id, "name": agent.name, "org_id": agent.org_id, "status": agent.status,
            "acting_for_user_id": current_user.id}


@router.get("/")
async def overview(db: AsyncSession = Depends(get_db),
                   current_user: User = Depends(require_role(UserRole.admin, UserRole.approver))):
    return await AgentIdentityService(db).overview(current_user.org_id)


@router.put("/settings")
async def update_settings(data: AgentIdentitySettingsIn, db: AsyncSession = Depends(get_db),
                          current_user: User = Depends(require_role(UserRole.admin))):
    before, after = await AgentIdentityService(db).save_settings(current_user.org_id, data.model_dump(), current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "agent_identity", 0, "settings_updated",
                               {"before": before, "after": after})
    return after


@router.post("/agents/{agent_id}/rotate")
async def rotate(agent_id: int, db: AsyncSession = Depends(get_db),
                 current_user: User = Depends(require_role(UserRole.admin))):
    """Issue a new key. It is returned once; the previous one works until the grace period ends."""
    r = await AgentIdentityService(db).rotate(current_user.org_id, agent_id)
    await AuditService(db).log(current_user.org_id, current_user.id, "agent", agent_id, "api_key_rotated",
                               {"previous_key_valid_until": str(r["previous_key_valid_until"])})
    return r


@router.post("/agents/{agent_id}/revoke")
async def revoke(agent_id: int, db: AsyncSession = Depends(get_db),
                 current_user: User = Depends(require_role(UserRole.admin))):
    r = await AgentIdentityService(db).revoke(current_user.org_id, agent_id)
    await AuditService(db).log(current_user.org_id, current_user.id, "agent", agent_id, "api_key_revoked", {})
    return r
