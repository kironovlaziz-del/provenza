# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Agent-to-agent messages (ASI07): send / receive attestation, channels, settings."""

from typing import Literal, Optional

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.user import User, UserRole
from app.schemas.a2a import A2AChannelIn, A2AReceiveIn, A2ASendIn, A2ASettingsIn
from app.services.a2a_guard import A2AGuard
from app.services.audit_service import AuditService

router = APIRouter()


@router.get("/")
async def overview(
    status: Optional[Literal["accepted", "quarantined", "rejected"]] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.approver)),
):
    return await A2AGuard(db).overview(current_user.org_id, status)


@router.put("/settings")
async def update_settings(
    data: A2ASettingsIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    before, after = await A2AGuard(db).save_settings(current_user.org_id, data.model_dump(), current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "a2a_guard", 0, "settings_updated",
                               {"before": before, "after": after})
    return after


@router.post("/send")
async def send(
    data: A2ASendIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Register a signed message before handing it to the recipient. Deliver only if deliver=true."""
    return await A2AGuard(db).send(current_user.org_id, data.envelope, data.signature, data.payload)


@router.post("/receive")
async def receive(
    data: A2AReceiveIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Called by the recipient before acting on a message. Act only if use=true."""
    return await A2AGuard(db).receive(current_user.org_id, data.agent_id, data.message_id, data.payload_sha256)


@router.post("/messages/{message_id}/release")
async def release(message_id: int, db: AsyncSession = Depends(get_db),
                  current_user: User = Depends(require_role(UserRole.admin))):
    r = await A2AGuard(db).release(current_user.org_id, message_id)
    await AuditService(db).log(current_user.org_id, current_user.id, "a2a_message", message_id, "message_released", r)
    return r


@router.post("/channels")
async def add_channel(data: A2AChannelIn, db: AsyncSession = Depends(get_db),
                      current_user: User = Depends(require_role(UserRole.admin))):
    r = await A2AGuard(db).add_channel(current_user.org_id, data.model_dump(), current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "a2a_channel", r["id"], "channel_created", r)
    return r


@router.post("/channels/{channel_id}/disable")
async def disable_channel(channel_id: int, db: AsyncSession = Depends(get_db),
                          current_user: User = Depends(require_role(UserRole.admin))):
    r = await A2AGuard(db).disable_channel(current_user.org_id, channel_id, current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "a2a_channel", channel_id, "channel_disabled", r)
    return r
