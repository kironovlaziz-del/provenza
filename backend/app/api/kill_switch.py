# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Kill switch (services/kill_switch.py).

    GET  /kill-switch              what is stopped now, agents by status
    GET  /kill-switch/events       history, active stops first
    POST /kill-switch/events       stop: scope agent|team|all_agents|org_traffic (admin)
    POST /kill-switch/events/{id}/lift   undo that stop (admin)

Organization-wide stops must repeat the scope in `confirm`, so a stray
call cannot stop the whole organization.
"""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
from app.core.errors import api_error
from app.models.user import User, UserRole
from app.services import kill_switch
from app.services.audit_service import AuditService

router = APIRouter()
_admin = require_role(UserRole.admin)
_reviewer = require_role(UserRole.admin, UserRole.approver)


class StopIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope: str = Field(pattern="^(agent|team|all_agents|org_traffic)$")
    target_id: Optional[int] = None
    reason: str = Field(min_length=3, max_length=2000)
    # organization-wide stops: the scope typed again
    confirm: Optional[str] = Field(default=None, max_length=40)
    terminate_chains: bool = True


class LiftIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Optional[str] = Field(default=None, max_length=2000)


@router.get("")
async def overview(db: AsyncSession = Depends(get_db), current_user: User = Depends(_reviewer)):
    return await kill_switch.overview(db, current_user.org_id)


@router.get("/events")
async def events(limit: int = Query(100, ge=1, le=500), db: AsyncSession = Depends(get_db),
                 current_user: User = Depends(_reviewer)):
    return await kill_switch.list_events(db, current_user.org_id, limit)


@router.post("/events", status_code=201)
async def stop(data: StopIn, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    if data.scope in kill_switch.ORG_WIDE and data.confirm != data.scope:
        raise api_error(422, "kill_switch.confirm_required", scope=data.scope)
    if data.scope in ("agent", "team") and data.target_id is None:
        raise api_error(422, "kill_switch.target_required")
    event = await kill_switch.engage(db, current_user.org_id, current_user.id, data.scope, data.target_id,
                                     data.reason, terminate_chains=data.terminate_chains)
    s = event.stopped or {}
    await AuditService(db).log(current_user.org_id, current_user.id, "kill_switch", event.id, "engaged", {
        "scope": event.scope, "target_id": data.target_id, "target_name": event.target_name, "reason": event.reason,
        "agents": [a["id"] for a in s.get("agents") or []], "chains": s.get("chains") or [],
    })  # commits the stop with its record
    await kill_switch.notify(db, event, lifted=False)
    return kill_switch.event_out(event, {current_user.id: current_user.email})


@router.post("/events/{event_id}/lift")
async def lift(event_id: int, data: LiftIn, db: AsyncSession = Depends(get_db),
               current_user: User = Depends(_admin)):
    event = await kill_switch.lift(db, current_user.org_id, current_user.id, event_id, data.reason)
    r = event.lift_result or {}
    await AuditService(db).log(current_user.org_id, current_user.id, "kill_switch", event.id, "lifted", {
        "scope": event.scope, "reason": event.lift_reason,
        "restored": [a["id"] for a in r.get("restored") or []],
        "kept": [a["id"] for a in r.get("kept") or []],
        "skipped": [a["id"] for a in r.get("skipped") or []],
    })
    await kill_switch.notify(db, event, lifted=True)
    users = await kill_switch.emails(db, [event.created_by, event.lifted_by])
    return kill_switch.event_out(event, users)
