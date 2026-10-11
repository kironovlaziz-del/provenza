# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
PVP evidence and administration.

  GET /pvp/receipts/{action_id}          the action's receipt (app/pvp/receipt.py):
                                         verifiable offline with tools/provenza_audit.py receipt
  GET /pvp/receipts/{action_id}/trace    the same as a TRACE v0.2 Trust Record (app/pvp/trace.py)
  GET /pvp/chains/{chain_id}/trace       one Trust Record for a whole delegation chain
  GET /pvp/guard-log                     what the Input Guard refused (admins)
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.config import settings
from app.core.database import get_db
from app.core.errors import api_error
from app.core.pagination import PaginationParams
from app.models.pvp_guard import PVPGuardLog
from app.models.user import User, UserRole
from app.schemas.pagination import Page

router = APIRouter()


class GuardLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    agent_id: Optional[int]
    user_id: Optional[int]
    protocol: str
    route: str
    reason: str
    findings: List[Dict[str, Any]]
    body_sha256: str
    size_bytes: int
    client_ip: Optional[str]
    created_at: datetime


@router.get("/guard-log", response_model=Page[GuardLogOut])
async def guard_log(
    agent_id: Optional[int] = None,
    reason: Optional[str] = None,
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """Refused requests of this organization, newest first."""
    where = [PVPGuardLog.org_id == current_user.org_id]
    if agent_id is not None:
        where.append(PVPGuardLog.agent_id == agent_id)
    if reason:
        where.append(PVPGuardLog.reason == reason)
    total = (await db.execute(select(func.count()).select_from(PVPGuardLog).where(*where))).scalar_one()
    rows = (await db.execute(
        select(PVPGuardLog).where(*where).order_by(PVPGuardLog.id.desc())
        .offset(pagination.skip).limit(pagination.limit)
    )).scalars().all()
    return Page(items=rows, total=total, skip=pagination.skip, limit=pagination.limit)


def _base(request: Request) -> str:
    return (settings.PUBLIC_BASE_URL or str(request.base_url)).rstrip("/")


@router.get("/receipts/{action_id}")
async def receipt(action_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Everything an auditor needs to verify this action without trusting
    this server. Seals the action first if the next run has not yet."""
    from app.pvp.receipt import build

    return (await build(db, user.org_id, action_id)).model_dump(mode="json")


@router.get("/receipts/{action_id}/trace")
async def receipt_trace(action_id: int, request: Request, db: AsyncSession = Depends(get_db),
                        user: User = Depends(get_current_user)):
    from app.models.agent import Agent
    from app.pvp import trace
    from app.pvp.receipt import build

    org_id = user.org_id
    r = await build(db, org_id, action_id)
    agent = await db.get(Agent, r.action.agent_id)
    return await trace.export(db, org_id, agent, [r], _base(request),
                              resolver=f"{_base(request)}{settings.API_V1_STR}/pvp/receipts/{action_id}")


@router.get("/chains/{chain_id}/trace")
async def chain_trace(chain_id: int, request: Request, db: AsyncSession = Depends(get_db),
                      user: User = Depends(get_current_user)):
    """One Trust Record for a delegation chain - the run: every recorded
    action of the chain (at most trace.MAX_CHAIN_ACTIONS), subject = the
    chain's root agent."""
    from app.models.agent import Agent
    from app.models.agent_action import AgentAction
    from app.models.delegation import DelegationChain
    from app.pvp import trace
    from app.pvp.receipt import build

    org_id = user.org_id
    chain = (await db.execute(select(DelegationChain).where(
        DelegationChain.id == chain_id, DelegationChain.org_id == org_id))).scalar_one_or_none()
    if chain is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "pvp.chain_not_found")
    root_agent_id = chain.root_agent_id
    ids = list((await db.execute(
        select(AgentAction.id).where(AgentAction.org_id == org_id, AgentAction.chain_id == chain_id,
                                     AgentAction.evidence.is_not(None))
        .order_by(AgentAction.id).limit(trace.MAX_CHAIN_ACTIONS + 1))).scalars())
    if not ids:
        raise api_error(status.HTTP_409_CONFLICT, "pvp.no_evidence")
    if len(ids) > trace.MAX_CHAIN_ACTIONS:
        raise api_error(status.HTTP_409_CONFLICT, "pvp.chain_too_long", max=trace.MAX_CHAIN_ACTIONS)
    proofs: dict = {}
    receipts = [await build(db, org_id, i, proofs) for i in ids]
    agent = await db.get(Agent, root_agent_id)
    return await trace.export(db, org_id, agent, receipts, _base(request))
