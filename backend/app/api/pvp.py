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
  GET /pvp/egress-catalog                AI provider domains an agent process must route
                                         through governance (app/pvp/egress.py); agent keys too
  GET /pvp/permits/{org}/jwks.json       the keys permits are signed with (app/pvp/permits.py);
                                         public, for tools
  POST /pvp/permits/redeem               a tool redeems a permit, once; the permit is the credential
  POST /pvp/permits/keys/rotate          a new permit key (admins)
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
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


@router.get("/egress-catalog")
async def egress_catalog(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """The hosts provenza.auto intercepts. The decision for each call is still
    the server's (an "egress" action checked against this catalog)."""
    from app.pvp import egress

    return {"action_type": egress.ACTION_TYPE, "tool_prefix": egress.PREFIX,
            "domains": await egress.catalog(db, user.org_id)}


# ---------------------------------------------------------------- permits

class RedeemIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    permit: str = Field(max_length=4096)
    tool: Optional[str] = Field(default=None, max_length=100)
    input_sha256: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")


@router.get("/permits/{org_slug}/jwks.json")
async def permit_jwks(org_slug: str, response: Response, db: AsyncSession = Depends(get_db)):
    """Public keys only - a tool needs no account to verify a permit."""
    from app.models.organization import Organization
    from app.pvp import permits

    org_id = (await db.execute(select(Organization.id).where(Organization.slug == org_slug))).scalar_one_or_none()
    if org_id is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "permit.unknown_issuer")
    keys = await permits.jwks(db, org_id)
    if not keys["keys"]:
        await permits.current_key(db, org_id)   # the first allowed check would make it; publish it now
        await db.commit()
        keys = await permits.jwks(db, org_id)
    response.headers["Cache-Control"] = "public, max-age=300"
    return keys


@router.post("/permits/redeem")
async def permit_redeem(data: RedeemIn, request: Request, db: AsyncSession = Depends(get_db)):
    """A tool about to run marks the permit used. `tool` and `input_sha256` are
    what it is about to run: a permit for anything else is refused, unused."""
    from app.core import rate_limit
    from app.pvp import permits

    rate_limit.enforce(request, scope="permit_redeem", limit=600, window_seconds=60)
    out = await permits.redeem(db, data.permit, tool=data.tool, input_sha256=data.input_sha256)
    await db.commit()
    return out


@router.post("/permits/keys/rotate")
async def permit_rotate(db: AsyncSession = Depends(get_db), user: User = Depends(require_role(UserRole.admin))):
    """A new permit key. Tools keep accepting permits of the old one for an
    hour (they live minutes), then only the new one."""
    from app.pvp import permits
    from app.services.audit_service import AuditService

    org_id, user_id = user.org_id, user.id
    key = await permits.rotate(db, org_id)
    kid = key.kid
    await db.commit()
    await AuditService(db).log(org_id, user_id, "organization", org_id, "permit_key_rotated", {"kid": kid})
    return {"kid": kid}
