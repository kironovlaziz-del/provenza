# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Egress checks (app/services/egress_check.py) and the lockdown generator
(app/services/egress_lockdown.py).

  agents (X-Agent-Key)
    POST /agents/egress-check               targets and a beacon URL
    POST /agents/egress-check/{id}/report   what the host reached, signed
  admins and approvers
    GET  /agent-identity/egress             each agent's latest verdict
  everyone signed in
    POST /egress-lockdown/render            network rules that leave an agent only the egress proxy
  the beacon (no account; outside /api/v1, so the proxy's relay cannot carry it)
    GET  /egress-beacon/{token}
"""

from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, Header, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core import rate_limit
from app.core.database import get_db
from app.core.errors import api_error
from app.models.user import User, UserRole
from app.services import egress_check, egress_lockdown
from app.services.agent_identity import authenticate_agent_request

agent_router = APIRouter()
admin_router = APIRouter()
lockdown_router = APIRouter()
beacon_router = APIRouter()


async def _agent(request: Request, x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key"),
                 db: AsyncSession = Depends(get_db)) -> User:
    if not x_agent_key:
        raise api_error(status.HTTP_401_UNAUTHORIZED, "egress_check.agent_key_required")
    return await authenticate_agent_request(request, db, x_agent_key)


class Result(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str = Field(max_length=300)
    reachable: bool


class ReportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    results: List[Result] = Field(max_length=egress_check.MAX_TARGETS)
    beacon_reached: bool
    signature: str = Field(max_length=200)
    pq_signature: Optional[str] = Field(default=None, max_length=8000)


@agent_router.post("/egress-check")
async def start_check(request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(_agent)):
    return await egress_check.start(db, request.state.agent, str(request.base_url))


@agent_router.post("/egress-check/{check_id}/report")
async def report_check(check_id: int, data: ReportIn, request: Request, db: AsyncSession = Depends(get_db),
                       user: User = Depends(_agent)):
    return await egress_check.report(db, request.state.agent, check_id, [r.model_dump() for r in data.results],
                                     data.beacon_reached, data.signature, data.pq_signature)


@admin_router.get("/egress")
async def egress_overview(db: AsyncSession = Depends(get_db),
                          user: User = Depends(require_role(UserRole.admin, UserRole.approver))):
    return {"checks": await egress_check.overview(db, user.org_id)}


class LockdownIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["kubernetes", "docker", "nftables"]
    proxy_host: str = Field(default="provenza-proxy", max_length=253, pattern=r"^[A-Za-z0-9.:-]+$")
    proxy_port: int = Field(default=8443, ge=1, le=65535)
    namespace: str = Field(default="agents", max_length=63, pattern=r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
    proxy_namespace: str = Field(default="provenza-egress", max_length=63, pattern=r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
    agent_label: str = Field(default="provenza/egress=proxied", max_length=120,
                             pattern=r"^[A-Za-z0-9./_-]+=[A-Za-z0-9._-]*$")
    agent_user: str = Field(default="agent", max_length=32, pattern=r"^[a-z_][a-z0-9_-]*$")
    agent_service: str = Field(default="agent", max_length=63, pattern=r"^[a-z0-9][a-z0-9_-]*$")


@lockdown_router.post("/render")
async def render_lockdown(data: LockdownIn, request: Request, user: User = Depends(get_current_user)):
    from app.core.config import settings

    server = (settings.PUBLIC_BASE_URL or str(request.base_url)).rstrip("/")
    return egress_lockdown.render(data.kind, server_url=server, **data.model_dump(exclude={"kind"}))


@beacon_router.get("/egress-beacon/{token}")
async def beacon(token: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Reached directly from an agent's host: that host is not confined. The
    answer is the same for every token."""
    rate_limit.enforce(request, scope="egress_beacon", limit=120, window_seconds=60)
    await egress_check.beacon(db, token, request.client.host if request.client else None)
    return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"Cache-Control": "no-store"})
