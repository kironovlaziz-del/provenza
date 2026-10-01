# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
LLM gateway. /v1/* is OpenAI-compatible and is called by agents with their
own key - either X-Agent-Key or "Authorization: Bearer <agent key>", so a
stock OpenAI SDK works with base_url=<provenza>/api/v1/gateway/v1. The rest
is the admin side: overview, settings, routes.
"""

from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
from app.models.user import User, UserRole
from app.schemas.gateway import ChatCompletionIn, GatewayRouteIn, GatewaySettingsIn
from app.services.agent_identity import authenticate_agent_request
from app.services.audit_service import AuditService
from app.services.gateway_service import GatewayError, GatewayService

router = APIRouter()


async def gateway_agent(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key"),
    db: AsyncSession = Depends(get_db),
) -> User:
    key = x_agent_key
    if not key and authorization and authorization.lower().startswith("bearer "):
        key = authorization[7:].strip()
    if not key:
        raise HTTPException(status_code=401, detail="The gateway needs an agent key (X-Agent-Key or Bearer).")
    return await authenticate_agent_request(request, db, key)


@router.post("/v1/chat/completions")
async def chat_completions(data: ChatCompletionIn, request: Request, db: AsyncSession = Depends(get_db),
                           user: User = Depends(gateway_agent)):
    try:
        return await GatewayService(db).chat(request.state.agent, user, data.model_dump(exclude_none=False))
    except GatewayError as err:
        return JSONResponse(status_code=err.http_status, content=err.body())


@router.get("/v1/models")
async def list_models(request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(gateway_agent)):
    agent = request.state.agent
    return await GatewayService(db).models(agent.org_id, agent)


# ---------------------------------------------------------------- admin
@router.get("/")
async def overview(db: AsyncSession = Depends(get_db),
                   current_user: User = Depends(require_role(UserRole.admin, UserRole.approver))):
    return await GatewayService(db).overview(current_user.org_id)


@router.put("/settings")
async def update_settings(data: GatewaySettingsIn, db: AsyncSession = Depends(get_db),
                          current_user: User = Depends(require_role(UserRole.admin))):
    before, after = await GatewayService(db).save_settings(current_user.org_id, data.model_dump(), current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "gateway", 0, "settings_updated",
                               {"before": before, "after": after})
    return after


@router.post("/routes")
async def add_route(data: GatewayRouteIn, db: AsyncSession = Depends(get_db),
                    current_user: User = Depends(require_role(UserRole.admin))):
    r = await GatewayService(db).add_route(current_user.org_id, data.model_dump(), current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "gateway_route", r["id"], "route_created", r)
    return r


@router.post("/routes/{route_id}/disable")
async def disable_route(route_id: int, db: AsyncSession = Depends(get_db),
                        current_user: User = Depends(require_role(UserRole.admin))):
    r = await GatewayService(db).disable_route(current_user.org_id, route_id)
    await AuditService(db).log(current_user.org_id, current_user.id, "gateway_route", route_id, "route_disabled", r)
    return r
