# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
A2A gateway: the agent side and its administration (app/pvp/a2a_gateway.py).

Agents, with their own key (X-Agent-Key or "Authorization: Bearer <key>"):

  GET  /api/v1/a2a-gateway/<peer>/.well-known/agent-card.json
       the approved card, pointing at Provenza; A2A 1.0 when the request
       says A2A-Version: 1.0, else the 0.3 form (an empty version is 0.3)
  POST /api/v1/a2a-gateway/<peer>
       JSON-RPC: SendMessage / GetTask / CancelTask (1.0) and message/send /
       tasks/get / tasks/cancel (0.3). Streaming, push-notification configs,
       ListTasks and the extended card answer UnsupportedOperation /
       PushNotificationNotSupported.

A peer the agent may not reach answers 404, exactly like one that does not
exist. Admins manage peers at /api/v1/a2a-peers.
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.api.mcp import _check_header, _origin_ok
from app.core.config import settings
from app.core.crypto import encrypt_secret
from app.core.database import get_db
from app.core.errors import api_error
from app.core.outbound import validate_url
from app.models.a2a_gateway import A2APeer
from app.models.tool_registry import ToolRegistryEntry
from app.models.user import User, UserRole
from app.pvp import a2a_gateway as gw_module
from app.pvp import a2a_wire as w
from app.pvp import guard as pvp_guard
from app.pvp.a2a_gateway import A2AGateway, CHAIN_META, tool_name
from app.pvp.upstream_http import UpstreamError
from app.services.agent_identity import authenticate_agent_request
from app.services.audit_service import AuditService

agent_router = APIRouter()
admin_router = APIRouter()
SLUG = r"[a-z0-9][a-z0-9-]{0,39}"


async def a2a_agent(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key"),
    db: AsyncSession = Depends(get_db),
) -> User:
    key = x_agent_key
    if not key and authorization and authorization.lower().startswith("bearer "):
        key = authorization[7:].strip()
    if not key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="a2a.agent_key_required",
                            headers={"WWW-Authenticate": "Bearer"})
    return await authenticate_agent_request(request, db, key)


def _error(rid: Any, code: int, message: str, data: Any = None, http: int = 200) -> JSONResponse:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return JSONResponse(status_code=http, content={"jsonrpc": "2.0", "id": rid, "error": err})


def _base(request: Request) -> str:
    return (settings.PUBLIC_BASE_URL or str(request.base_url)).rstrip("/")


def _not_found() -> HTTPException:
    return api_error(status.HTTP_404_NOT_FOUND, "a2a.peer_not_found")


@agent_router.get("/{slug}/.well-known/agent-card.json")
async def agent_card(slug: str, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(a2a_agent)):
    if not re.fullmatch(SLUG, slug):
        raise _not_found()
    peer = await A2AGateway(db).reachable(request.state.agent, slug)
    if peer is None:
        raise _not_found()
    version = w.version_of(request.headers.get("a2a-version") or request.query_params.get("A2A-Version"))
    url = f"{_base(request)}{settings.API_V1_STR}/a2a-gateway/{slug}"
    return w.served_card(peer.card or {}, url, version or w.V1)


@agent_router.post("/{slug}")
async def a2a_endpoint(slug: str, request: Request, db: AsyncSession = Depends(get_db),
                       user: User = Depends(a2a_agent)):
    if not _origin_ok(request.headers.get("origin")):
        return _error(None, -32600, "Origin not allowed", http=status.HTTP_403_FORBIDDEN)
    try:
        body = await request.json()
    except ValueError:
        return _error(None, -32700, "Parse error", http=status.HTTP_400_BAD_REQUEST)
    if not isinstance(body, dict) or body.get("jsonrpc") != "2.0" or not isinstance(body.get("method"), str):
        return _error(None, -32600, "Invalid Request", http=status.HTTP_400_BAD_REQUEST)
    rid = body.get("id")
    if isinstance(rid, bool) or not isinstance(rid, (str, int)):
        return _error(None, -32600, "Invalid Request: id must be a string or an integer",
                      http=status.HTTP_400_BAD_REQUEST)
    method = body["method"]
    version = w.version_of(request.headers.get("a2a-version") or request.query_params.get("A2A-Version"))
    if version is None:
        return _error(rid, w.VERSION_NOT_SUPPORTED, "Version not supported", {"supported": list(w.SUPPORTED)})
    if method in w.UNSUPPORTED_METHODS:
        code = w.PUSH_NOT_SUPPORTED if "ushNotification" in method else w.UNSUPPORTED_OPERATION
        return _error(rid, code, "Not supported through Provenza")
    canonical = w.canonical_method(method, version)
    if canonical is None:
        return _error(rid, -32601, f"Method not found: {method[:100]}")

    agent = request.state.agent
    gw = A2AGateway(db)
    peer = await gw.reachable(agent, slug) if re.fullmatch(SLUG, slug) else None
    if peer is None:
        raise _not_found()
    try:
        params = (w.send_params_from_wire(body.get("params"), version) if canonical == "SendMessage"
                  else w.task_params_from_wire(body.get("params"), canonical))
    except w.A2AError as exc:
        return _error(rid, exc.code, exc.message, exc.data)
    meta = params.get("metadata") or {}
    chain_id = meta.get(CHAIN_META)
    if chain_id is not None and (isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id < 1):
        return _error(rid, w.INVALID_PARAMS, f"metadata['{CHAIN_META}'] must be a positive integer")
    try:
        await pvp_guard.admit(request, db, user, protocol="a2a", route=canonical,
                              identifiers={"tool_name": tool_name(slug)}, values={"params": params})
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {"code": str(exc.detail)}
        if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            return JSONResponse(status_code=429, headers=exc.headers, content={
                "jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "Rate limited", "data": detail}})
        return _error(rid, w.INVALID_PARAMS, "Refused by the input guard", detail.get("context") or detail)
    try:
        kind, obj = await gw.handle(agent, peer, canonical, params, chain_id)
    except w.A2AError as exc:
        return _error(rid, exc.code, exc.message, exc.data)
    except HTTPException as exc:
        return _error(rid, -32000, "Refused by Provenza", exc.detail if isinstance(exc.detail, (str, dict)) else None)
    return JSONResponse(content={"jsonrpc": "2.0", "id": rid,
                                 "result": w.result_to_wire(canonical, kind, obj, version)})


# ==================================================================== admin

_admin = require_role(UserRole.admin)


def _check_url(v: Optional[str]) -> Optional[str]:
    return None if v is None else validate_url(v)


class A2APeerIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slug: str = Field(pattern=f"^{SLUG}$")
    name: str = Field(min_length=1, max_length=255)
    card_url: str = Field(max_length=500)
    auth_header: str = "Authorization"
    auth_secret: Optional[str] = Field(default=None, min_length=1, max_length=4000)
    timeout_seconds: int = Field(default=60, ge=1, le=300)
    enabled: bool = True

    @field_validator("card_url")
    @classmethod
    def _url(cls, v):
        return _check_url(v)

    @field_validator("auth_header")
    @classmethod
    def _header(cls, v):
        return _check_header(v)


class A2APeerUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    card_url: Optional[str] = Field(default=None, max_length=500)
    auth_header: Optional[str] = None
    auth_secret: Optional[str] = Field(default=None, min_length=1, max_length=4000)
    clear_secret: bool = False
    timeout_seconds: Optional[int] = Field(default=None, ge=1, le=300)
    enabled: Optional[bool] = None

    @field_validator("card_url")
    @classmethod
    def _url(cls, v):
        return _check_url(v)

    @field_validator("auth_header")
    @classmethod
    def _header(cls, v):
        return _check_header(v)


class A2APeerOut(BaseModel):
    id: int
    slug: str
    tool_name: str
    name: str
    card_url: str
    auth_header: str
    has_secret: bool
    enabled: bool
    timeout_seconds: int
    card: Optional[Dict[str, Any]]
    card_digest: Optional[str]
    endpoint_url: Optional[str]
    protocol_version: Optional[str]
    status: str                 # the Tool Registry entry's status ("unsynced" before the first sync)
    pinned_digest: Optional[str]
    served: bool                # reachable for agents that hold "a2a.<slug>"
    last_synced_at: Optional[datetime]
    last_error: Optional[str]
    created_at: datetime


async def _out(db: AsyncSession, p: A2APeer) -> A2APeerOut:
    e = (await db.execute(select(ToolRegistryEntry).where(ToolRegistryEntry.id == p.registry_entry_id))
         ).scalar_one_or_none() if p.registry_entry_id else None
    return A2APeerOut(
        id=p.id, slug=p.slug, tool_name=tool_name(p.slug), name=p.name, card_url=p.card_url,
        auth_header=p.auth_header, has_secret=bool(p.auth_secret_encrypted), enabled=p.enabled,
        timeout_seconds=p.timeout_seconds, card=p.card, card_digest=p.card_digest, endpoint_url=p.endpoint_url,
        protocol_version=p.protocol_version, status=e.status if e else "unsynced",
        pinned_digest=e.pinned_digest if e else None,
        served=bool(e and e.status == "approved" and e.pinned_digest == p.card_digest and p.enabled),
        last_synced_at=p.last_synced_at, last_error=p.last_error, created_at=p.created_at)


async def _get(db: AsyncSession, org_id: int, peer_id: int) -> A2APeer:
    p = (await db.execute(select(A2APeer).where(A2APeer.id == peer_id, A2APeer.org_id == org_id)
                          .execution_options(populate_existing=True))).scalar_one_or_none()
    if p is None:
        raise _not_found()
    return p


@admin_router.get("", response_model=List[A2APeerOut])
async def list_peers(db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    rows = (await db.execute(select(A2APeer).where(A2APeer.org_id == user.org_id).order_by(A2APeer.slug))).scalars()
    return [await _out(db, p) for p in list(rows)]


@admin_router.post("", response_model=A2APeerOut)
async def create_peer(data: A2APeerIn, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    peer = A2APeer(org_id=org_id, slug=data.slug, name=data.name, card_url=data.card_url,
                   auth_header=data.auth_header, timeout_seconds=data.timeout_seconds, enabled=data.enabled,
                   auth_secret_encrypted=encrypt_secret(data.auth_secret, org_id) if data.auth_secret else None,
                   created_by=user_id)
    db.add(peer)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise api_error(status.HTTP_409_CONFLICT, "a2a.slug_taken", slug=data.slug)
    await AuditService(db).log(org_id, user_id, "a2a_peer", peer.id, "created",
                               {"slug": data.slug, "card_url": data.card_url, "has_secret": bool(data.auth_secret)})
    return await _out(db, await _get(db, org_id, peer.id))


@admin_router.patch("/{peer_id}", response_model=A2APeerOut)
async def update_peer(peer_id: int, data: A2APeerUpdate, db: AsyncSession = Depends(get_db),
                      user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    peer = await _get(db, org_id, peer_id)
    changes = data.model_dump(exclude_unset=True, exclude={"auth_secret", "clear_secret"})
    for key, value in changes.items():
        if value is not None:
            setattr(peer, key, value)
    if data.auth_secret:
        peer.auth_secret_encrypted = encrypt_secret(data.auth_secret, org_id)
    elif data.clear_secret:
        peer.auth_secret_encrypted = None
    await db.commit()
    gw_module._live.pop(peer_id, None)
    await AuditService(db).log(org_id, user_id, "a2a_peer", peer_id, "updated",
                               {"fields": sorted(changes), "secret": "set" if data.auth_secret
                                else "cleared" if data.clear_secret else "unchanged"})
    return await _out(db, await _get(db, org_id, peer_id))


@admin_router.delete("/{peer_id}")
async def delete_peer(peer_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    peer = await _get(db, org_id, peer_id)
    slug = peer.slug
    await db.delete(peer)
    await db.commit()
    gw_module._live.pop(peer_id, None)
    await AuditService(db).log(org_id, user_id, "a2a_peer", peer_id, "deleted", {"slug": slug})
    return {"deleted": True}


@admin_router.post("/{peer_id}/sync")
async def sync_peer(peer_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    peer = await _get(db, org_id, peer_id)
    try:
        report = await A2AGateway(db).sync(org_id, peer)
    except UpstreamError as exc:
        raise api_error(status.HTTP_502_BAD_GATEWAY, "a2a.upstream_failed", reason=exc.code)
    await AuditService(db).log(org_id, user_id, "a2a_peer", peer_id, "synced", report)
    return report


@admin_router.post("/{peer_id}/approve")
async def approve_peer(peer_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    """Approve exactly the card seen at the last sync (its digest becomes the pin)."""
    org_id, user_id = user.org_id, user.id
    peer = await _get(db, org_id, peer_id)
    if not peer.card_digest:
        raise api_error(status.HTTP_409_CONFLICT, "a2a.not_synced")
    name, digest = tool_name(peer.slug), peer.card_digest
    entry = await A2AGateway(db).approve(org_id, peer, user_id)
    await AuditService(db).log(org_id, user_id, "tool_registry", entry.id, "approved",
                               {"pattern": name, "pinned_digest": digest, "via": "a2a_gateway"})
    return {"approved": name, "pinned_digest": digest}


@admin_router.post("/{peer_id}/block")
async def block_peer(peer_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    peer = await _get(db, org_id, peer_id)
    entry = (await db.execute(select(ToolRegistryEntry).where(ToolRegistryEntry.id == peer.registry_entry_id))
             ).scalar_one_or_none() if peer.registry_entry_id else None
    if entry is None:
        raise api_error(status.HTTP_409_CONFLICT, "a2a.not_synced")
    entry.status = "blocked"
    name, entry_id = tool_name(peer.slug), entry.id
    await db.commit()
    await AuditService(db).log(org_id, user_id, "tool_registry", entry_id, "blocked",
                               {"pattern": name, "via": "a2a_gateway"})
    return {"blocked": name}
