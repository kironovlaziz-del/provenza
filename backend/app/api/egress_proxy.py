# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Egress proxy (app/pvp/egress_proxy.py): administration, and the API proxies use.

Admins (/api/v1/egress):
  routes        the external APIs and where their credential comes from
  proxies       deployed proxies; a key is shown once at creation
  redemptions   checks proxies redeemed - an open one is a request forwarded
                and never reported back

Proxies, with their key in X-Proxy-Key (/api/v1/egress-proxy):
  GET  /config     the organization's enabled routes (server-held secrets
                   decrypted: the proxy keeps them in memory only)
  POST /check      mediated mode: check for the agent whose key it received
  POST /redeem     reserve a check for the request about to be sent
  POST /complete   record what it did
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, Header, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.api.mcp import _check_header
from app.core.crypto import encrypt_secret
from app.core.database import get_db
from app.core.errors import api_error
from app.core.outbound import validate_url
from app.core.security import generate_api_key, hash_api_key
from app.models.egress_proxy import EgressProxy, EgressRedemption, EgressRoute
from app.models.user import User, UserRole
from app.pvp import egress_proxy as svc
from app.services.audit_service import AuditService

admin_router = APIRouter()
proxy_router = APIRouter()
_admin = require_role(UserRole.admin)

Method = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
SLUG = r"^[a-z0-9][a-z0-9-]{0,39}$"
HEX64 = r"^[0-9a-f]{64}$"
KEY_PREFIX = "pvz_proxy_"
MAX_BODY = 64 * 1024 * 1024


def _prefixes(v: Optional[List[str]]) -> Optional[List[str]]:
    if v is None:
        return v
    if not v or len(v) > 50:
        raise ValueError("1..50 path prefixes")
    for p in v:
        problem = svc.path_problem(p)
        if problem or len(p) > 500:
            raise ValueError(f"path prefix {p!r}: {problem or 'too long'}")
    return v


def _methods(v: Optional[List[str]]) -> Optional[List[str]]:
    if v is not None and (not v or len(set(v)) != len(v)):
        raise ValueError("methods: at least one, no repeats")
    return v


class RouteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slug: str = Field(pattern=SLUG)
    name: str = Field(min_length=1, max_length=255)
    upstream_url: str = Field(max_length=500)
    methods: List[Method] = Field(default_factory=lambda: ["GET", "POST"])
    path_prefixes: List[str] = Field(default_factory=lambda: ["/"])
    credential_source: Literal["server", "local", "none"] = "none"
    auth_header: str = "Authorization"
    secret: Optional[str] = Field(default=None, min_length=1, max_length=8000)
    max_body_bytes: int = Field(default=8 * 1024 * 1024, ge=0, le=MAX_BODY)
    enabled: bool = True

    @field_validator("upstream_url")
    @classmethod
    def _url(cls, v):
        return validate_url(v)

    @field_validator("auth_header")
    @classmethod
    def _hdr(cls, v):
        return _check_header(v)

    @field_validator("path_prefixes")
    @classmethod
    def _pre(cls, v):
        return _prefixes(v)

    @field_validator("methods")
    @classmethod
    def _met(cls, v):
        return _methods(v)


class RouteUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    upstream_url: Optional[str] = Field(default=None, max_length=500)
    methods: Optional[List[Method]] = None
    path_prefixes: Optional[List[str]] = None
    credential_source: Optional[Literal["server", "local", "none"]] = None
    auth_header: Optional[str] = None
    secret: Optional[str] = Field(default=None, min_length=1, max_length=8000)
    clear_secret: bool = False
    max_body_bytes: Optional[int] = Field(default=None, ge=0, le=MAX_BODY)
    enabled: Optional[bool] = None

    @field_validator("upstream_url")
    @classmethod
    def _url(cls, v):
        return None if v is None else validate_url(v)

    @field_validator("auth_header")
    @classmethod
    def _hdr(cls, v):
        return _check_header(v)

    @field_validator("path_prefixes")
    @classmethod
    def _pre(cls, v):
        return _prefixes(v)

    @field_validator("methods")
    @classmethod
    def _met(cls, v):
        return _methods(v)


class RouteOut(BaseModel):
    id: int
    slug: str
    tool_name: str
    name: str
    upstream_url: str
    methods: List[str]
    path_prefixes: List[str]
    credential_source: str
    auth_header: str
    has_secret: bool          # the secret itself is never returned
    max_body_bytes: int
    enabled: bool
    created_at: datetime


def _route_out(r: EgressRoute) -> RouteOut:
    return RouteOut(id=r.id, slug=r.slug, tool_name=svc.PREFIX + r.slug, name=r.name, upstream_url=r.upstream_url,
                    methods=r.methods, path_prefixes=r.path_prefixes, credential_source=r.credential_source,
                    auth_header=r.auth_header, has_secret=bool(r.secret_encrypted), max_body_bytes=r.max_body_bytes,
                    enabled=r.enabled, created_at=r.created_at)


async def _get_route(db: AsyncSession, org_id: int, route_id: int) -> EgressRoute:
    r = (await db.execute(select(EgressRoute).where(EgressRoute.id == route_id, EgressRoute.org_id == org_id)
                          .execution_options(populate_existing=True))).scalar_one_or_none()
    if r is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "egress.route_not_found")
    return r


# ================================================================ admin: routes

@admin_router.get("/routes", response_model=List[RouteOut])
async def list_routes(db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    rows = (await db.execute(select(EgressRoute).where(EgressRoute.org_id == user.org_id)
                             .order_by(EgressRoute.slug))).scalars()
    return [_route_out(r) for r in rows]


@admin_router.post("/routes", response_model=RouteOut)
async def create_route(data: RouteIn, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    if data.secret and data.credential_source != "server":
        raise api_error(422, "egress.secret_needs_server_source")
    route = EgressRoute(org_id=org_id, slug=data.slug, name=data.name, upstream_url=data.upstream_url,
                        methods=list(data.methods), path_prefixes=data.path_prefixes,
                        credential_source=data.credential_source, auth_header=data.auth_header,
                        secret_encrypted=encrypt_secret(data.secret, org_id) if data.secret else None,
                        max_body_bytes=data.max_body_bytes, enabled=data.enabled, created_by=user_id)
    db.add(route)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise api_error(status.HTTP_409_CONFLICT, "egress.slug_taken", slug=data.slug)
    await AuditService(db).log(org_id, user_id, "egress_route", route.id, "created",
                               {"slug": data.slug, "upstream_url": data.upstream_url,
                                "credential_source": data.credential_source, "has_secret": bool(data.secret)})
    return _route_out(await _get_route(db, org_id, route.id))


@admin_router.patch("/routes/{route_id}", response_model=RouteOut)
async def update_route(route_id: int, data: RouteUpdate, db: AsyncSession = Depends(get_db),
                       user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    route = await _get_route(db, org_id, route_id)
    changes = data.model_dump(exclude_unset=True, exclude={"secret", "clear_secret"})
    for key, value in changes.items():
        if value is not None:
            setattr(route, key, list(value) if key == "methods" else value)
    if data.secret:
        if route.credential_source != "server":
            raise api_error(422, "egress.secret_needs_server_source")
        route.secret_encrypted = encrypt_secret(data.secret, org_id)
    elif data.clear_secret or route.credential_source != "server":
        route.secret_encrypted = None   # a secret is kept only for a server-source route
    await db.commit()
    await AuditService(db).log(org_id, user_id, "egress_route", route_id, "updated",
                               {"fields": sorted(changes), "secret": "set" if data.secret
                                else "cleared" if data.clear_secret else "unchanged"})
    return _route_out(await _get_route(db, org_id, route_id))


@admin_router.delete("/routes/{route_id}")
async def delete_route(route_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    route = await _get_route(db, org_id, route_id)
    slug = route.slug
    await db.delete(route)
    await db.commit()
    await AuditService(db).log(org_id, user_id, "egress_route", route_id, "deleted", {"slug": slug})
    return {"deleted": True}


# ================================================================ admin: proxies

class ProxyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=255)


class ProxyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    key_prefix: str
    enabled: bool
    last_seen_at: Optional[datetime]
    revoked_at: Optional[datetime]
    created_at: datetime


class ProxyCreated(ProxyOut):
    key: str   # shown once


@admin_router.get("/proxies", response_model=List[ProxyOut])
async def list_proxies(db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    return list((await db.execute(select(EgressProxy).where(EgressProxy.org_id == user.org_id)
                                  .order_by(EgressProxy.id))).scalars())


@admin_router.post("/proxies", response_model=ProxyCreated)
async def create_proxy(data: ProxyIn, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    key = KEY_PREFIX + generate_api_key()
    proxy = EgressProxy(org_id=org_id, name=data.name, key_hash=hash_api_key(key), key_prefix=key[:16],
                        created_by=user_id)
    db.add(proxy)
    await db.flush()
    proxy_id = proxy.id
    await AuditService(db).log(org_id, user_id, "egress_proxy", proxy_id, "created", {"name": data.name})
    proxy = await db.get(EgressProxy, proxy_id)
    return ProxyCreated(**ProxyOut.model_validate(proxy).model_dump(), key=key)


@admin_router.post("/proxies/{proxy_id}/revoke", response_model=ProxyOut)
async def revoke_proxy(proxy_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    proxy = (await db.execute(select(EgressProxy).where(EgressProxy.id == proxy_id, EgressProxy.org_id == org_id))
             ).scalar_one_or_none()
    if proxy is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "egress.proxy_not_found")
    proxy.enabled, proxy.revoked_at = False, datetime.now(timezone.utc)
    await db.commit()
    await AuditService(db).log(org_id, user_id, "egress_proxy", proxy_id, "revoked", {})
    return await db.get(EgressProxy, proxy_id)


class RedemptionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    proxy_id: int
    route_id: Optional[int]
    agent_id: int
    descriptor: Dict[str, Any]
    reserved_at: datetime
    completed_at: Optional[datetime]
    action_id: Optional[int]


@admin_router.get("/redemptions", response_model=List[RedemptionOut])
async def list_redemptions(open: bool = False, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    """open=true: forwarded but never reported back (a proxy that crashed, or worse)."""
    q = select(EgressRedemption).where(EgressRedemption.org_id == user.org_id)
    if open:
        q = q.where(EgressRedemption.completed_at.is_(None))
    return list((await db.execute(q.order_by(EgressRedemption.id.desc()).limit(500))).scalars())


# ================================================================ the proxies' API

async def current_proxy(x_proxy_key: Optional[str] = Header(None, alias="X-Proxy-Key"),
                        db: AsyncSession = Depends(get_db)) -> EgressProxy:
    if not x_proxy_key:
        raise api_error(status.HTTP_401_UNAUTHORIZED, "egress.proxy_key_required")
    proxy = (await db.execute(select(EgressProxy).where(EgressProxy.key_hash == hash_api_key(x_proxy_key.strip())))
             ).scalar_one_or_none()
    if proxy is None or not proxy.enabled or proxy.revoked_at is not None:
        raise api_error(status.HTTP_401_UNAUTHORIZED, "egress.invalid_proxy_key")
    now = datetime.now(timezone.utc)
    if proxy.last_seen_at is None or (now - proxy.last_seen_at).total_seconds() > 60:
        proxy.last_seen_at = now
        await db.commit()
    return proxy


@proxy_router.get("/config")
async def proxy_config(db: AsyncSession = Depends(get_db), proxy: EgressProxy = Depends(current_proxy)):
    routes = (await db.execute(select(EgressRoute).where(EgressRoute.org_id == proxy.org_id,
                                                         EgressRoute.enabled.is_(True))
                               .order_by(EgressRoute.slug))).scalars()
    return {"routes": [svc.route_config(r) for r in routes], "refresh_seconds": 60}


class RedeemIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check_id: str = Field(min_length=16, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    route: str = Field(pattern=SLUG)
    method: Method
    path: str = Field(min_length=1, max_length=2000)
    query_sha256: Optional[str] = Field(default=None, pattern=HEX64)
    body_sha256: Optional[str] = Field(default=None, pattern=HEX64)
    body_bytes: int = Field(ge=0, le=MAX_BODY)


class ProxyCheckIn(BaseModel):
    """A request the proxy is about to forward, for the agent whose key it
    received (mediated mode). The proxy cannot sign as the agent; it is the
    witness, as the gateways are."""
    model_config = ConfigDict(extra="forbid")
    route: str = Field(pattern=SLUG)
    method: Method
    path: str = Field(min_length=1, max_length=2000)
    query_sha256: Optional[str] = Field(default=None, pattern=HEX64)
    body_sha256: Optional[str] = Field(default=None, pattern=HEX64)
    body_bytes: int = Field(ge=0, le=MAX_BODY)


@proxy_router.post("/check")
async def proxy_check(data: ProxyCheckIn, db: AsyncSession = Depends(get_db),
                      proxy: EgressProxy = Depends(current_proxy),
                      x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key")):
    """Mediated mode: check on behalf of the agent that sent its key to the
    proxy. Agents calling Provenza themselves use /agents/actions/check, signed."""
    from app.pvp.model import PVPActionRequest
    from app.pvp.orchestrator import PVPOrchestrator
    from app.services.agent_identity import agent_by_key

    agent = await agent_by_key(db, x_agent_key) if x_agent_key else None
    if agent is None or agent.org_id != proxy.org_id:
        raise api_error(status.HTTP_401_UNAUTHORIZED, "egress.agent_key_invalid")
    if agent.status != "active":
        raise api_error(status.HTTP_403_FORBIDDEN, "egress.agent_inactive")
    desc = svc.descriptor(data.route, data.method, data.path, data.query_sha256, data.body_sha256, data.body_bytes)
    req = PVPActionRequest(agent_id=agent.id, action_type=svc.ACTION_TYPE, tool_name=svc.PREFIX + data.route,
                           input=desc)
    chk = await PVPOrchestrator(db).check(proxy.org_id, req)
    return {"decision": chk.decision, "reason": chk.reason, "check_id": chk.check_id}


@proxy_router.post("/redeem")
async def proxy_redeem(data: RedeemIn, db: AsyncSession = Depends(get_db),
                       proxy: EgressProxy = Depends(current_proxy)):
    desc = svc.descriptor(data.route, data.method, data.path, data.query_sha256, data.body_sha256, data.body_bytes)
    return await svc.redeem(db, proxy, data.check_id, desc)


class CompleteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check_id: str = Field(min_length=16, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    status: int = Field(ge=0, le=599)    # 0: no response (the upstream failed)
    response_sha256: Optional[str] = Field(default=None, pattern=HEX64)
    response_bytes: Optional[int] = Field(default=None, ge=0)
    error: Optional[str] = Field(default=None, pattern=r"^[a-z0-9_.]{1,100}$")
    duration_ms: Optional[int] = Field(default=None, ge=0)


@proxy_router.post("/complete")
async def proxy_complete(data: CompleteIn, db: AsyncSession = Depends(get_db),
                         proxy: EgressProxy = Depends(current_proxy)):
    output = {"status": data.status, "response_sha256": data.response_sha256,
              "response_bytes": data.response_bytes}
    if data.error:
        output["error"] = data.error
    return await svc.complete(db, proxy, data.check_id, output, data.duration_ms)

