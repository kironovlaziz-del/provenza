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
  credentials   upstreams' credentials, sealed in the browser to each proxy's
                key (app/pvp/sealed.py, app/services/credentials.py): this
                server stores them and cannot read them

Proxies, with their key in X-Proxy-Key (/api/v1/egress-proxy):
  POST /key          its own signing key and the encryption key it signs
  GET  /config       the organization's enabled routes (no credentials)
  GET  /credentials  the envelopes sealed to it
  POST /check      mediated mode: check for the agent whose key it received
  POST /redeem     reserve a check for the request about to be sent
  POST /complete   record what it did
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.api.http_tools import CallIn as HttpToolCallIn
from app.api.mcp import _check_header
from app.core.database import get_db
from app.core.errors import api_error
from app.core.outbound import validate_url
from app.core.security import generate_api_key, hash_api_key
from app.models.egress_proxy import EgressProxy, EgressRedemption, EgressRoute
from app.models.user import User, UserRole
from app.pvp import egress_proxy as svc
from app.pvp import enforcement
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
    # sealed: entered in the browser and sealed to the proxies (PUT /egress/credentials/route/{id});
    # local: in the proxies' configuration; "server" is the old name of "sealed"
    credential_source: Literal["sealed", "server", "local", "none"] = "none"
    auth_header: str = "Authorization"
    secret: Optional[str] = Field(default=None, max_length=8000)   # refused: never sent in clear text
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
    credential_source: Optional[Literal["sealed", "server", "local", "none"]] = None
    auth_header: Optional[str] = None
    secret: Optional[str] = Field(default=None, max_length=8000)   # refused: never sent in clear text
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
    has_secret: bool          # a credential is configured (it is never readable here)
    credential: Dict[str, Any]   # where it lives (app/services/credentials.py)
    max_body_bytes: int
    enabled: bool
    created_at: datetime


async def _route_out(db: AsyncSession, r: EgressRoute) -> RouteOut:
    from app.services import credentials

    cred = await credentials.state(db, r.org_id, "route", r)
    return RouteOut(id=r.id, slug=r.slug, tool_name=svc.PREFIX + r.slug, name=r.name, upstream_url=r.upstream_url,
                    methods=r.methods, path_prefixes=r.path_prefixes, credential_source=r.credential_source,
                    auth_header=r.auth_header, has_secret=r.credential_source != "none", credential=cred,
                    max_body_bytes=r.max_body_bytes, enabled=r.enabled, created_at=r.created_at)


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
                             .order_by(EgressRoute.slug))).scalars().all()
    return [await _route_out(db, r) for r in rows]


@admin_router.post("/routes", response_model=RouteOut)
async def create_route(data: RouteIn, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    from app.services import credentials

    org_id, user_id = user.org_id, user.id
    if data.secret is not None:
        raise credentials.plaintext_refused()
    source = "sealed" if data.credential_source == "server" else data.credential_source
    route = EgressRoute(org_id=org_id, slug=data.slug, name=data.name, upstream_url=data.upstream_url,
                        methods=list(data.methods), path_prefixes=data.path_prefixes,
                        credential_source=source, auth_header=data.auth_header,
                        max_body_bytes=data.max_body_bytes, enabled=data.enabled, created_by=user_id)
    db.add(route)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise api_error(status.HTTP_409_CONFLICT, "egress.slug_taken", slug=data.slug)
    await AuditService(db).log(org_id, user_id, "egress_route", route.id, "created",
                               {"slug": data.slug, "upstream_url": data.upstream_url,
                                "credential_source": source})
    return await _route_out(db, await _get_route(db, org_id, route.id))


@admin_router.patch("/routes/{route_id}", response_model=RouteOut)
async def update_route(route_id: int, data: RouteUpdate, db: AsyncSession = Depends(get_db),
                       user: User = Depends(_admin)):
    from app.services import credentials

    org_id, user_id = user.org_id, user.id
    if data.secret is not None:
        raise credentials.plaintext_refused()
    route = await _get_route(db, org_id, route_id)
    changes = data.model_dump(exclude_unset=True, exclude={"secret", "clear_secret", "credential_source"})
    for key, value in changes.items():
        if value is not None:
            setattr(route, key, list(value) if key == "methods" else value)
    await db.commit()
    source = data.credential_source
    if data.clear_secret:
        source = "none"
    if source is not None:
        source = "sealed" if source == "server" else source
        if source == "sealed":
            route.credential_source = source   # the envelopes follow (PUT /egress/credentials/route/{id})
            await db.commit()
        else:
            await credentials.set_source(db, org_id, "route", route_id, source)
        changes["credential_source"] = source
    await AuditService(db).log(org_id, user_id, "egress_route", route_id, "updated", {"fields": sorted(changes)})
    return await _route_out(db, await _get_route(db, org_id, route_id))


@admin_router.delete("/routes/{route_id}")
async def delete_route(route_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    route = await _get_route(db, org_id, route_id)
    slug = route.slug
    from app.services import credentials

    await credentials.forget(db, "route", route_id)
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
    # the proxy's own signing key (generated on its host): what its receipts are checked with
    public_key: Optional[str] = None
    # its X25519 key, signed by the signing key: what credentials are sealed to (app/pvp/sealed.py)
    encryption_key: Optional[str] = None
    encryption_key_signature: Optional[str] = None

    @computed_field
    @property
    def key_fingerprint(self) -> Optional[str]:
        from app.core.agent_signing import key_fingerprint

        return key_fingerprint(self.public_key) if self.public_key else None

    @computed_field
    @property
    def encryption_key_fingerprint(self) -> Optional[str]:
        from app.core.agent_signing import key_fingerprint

        return key_fingerprint(self.encryption_key) if self.encryption_key else None


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


# ---------------------------------------------------------------------- the local kill switch (admin)

@admin_router.get("/proxies/{proxy_id}/kill-switch")
async def proxy_kill_switch(proxy_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    """The proxy's local kill switch and its reconciliation report (null: not engaged)."""
    from app.pvp import proxy_offline

    return {"kill_switch": await proxy_offline.view(db, proxy_id, user)}


class LiftChallengeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    accept: List[str] = Field(default_factory=list, max_length=500)


class LiftSignIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    statement: Dict[str, Any]
    assertion: Dict[str, Any]


@admin_router.post("/proxies/{proxy_id}/kill-switch/challenge")
async def proxy_kill_switch_challenge(proxy_id: int, data: LiftChallengeIn, db: AsyncSession = Depends(get_db),
                                      user: User = Depends(_admin)):
    """The statement an administrator's passkey signs to lift it: the report's
    hash and the differences accepted (every unsigned one)."""
    from app.pvp import proxy_offline

    return await proxy_offline.lift_challenge(db, user, proxy_id, data.accept)


@admin_router.post("/proxies/{proxy_id}/kill-switch/sign")
async def proxy_kill_switch_sign(proxy_id: int, data: LiftSignIn, db: AsyncSession = Depends(get_db),
                                 user: User = Depends(_admin)):
    from app.pvp import proxy_offline

    org_id, user_id = user.org_id, user.id
    out = await proxy_offline.lift_sign(db, user, proxy_id, data.statement, data.assertion)
    await AuditService(db).log(org_id, user_id, "egress_proxy", proxy_id, "kill_switch_signed",
                               {"report_sha256": (data.statement or {}).get("report_sha256"),
                                "accepted": len((data.statement or {}).get("accept") or [])})
    return {"kill_switch": out}


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


# ================================================================ admin: credentials

class ProxyKeyOut(BaseModel):
    """What the browser seals to. It checks the signature itself
    (frontend/lib/sealing.ts) and shows both fingerprints, to compare with
    what the proxy prints on its own host."""
    proxy_id: int
    org_id: int               # with proxy_id and the object: the context an envelope is sealed for
    name: str
    public_key: str
    key_fingerprint: str
    encryption_key: str
    encryption_key_signature: str
    encryption_key_fingerprint: str


@admin_router.get("/proxy-keys", response_model=List[ProxyKeyOut])
async def proxy_keys(db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    from app.core.agent_signing import key_fingerprint
    from app.services import credentials

    return [ProxyKeyOut(proxy_id=p.id, org_id=p.org_id, name=p.name, public_key=p.public_key, key_fingerprint=key_fingerprint(p.public_key),
                        encryption_key=p.encryption_key, encryption_key_signature=p.encryption_key_signature,
                        encryption_key_fingerprint=key_fingerprint(p.encryption_key))
            for p in await credentials.proxies_with_keys(db, user.org_id) if p.public_key]


CredObject = Literal["route", "provider", "mcp_server", "a2a_peer", "http_tool"]


class SealedIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    envelopes: List[Dict[str, Any]] = Field(min_length=1, max_length=100)
    # the administrator's session-key signature over them (POST .../statement)
    statement: Dict[str, Any]
    signature: str = Field(max_length=200)


class SealStatementIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # None: the envelopes already stored (a countersignature)
    envelopes: Optional[List[Dict[str, Any]]] = Field(default=None, min_length=1, max_length=100)


class CountersignIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    statement: Dict[str, Any]
    signature: str = Field(max_length=200)


class SourceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Literal["local", "none"]


@admin_router.get("/credentials/legacy")
async def legacy_credentials(db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    """Credentials this server still holds from before sealing: unused until sealed."""
    from app.services import credentials

    return {"count": await credentials.legacy_count(db, user.org_id),
            "proxies_with_keys": len(await credentials.proxies_with_keys(db, user.org_id))}


@admin_router.post("/credentials/seal-legacy")
async def seal_legacy_credentials(db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    """Seal them once to every proxy with a key, and erase them here."""
    from app.services import credentials

    org_id, user_id = user.org_id, user.id
    out = await credentials.seal_legacy(db, org_id, user_id)
    await AuditService(db).log(org_id, user_id, "credential", None, "legacy_sealed",
                               {"sealed": out["sealed"], "proxies": out["proxies"], "failed": out["failed"]})
    return out


@admin_router.get("/credentials/{obj}/{object_id}")
async def credential_state(obj: CredObject, object_id: int, db: AsyncSession = Depends(get_db),
                           user: User = Depends(_admin)):
    from app.services import credentials

    return await credentials.state(db, user.org_id, obj, await credentials.target(db, user.org_id, obj, object_id))


@admin_router.put("/credentials/{obj}/{object_id}")
async def store_credential(obj: CredObject, object_id: int, data: SealedIn, db: AsyncSession = Depends(get_db),
                           user: User = Depends(_admin)):
    """Envelopes sealed in the browser, one per proxy: they replace the
    object's credential (and erase one this server held before)."""
    from app.services import credentials

    org_id, user_id = user.org_id, user.id
    out = await credentials.store(db, user, getattr(user, "_signing_session", None), obj, object_id,
                                  data.envelopes, data.statement, data.signature)
    await AuditService(db).log(org_id, user_id, "credential", object_id, "sealed",
                               {"object": obj, "proxies": out["sealed_for"]})
    return out


@admin_router.post("/credentials/{obj}/{object_id}/statement")
async def credential_statement(obj: CredObject, object_id: int, data: SealStatementIn,
                               db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    """What the administrator signs with this session's key over the
    envelopes (docs/pvp/edge.md, section 4.1): those about to be stored, or
    the ones stored (a countersignature, for envelopes sealed here)."""
    from app.services import credentials

    return {"statement": await credentials.statement(db, user, getattr(user, "_signing_session", None), obj,
                                                     object_id, data.envelopes)}


@admin_router.post("/credentials/{obj}/{object_id}/countersign")
async def countersign_credential(obj: CredObject, object_id: int, data: CountersignIn,
                                 db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    """An administrator vouches for the envelopes stored for an object."""
    from app.services import credentials

    org_id, user_id = user.org_id, user.id
    out = await credentials.countersign(db, user, getattr(user, "_signing_session", None), obj, object_id,
                                        data.statement, data.signature)
    await AuditService(db).log(org_id, user_id, "credential", object_id, "countersigned",
                               {"object": obj, "proxies": out["sealed_for"]})
    return out


@admin_router.post("/credentials/{obj}/{object_id}/source")
async def credential_source(obj: CredObject, object_id: int, data: SourceIn, db: AsyncSession = Depends(get_db),
                            user: User = Depends(_admin)):
    """"local": the proxies' own configuration holds it; "none": no credential."""
    from app.services import credentials

    org_id, user_id = user.org_id, user.id
    out = await credentials.set_source(db, org_id, obj, object_id, data.source)
    await AuditService(db).log(org_id, user_id, "credential", object_id, "source_set",
                               {"object": obj, "source": data.source})
    return out


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


class KeyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    public_key: str = Field(min_length=40, max_length=60)
    # the X25519 key credentials are sealed to, signed by public_key (app/pvp/sealed.key_statement)
    encryption_key: Optional[str] = Field(default=None, min_length=40, max_length=60)
    encryption_key_signature: Optional[str] = Field(default=None, min_length=80, max_length=100)


@proxy_router.post("/key")
async def register_proxy_key(data: KeyIn, db: AsyncSession = Depends(get_db),
                             proxy: EgressProxy = Depends(current_proxy)):
    """The proxy's own Ed25519 key, generated on its host: registered once.
    A different key later is refused - a new key is a new proxy (Egress ->
    Proxies), so a stolen proxy key cannot swap the key receipts are signed with."""
    from app.core.agent_signing import key_fingerprint, normalize_public_key

    try:
        key = normalize_public_key(data.public_key)
    except ValueError:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "egress.bad_proxy_public_key")
    if proxy.public_key and proxy.public_key != key:
        raise api_error(status.HTTP_409_CONFLICT, "egress.proxy_key_changed")
    enc = None
    if data.encryption_key is not None or data.encryption_key_signature is not None:
        import base64

        from app.core.agent_signing import verify_payload
        from app.pvp import sealed

        try:
            raw = base64.b64decode(data.encryption_key or "", validate=True)
        except ValueError:
            raw = b""
        if len(raw) != 32 or not data.encryption_key_signature or not verify_payload(
                sealed.key_statement(data.encryption_key), data.encryption_key_signature, key):
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "egress.bad_proxy_encryption_key")
        enc = base64.b64encode(raw).decode("ascii")
        if proxy.encryption_key and proxy.encryption_key != enc:
            # sealed credentials stay addressed to the first key: a new key is a new proxy
            raise api_error(status.HTTP_409_CONFLICT, "egress.proxy_key_changed")
    org_id, proxy_id = proxy.org_id, proxy.id
    events = []
    if not proxy.public_key:
        proxy.public_key, proxy.key_registered_at = key, datetime.now(timezone.utc)
        events.append(("key_registered", {"key_fingerprint": key_fingerprint(key)}))
    if enc and not proxy.encryption_key:
        proxy.encryption_key, proxy.encryption_key_signature = enc, data.encryption_key_signature
        events.append(("encryption_key_registered", {"encryption_key_fingerprint": key_fingerprint(enc)}))
    if events:
        await db.commit()
        for action, details in events:
            await AuditService(db).log(org_id, None, "egress_proxy", proxy_id, action, details)
    # org_id and proxy_id: what the proxy expects in the context of an envelope sealed to it
    return {"proxy_id": proxy_id, "org_id": org_id, "key_fingerprint": key_fingerprint(key),
            "encryption_key_fingerprint": key_fingerprint(enc) if enc else None}


@proxy_router.get("/credentials")
async def proxy_credentials(db: AsyncSession = Depends(get_db), proxy: EgressProxy = Depends(current_proxy)):
    """The envelopes sealed to this proxy (app/pvp/sealed.py). The proxy opens
    each one only for the object its context names."""
    from app.services import credentials

    return {"credentials": await credentials.for_proxy(db, proxy)}


@proxy_router.get("/policy-release")
async def proxy_policy_release(after: int = 0, db: AsyncSession = Depends(get_db),
                               proxy: EgressProxy = Depends(current_proxy)):
    """The signed policy in force and the releases that lead to it from
    release `after` (the last one the proxy verified): each one as signed,
    with the manifest that governs it. The proxy checks every step itself
    (proxy/internal/trust); this server is only the courier."""
    from app.services import policy_release as pr

    return await pr.chain_after(db, proxy.org_id, after)


class CheckInfoIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check_id: str = Field(min_length=16, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


@proxy_router.post("/check-info")
async def proxy_check_info(data: CheckInfoIn, request: Request, db: AsyncSession = Depends(get_db),
                           proxy: EgressProxy = Depends(current_proxy)):
    """What a check an agent brings (SDK mode) was issued for - so the proxy
    can judge the same action under the signed policy before redeeming it."""
    await enforcement.proxy_gate(db, proxy, request)
    return await svc.check_info(db, proxy, data.check_id)


@proxy_router.get("/config")
async def proxy_config(db: AsyncSession = Depends(get_db), proxy: EgressProxy = Depends(current_proxy)):
    from app.models.a2a_gateway import A2APeer
    from app.models.mcp import MCPServer

    routes = (await db.execute(select(EgressRoute).where(EgressRoute.org_id == proxy.org_id,
                                                         EgressRoute.enabled.is_(True))
                               .order_by(EgressRoute.slug))).scalars()
    # the MCP servers and A2A peers whose credential the proxies hold: they are reached only through them -
    # in enforce mode all of them (this server's gateways execute nothing then)
    every = await enforcement.enforced(db, proxy.org_id)
    servers = (await db.execute(select(MCPServer).where(
        MCPServer.org_id == proxy.org_id, MCPServer.enabled.is_(True),
        *(() if every else (MCPServer.credential_source != "none",))).order_by(MCPServer.slug))).scalars()
    peers = (await db.execute(select(A2APeer).where(
        A2APeer.org_id == proxy.org_id, A2APeer.enabled.is_(True),
        *(() if every else (A2APeer.credential_source != "none",))).order_by(A2APeer.slug))).scalars()
    return {"routes": [svc.route_config(r) for r in routes],
            "mcp_servers": [{"id": s.id, "slug": s.slug, "url": s.url, "protocol": s.detected_version or s.protocol,
                             "auth_header": s.auth_header, "credential_source": s.credential_source,
                             "timeout_seconds": s.timeout_seconds} for s in servers],
            "a2a_peers": [{"id": p.id, "slug": p.slug, "card_url": p.card_url, "auth_header": p.auth_header,
                           "credential_source": p.credential_source, "timeout_seconds": p.timeout_seconds}
                          for p in peers],
            "refresh_seconds": 60}


class Receipt(BaseModel):
    """The proxy's signed receipt (app/pvp/witness.py)."""
    model_config = ConfigDict(extra="forbid")
    statement: Dict[str, Any]
    signature: str = Field(max_length=200)


class Enforcement(BaseModel):
    """The proxy's own verdict under the signed policy: a refusal it made."""
    model_config = ConfigDict(extra="forbid")
    decision: Literal["denied", "pending_approval"]
    reason: str = Field(max_length=1000)
    receipt: Optional[Receipt] = None


class RedeemIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check_id: str = Field(min_length=16, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    route: str = Field(pattern=SLUG)
    method: Method
    path: str = Field(min_length=1, max_length=2000)
    query_sha256: Optional[str] = Field(default=None, pattern=HEX64)
    body_sha256: Optional[str] = Field(default=None, pattern=HEX64)
    body_bytes: int = Field(ge=0, le=MAX_BODY)
    enforcement: Optional[Enforcement] = None


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
async def proxy_check(data: ProxyCheckIn, request: Request, db: AsyncSession = Depends(get_db),
                      proxy: EgressProxy = Depends(current_proxy),
                      x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key")):
    """Mediated mode: check on behalf of the agent that sent its key to the
    proxy. Agents calling Provenza themselves use /agents/actions/check, signed.
    With the agent's signed request (X-Provenza-Request: the proxy in agent
    mode signs for it) the check is the agent's own - verified here as well;
    enforce mode takes no other."""
    from app.pvp import proxy_actions
    from app.pvp.model import PVPActionRequest
    from app.pvp.orchestrator import PVPOrchestrator

    enforced = await enforcement.proxy_gate(db, proxy, request)
    agent = await proxy_actions.agent_for(db, proxy, x_agent_key)
    desc = svc.descriptor(data.route, data.method, data.path, data.query_sha256, data.body_sha256, data.body_bytes)
    header = request.headers.get(enforcement.REQUEST_HEADER)
    sr = enforcement.signed_request(header)
    if sr is None and (header or enforced):
        raise api_error(status.HTTP_401_UNAUTHORIZED, "enforcement.agent_signature_required")
    signed = {}
    if sr is not None:
        p = sr["payload"]
        if p.get("agent_id") != agent.id:
            raise api_error(status.HTTP_403_FORBIDDEN, "enforcement.not_the_signed_request")
        signed = {"chain_id": p.get("chain_id"), "nonce": p.get("nonce"), "issued_at": p.get("issued_at"),
                  "signature": sr["signature"], "pq_signature": sr.get("pq_signature")}
    try:
        req = PVPActionRequest(agent_id=agent.id, action_type=svc.ACTION_TYPE, tool_name=svc.PREFIX + data.route,
                               input=desc, **signed)
    except ValueError:
        raise api_error(status.HTTP_401_UNAUTHORIZED, "enforcement.agent_signature_required")
    if sr is not None and req.signed_payload() != sr["payload"]:
        raise api_error(status.HTTP_403_FORBIDDEN, "enforcement.not_the_signed_request")
    from app.pvp import approvals

    chk = await PVPOrchestrator(db).check(proxy.org_id, req, require_signature=sr is not None,
                                          permit=not enforced)
    return {"decision": chk.decision, "reason": chk.reason, "check_id": chk.check_id, "agent_id": req.agent_id,
            "chain_id": None, "approval": await approvals.proof_for_check(db, proxy.org_id, chk.check_id)}


@proxy_router.post("/http-tools/plan")
async def proxy_http_tool_plan(data: HttpToolCallIn, request: Request, db: AsyncSession = Depends(get_db),
                               proxy: EgressProxy = Depends(current_proxy),
                               x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key")):
    """An HTTP tool call the agent sent to the proxy (/_tools/call, the body of
    /http-tools/call): judged as the HTTP tool gateway judges it; the proxy
    sends it with the credential sealed to it and completes it
    (app/pvp/proxy_actions.py)."""
    from app.pvp import guard as pvp_guard
    from app.pvp import proxy_actions
    from app.pvp.http_tools import HttpToolGateway
    from app.pvp.model import PVPActionRequest
    from app.services.agent_identity import _accountable_user

    await enforcement.proxy_gate(db, proxy, request)
    agent = await proxy_actions.agent_for(db, proxy, x_agent_key)
    if data.agent_id != agent.id:
        raise api_error(status.HTTP_403_FORBIDDEN, "http_tool.not_this_agent")
    user = await _accountable_user(db, agent)
    if user is None:
        raise api_error(status.HTTP_403_FORBIDDEN, "agent_identity.no_accountable_user")
    request.state.agent = agent
    await pvp_guard.admit(request, db, user, protocol="rest", route="http_tool.call",
                          identifiers={"tool_name": data.tool_name}, values={"input": data.input})
    try:
        req = PVPActionRequest(agent_id=data.agent_id, chain_id=data.chain_id, action_type="tool_call",
                               tool_name=data.tool_name, input=data.input, nonce=data.nonce,
                               issued_at=data.issued_at, signature=data.signature, pq_signature=data.pq_signature)
    except ValueError as exc:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "pvp.input_rejected", reason=str(exc)[:300])
    return await HttpToolGateway(db).plan(agent, req, proxy)


class LlmPlanIn(BaseModel):
    """A chat completion the agent sent to the proxy (/_llm/v1/chat/completions):
    what the LLM gateway records of it - never the messages."""
    model_config = ConfigDict(extra="forbid")
    model: str = Field(min_length=1, max_length=200)
    messages: int = Field(ge=1, le=10000)
    messages_sha256: str = Field(pattern=HEX64)
    max_tokens: Optional[int] = Field(default=None, ge=1, le=1_000_000)
    stream: bool = False
    chain_id: Optional[int] = Field(default=None, ge=1, le=2**31 - 1)


@proxy_router.post("/llm/plan")
async def proxy_llm_plan(data: LlmPlanIn, request: Request, db: AsyncSession = Depends(get_db),
                         proxy: EgressProxy = Depends(current_proxy),
                         x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key")):
    """Decided as the LLM gateway decides (app/services/gateway_service.py);
    a refusal comes back as the gateway's OpenAI error with its HTTP status,
    for the proxy to pass on."""
    from app.pvp import proxy_actions
    from app.services.gateway_service import GatewayError, GatewayService

    agent = await proxy_actions.agent_for(db, proxy, x_agent_key)
    await enforcement.verify_agent_request(db, proxy, agent, request, "llm")
    try:
        return await GatewayService(db).plan(agent, data.model_dump(), data.chain_id, proxy)
    except GatewayError as err:
        return {"decision": "refused", "status": err.http_status, **err.body()}


class McpSyncIn(BaseModel):
    """What a proxy found on an MCP server whose credential is sealed to it."""
    model_config = ConfigDict(extra="forbid")
    server_id: int
    tools: Optional[List[Dict[str, Any]]] = Field(default=None, max_length=1000)
    server_info: Optional[Dict[str, Any]] = None
    detected_version: Optional[str] = Field(default=None, max_length=20)
    error: Optional[str] = Field(default=None, max_length=300)


@proxy_router.post("/mcp/sync")
async def proxy_mcp_sync(data: McpSyncIn, db: AsyncSession = Depends(get_db),
                         proxy: EgressProxy = Depends(current_proxy)):
    """The proxy synced the server (this server cannot reach it): the same
    as the admin's sync - new tools pending, a changed one drifted."""
    from app.models.mcp import MCPServer
    from app.pvp import mcp_client
    from app.pvp.mcp_gateway import MCPGateway

    server = (await db.execute(select(MCPServer).where(MCPServer.id == data.server_id,
                                                       MCPServer.org_id == proxy.org_id))).scalar_one_or_none()
    if server is None or (server.credential_source or "none") == "none" and \
            not await enforcement.enforced(db, proxy.org_id):
        raise api_error(status.HTTP_404_NOT_FOUND, "mcp.server_not_found")
    if data.error or data.tools is None:
        server.last_error = f"via egress proxy #{proxy.id}: {(data.error or 'no tools')[:250]}"
        await db.commit()
        return {"synced": False}
    if data.detected_version in mcp_client.SUPPORTED:
        server.detected_version = data.detected_version
    report = await MCPGateway(db).apply_sync(proxy.org_id, server, data.tools, data.server_info)
    return {"synced": True, **{k: len(v) for k, v in report.items()}}


class McpPlanIn(BaseModel):
    """A tools/call the agent sent to the proxy (/_mcp) for a server whose
    credential is sealed to it, with the live definition's digest the proxy
    computed from the upstream (or why it could not)."""
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    arguments: Dict[str, Any] = Field(default_factory=dict)
    chain_id: Optional[int] = Field(default=None, ge=1, le=2**31 - 1)
    live_digest: Optional[str] = Field(default=None, pattern=HEX64)
    live_error: Optional[str] = Field(default=None, max_length=100)


@proxy_router.post("/mcp/plan")
async def proxy_mcp_plan(data: McpPlanIn, request: Request, db: AsyncSession = Depends(get_db),
                         proxy: EgressProxy = Depends(current_proxy),
                         x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key")):
    from app.pvp import guard as pvp_guard
    from app.pvp import proxy_actions
    from app.pvp.mcp_gateway import MCPGateway, MCPGatewayError
    from app.services.agent_identity import _accountable_user

    agent = await proxy_actions.agent_for(db, proxy, x_agent_key)
    await enforcement.verify_agent_request(db, proxy, agent, request, "mcp")
    user = await _accountable_user(db, agent)
    if user is None:
        raise api_error(status.HTTP_403_FORBIDDEN, "agent_identity.no_accountable_user")
    request.state.agent = agent
    await pvp_guard.admit(request, db, user, protocol="mcp", route="tools/call",
                          identifiers={"tool_name": data.name}, values={"arguments": data.arguments})
    try:
        return await MCPGateway(db).plan(agent, data.name, data.arguments, data.chain_id, data.live_digest,
                                         data.live_error, proxy)
    except MCPGatewayError as exc:
        return {"decision": "error", "error": {"code": exc.code, "message": exc.message}}


class A2ASyncIn(BaseModel):
    """The card a proxy fetched from a peer whose credential is sealed to it."""
    model_config = ConfigDict(extra="forbid")
    peer_id: int
    card: Optional[Dict[str, Any]] = None
    error: Optional[str] = Field(default=None, max_length=300)


@proxy_router.post("/a2a/sync")
async def proxy_a2a_sync(data: A2ASyncIn, db: AsyncSession = Depends(get_db),
                         proxy: EgressProxy = Depends(current_proxy)):
    """As the admin's sync: a new peer pending, a changed card drifted."""
    from app.models.a2a_gateway import A2APeer
    from app.pvp import a2a_wire as w
    from app.pvp import sealed
    from app.pvp.a2a_gateway import A2AGateway
    from app.pvp.upstream_http import UpstreamError

    peer = (await db.execute(select(A2APeer).where(A2APeer.id == data.peer_id,
                                                   A2APeer.org_id == proxy.org_id))).scalar_one_or_none()
    if peer is None or (peer.credential_source or "none") == "none" and \
            not await enforcement.enforced(db, proxy.org_id):
        raise api_error(status.HTTP_404_NOT_FOUND, "a2a.peer_not_found")
    if data.error or data.card is None:
        peer.last_error = f"via egress proxy #{proxy.id}: {(data.error or 'no card')[:250]}"
        await db.commit()
        return {"synced": False}
    try:
        report = await A2AGateway(db).apply_card(proxy.org_id, peer, w.pinned_card(data.card))
    except UpstreamError as exc:
        return {"synced": False, "error": exc.code}
    peer = await db.get(A2APeer, data.peer_id)
    if sealed.origin(peer.endpoint_url) != sealed.origin(peer.card_url):
        # its credential is sealed for the card's origin: it is not sent anywhere else
        peer.last_error = "the card names an endpoint on another origin than the card: its credential is not sent there"
        await db.commit()
    return {"synced": True, **report}


class A2APlanIn(BaseModel):
    """A JSON-RPC request the agent sent to the proxy (/_a2a/<peer>) for a peer
    whose credential is sealed to it, with the peer's live card the proxy
    fetched with that credential (or why it could not)."""
    model_config = ConfigDict(extra="forbid")
    slug: str = Field(pattern=SLUG)
    body: Any = None
    a2a_version: Optional[str] = Field(default=None, max_length=20)
    live_card: Optional[Dict[str, Any]] = None
    live_error: Optional[str] = Field(default=None, max_length=100)


@proxy_router.post("/a2a/plan")
async def proxy_a2a_plan(data: A2APlanIn, request: Request, db: AsyncSession = Depends(get_db),
                         proxy: EgressProxy = Depends(current_proxy),
                         x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key")):
    """Checked and decided as the A2A gateway does (app/api/a2a_gateway.py,
    app/pvp/a2a_gateway.py). The answer: the JSON-RPC response for the agent
    (a refusal), or the request to send to the peer."""
    import json as _json

    from fastapi.responses import JSONResponse

    from app.api.a2a_gateway import read_request
    from app.pvp import a2a_wire as w
    from app.pvp import proxy_actions
    from app.pvp.a2a_gateway import A2AGateway
    from app.services.agent_identity import _accountable_user
    from app.services.supply_chain import manifest_digest

    agent = await proxy_actions.agent_for(db, proxy, x_agent_key)
    await enforcement.verify_agent_request(db, proxy, agent, request, "a2a")
    user = await _accountable_user(db, agent)
    if user is None:
        raise api_error(status.HTTP_403_FORBIDDEN, "agent_identity.no_accountable_user")
    request.state.agent = agent
    parsed = await read_request(request, db, user, data.slug, data.body, data.a2a_version)
    if isinstance(parsed, JSONResponse):
        return {"decision": "reply", "status": parsed.status_code, "response": _json.loads(parsed.body)}
    rid, canonical, version, params, chain_id, peer = parsed
    if (peer.credential_source or "none") == "none" and not await enforcement.enforced(db, proxy.org_id):
        raise api_error(status.HTTP_404_NOT_FOUND, "a2a.peer_not_found")
    live, live_error = None, data.live_error or (None if data.live_card is not None else "upstream.no_card")
    if data.live_card is not None:
        live = manifest_digest(w.pinned_card(data.live_card))
    try:
        _orc, check, req = await A2AGateway(db).prepare(agent, peer, canonical, params, chain_id, live, live_error,
                                                        proxy_actions.EXECUTOR)
    except w.A2AError as exc:
        err = {"code": exc.code, "message": exc.message, **({"data": exc.data} if exc.data else {})}
        return {"decision": "reply", "status": 200, "response": {"jsonrpc": "2.0", "id": rid, "error": err}}
    except HTTPException as exc:
        return {"decision": "reply", "status": 200, "response": {"jsonrpc": "2.0", "id": rid, "error": {
            "code": -32000, "message": "Refused by Provenza",
            "data": exc.detail if isinstance(exc.detail, (str, dict)) else None}}}
    await proxy_actions.reserve(db, proxy, check.check_id, params)
    out = await proxy_actions.allowed(db, proxy, check, params)
    return {**out, "input": params, "rid": rid, "canonical": canonical, "version": version, "request": req,
            "tool_digest": live,
            "credential": {"object": "a2a_peer", "id": peer.id, "source": peer.credential_source,
                           "header": peer.auth_header}}


class A2ACompleteIn(BaseModel):
    """What the peer answered to a request the proxy sent: the server reads it
    as its gateway does; what is recorded is its status and hash."""
    model_config = ConfigDict(extra="forbid")
    check_id: str = Field(min_length=16, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    rid: Any = None
    canonical: Literal["SendMessage", "GetTask", "CancelTask"]
    version: str = Field(max_length=20)
    wire_id: int
    status: int = Field(ge=0, le=599)
    content_type: str = Field(default="", max_length=200)
    response: Optional[str] = Field(default=None, max_length=12_000_000)     # base64
    upstream_error: Optional[str] = Field(default=None, pattern=r"^[a-z0-9_.]{1,100}$")
    duration_ms: Optional[int] = Field(default=None, ge=0)
    receipt: Optional[Receipt] = None


@proxy_router.post("/a2a/complete")
async def proxy_a2a_complete(data: A2ACompleteIn, request: Request, db: AsyncSession = Depends(get_db),
                             proxy: EgressProxy = Depends(current_proxy)):
    import base64
    import hashlib

    from app.models.a2a_gateway import A2APeer
    from app.models.agent_action import ActionCheck
    from app.pvp import a2a_wire as w
    from app.pvp.a2a_gateway import A2AGateway
    from app.pvp.upstream_http import parse_body

    chk = (await db.execute(select(ActionCheck).where(ActionCheck.token == data.check_id,
                                                      ActionCheck.org_id == proxy.org_id))).scalar_one_or_none()
    if chk is None or not (chk.tool_name or "").startswith("a2a."):
        raise api_error(status.HTTP_404_NOT_FOUND, "egress.unknown_redemption")
    org_id, agent_id, tool = chk.org_id, chk.agent_id, chk.tool_name
    peer = (await db.execute(select(A2APeer).where(A2APeer.org_id == org_id,
                                                   A2APeer.slug == tool[len("a2a."):]))).scalar_one_or_none()
    if peer is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "a2a.peer_not_found")
    peer_id, peer_version = peer.id, peer.protocol_version
    raw = base64.b64decode(data.response or "", validate=False) if data.response else b""
    output = {"status": data.status, "response_sha256": hashlib.sha256(raw).hexdigest() if raw else None}
    if data.upstream_error:
        output["error"] = data.upstream_error
    enforced = await enforcement.proxy_gate(db, proxy, request)
    recorded = await svc.complete(db, proxy, data.check_id, output, data.duration_ms,
                                  data.receipt.model_dump() if data.receipt else None, enforced=enforced)
    msg = None if data.upstream_error else parse_body(data.content_type, raw, data.wire_id)
    kind, obj, _out, peer_error = await A2AGateway(db).finish(org_id, agent_id, peer_id, data.canonical,
                                                               peer_version, data.status, msg, data.upstream_error)
    await db.commit()
    if peer_error is not None:
        err = {"code": peer_error.code, "message": peer_error.message,
               "data": {**(peer_error.data or {}), "action_id": recorded["action_id"]}}
        return {"action_id": recorded["action_id"], "response": {"jsonrpc": "2.0", "id": data.rid, "error": err}}
    return {"action_id": recorded["action_id"], "response": {
        "jsonrpc": "2.0", "id": data.rid, "result": w.result_to_wire(data.canonical, kind, obj, data.version)}}


@proxy_router.post("/redeem")
async def proxy_redeem(data: RedeemIn, request: Request, db: AsyncSession = Depends(get_db),
                       proxy: EgressProxy = Depends(current_proxy)):
    enforced = await enforcement.proxy_gate(db, proxy, request)
    desc = svc.descriptor(data.route, data.method, data.path, data.query_sha256, data.body_sha256, data.body_bytes)
    enf = data.enforcement.model_dump() if data.enforcement else None
    return await svc.redeem(db, proxy, data.check_id, desc, enf, enforced=enforced)


class CompleteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check_id: str = Field(min_length=16, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    status: int = Field(ge=0, le=599)    # 0: no response (the upstream failed)
    response_sha256: Optional[str] = Field(default=None, pattern=HEX64)
    response_bytes: Optional[int] = Field(default=None, ge=0)
    error: Optional[str] = Field(default=None, pattern=r"^[a-z0-9_.]{1,100}$")
    duration_ms: Optional[int] = Field(default=None, ge=0)
    receipt: Optional[Receipt] = None
    # a gateway action the proxy executed (app/pvp/proxy_actions.py): what it reports
    # instead of the route fields - metadata only, never content
    output: Optional[Dict[str, Any]] = None
    enforcement: Optional[Enforcement] = None

    @field_validator("output")
    @classmethod
    def _small(cls, v):
        import json

        if v is not None and (len(v) > 20 or len(json.dumps(v)) > 4000):
            raise ValueError("the output a proxy reports is metadata: at most 20 fields, 4000 bytes")
        return v


class OfflineActionsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    actions: List[Any] = Field(max_length=100)


@proxy_router.post("/offline-actions")
async def proxy_offline_actions(data: OfflineActionsIn, db: AsyncSession = Depends(get_db),
                                proxy: EgressProxy = Depends(current_proxy)):
    """What the proxy did while this server was unreachable (app/pvp/proxy_offline.py)."""
    from app.pvp import proxy_offline

    return {"results": await proxy_offline.offline_actions(db, proxy, data.actions)}


@proxy_router.get("/reconciliation")
async def proxy_reconciliation(db: AsyncSession = Depends(get_db), proxy: EgressProxy = Depends(current_proxy)):
    """What the server states now, for a stopped proxy to compare with its release."""
    from app.pvp import proxy_offline

    return await proxy_offline.reconciliation_state(db, proxy.org_id)


class KillSwitchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    report: Dict[str, Any]
    receipt: Dict[str, Any]


@proxy_router.post("/kill-switch")
async def proxy_kill_switch_report(data: KillSwitchIn, db: AsyncSession = Depends(get_db),
                                   proxy: EgressProxy = Depends(current_proxy)):
    from app.pvp import proxy_offline

    return await proxy_offline.report(db, proxy, data.report, data.receipt)


@proxy_router.get("/kill-switch/lift")
async def proxy_kill_switch_lift(db: AsyncSession = Depends(get_db), proxy: EgressProxy = Depends(current_proxy)):
    from app.pvp import proxy_offline

    return await proxy_offline.lift_signatures(db, proxy)


class LiftedIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    report_sha256: str = Field(min_length=64, max_length=64)
    signers: List[str] = Field(default_factory=list, max_length=20)


@proxy_router.post("/kill-switch/lifted")
async def proxy_kill_switch_lifted(data: LiftedIn, db: AsyncSession = Depends(get_db),
                                   proxy: EgressProxy = Depends(current_proxy)):
    from app.pvp import proxy_offline

    org_id, proxy_id = proxy.org_id, proxy.id
    await proxy_offline.lifted(db, proxy, data.report_sha256, data.signers)
    await AuditService(db).log(org_id, None, "egress_proxy", proxy_id, "kill_switch_lifted",
                               {"report_sha256": data.report_sha256, "signers": data.signers})
    return {"ok": True}


@proxy_router.post("/complete")
async def proxy_complete(data: CompleteIn, request: Request, db: AsyncSession = Depends(get_db),
                         proxy: EgressProxy = Depends(current_proxy)):
    if data.output is not None:
        output = data.output
    else:
        output = {"status": data.status, "response_sha256": data.response_sha256,
                  "response_bytes": data.response_bytes}
        if data.error:
            output["error"] = data.error
    refused = data.enforcement.model_dump(exclude={"receipt"}) if data.enforcement else None
    enforced = await enforcement.proxy_gate(db, proxy, request)
    return await svc.complete(db, proxy, data.check_id, output, data.duration_ms,
                              data.receipt.model_dump() if data.receipt else None, refused, enforced=enforced)
