# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Single sign-on (app/services/sso.py).

  public                               /api/v1/auth/sso
    GET  /{org_slug}/info              whether the organization offers SSO (for the sign-in page)
    GET  /{org_slug}/start             -> the provider
    GET  /callback                     <- the provider; -> /login/sso#code=...
    POST /exchange                     the one-time code -> a session token
  admins                               /api/v1/sso
    GET  /settings   PUT /settings     the provider; saving checks its discovery document
"""

from datetime import timedelta
from typing import List, Optional
from urllib.parse import quote

import jwt
from fastapi import APIRouter, Cookie, Depends, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core import rate_limit, sessions
from app.core.config import settings
from app.core.crypto import encrypt_secret
from app.core.database import get_db
from app.core.errors import api_error
from app.core.security import create_access_token
from app.models.organization import Organization
from app.models.user import User, UserRole
from app.services import sso
from app.services.audit_service import AuditService

public_router = APIRouter()
admin_router = APIRouter()
COOKIE = "pvz_sso"
COOKIE_PATH = settings.API_V1_STR + "/auth/sso"


def _base(request: Request) -> str:
    return (settings.PUBLIC_BASE_URL or str(request.base_url)).rstrip("/")


def redirect_uri(request: Request) -> str:
    return _base(request) + settings.API_V1_STR + "/auth/sso/callback"


def _secure(request: Request) -> bool:
    return request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https" \
        or settings.PUBLIC_BASE_URL.startswith("https://")


def _fail(code: str) -> RedirectResponse:
    """Back to the sign-in page with a code it can translate - never the details."""
    resp = RedirectResponse("/login?sso_error=" + quote(code), status_code=status.HTTP_302_FOUND)
    resp.delete_cookie(COOKIE, path=COOKIE_PATH)
    return resp


async def _org(db: AsyncSession, slug: str) -> Optional[Organization]:
    return (await db.execute(select(Organization).where(Organization.slug == slug.strip().lower()))).scalar_one_or_none()


@public_router.get("/callback")
async def callback(request: Request, code: Optional[str] = None, state: Optional[str] = None,
                   error: Optional[str] = None, db: AsyncSession = Depends(get_db),
                   pvz_sso: Optional[str] = Cookie(None)):
    rate_limit.enforce(request, scope="sso", limit=60, window_seconds=300)
    if error:
        return _fail("sso.provider_refused")
    try:
        data = sso.unseal(pvz_sso, state)
        cfg = await sso.get_settings(db, data["org"])
        if cfg is None or not cfg.enabled or not code:
            raise sso.SsoError("sso.not_configured")
        tokens = await sso.exchange_code(cfg, code, data["verifier"], redirect_uri(request))
        claims = await sso.verify_id_token(tokens["id_token"], cfg, data["nonce"])
        user, idp_mfa = await sso.user_for(db, cfg, claims)
    except sso.SsoError as exc:
        return _fail(exc.code)
    org_id, user_id = user.org_id, user.id
    await AuditService(db).log(org_id, user_id, "user", user_id, "login_sso",
                               {"issuer": claims["iss"], "idp_mfa": idp_mfa})
    hand_off = create_access_token({"sub": str(user_id), "purpose": "sso_exchange", "idp_mfa": idp_mfa},
                                   expires_delta=timedelta(seconds=sso.EXCHANGE_TTL))
    resp = RedirectResponse("/login/sso#code=" + hand_off, status_code=status.HTTP_302_FOUND)
    resp.delete_cookie(COOKIE, path=COOKIE_PATH)
    return resp


class ExchangeIn(BaseModel):
    code: str = Field(min_length=20, max_length=4000)


@public_router.post("/exchange")
async def exchange(data: ExchangeIn, request: Request, db: AsyncSession = Depends(get_db)):
    rate_limit.enforce(request, scope="sso", limit=60, window_seconds=300)
    invalid = api_error(status.HTTP_401_UNAUTHORIZED, "sso.bad_code")
    try:
        payload = jwt.decode(data.code, settings.SECRET_KEY, algorithms=[settings.ALGORITHM],
                             options={"verify_sub": False})
    except jwt.PyJWTError:
        raise invalid
    if payload.get("purpose") != "sso_exchange" or sessions.is_revoked(payload.get("jti")):
        raise invalid
    sessions.revoke(payload.get("jti"), payload.get("exp"))      # one use
    user = await db.get(User, int(payload["sub"]))
    if user is None or user.status != "active":
        raise invalid
    if user.sessions_valid_after is not None and payload.get("iat", 0) < user.sessions_valid_after.timestamp():
        raise invalid
    claims = {"amr": ["sso"]}
    if payload.get("idp_mfa"):
        claims["idp_mfa"] = True
    from app.services import signing_sessions

    return {"access_token": await signing_sessions.issue_token(db, user, request, claims), "token_type": "bearer"}


@public_router.get("/{org_slug}/start")
async def start(org_slug: str, request: Request, db: AsyncSession = Depends(get_db)):
    rate_limit.enforce(request, scope="sso", limit=60, window_seconds=300)
    org = await _org(db, org_slug)
    cfg = await sso.get_settings(db, org.id) if org else None
    if cfg is None or not cfg.enabled:
        return _fail("sso.not_configured")
    try:
        url, sealed = await sso.start(cfg, redirect_uri(request), org.id)
    except sso.SsoError as exc:
        return _fail(exc.code)
    resp = RedirectResponse(url, status_code=status.HTTP_302_FOUND)
    resp.set_cookie(COOKIE, sealed, max_age=sso.STATE_TTL, path=COOKIE_PATH, httponly=True,
                    secure=_secure(request), samesite="lax")
    return resp


@public_router.get("/{org_slug}/info")
async def offered(org_slug: str, request: Request, db: AsyncSession = Depends(get_db)):
    """The same answer for an unknown organization as for one without SSO."""
    rate_limit.enforce(request, scope="sso_info", limit=60, window_seconds=60)
    org = await _org(db, org_slug)
    cfg = await sso.get_settings(db, org.id) if org else None
    on = bool(cfg and cfg.enabled)
    return {"sso": on, "password": not (on and cfg.enforce)}


# ================================================================ admin

class SsoSettingsIn(BaseModel):
    enabled: bool = True
    issuer: str = Field(min_length=8, max_length=500)
    client_id: str = Field(min_length=1, max_length=255)
    client_secret: Optional[str] = Field(default=None, min_length=1, max_length=2000)   # None keeps the stored one
    email_claim: str = Field(default="email", pattern=r"^[A-Za-z0-9_:.-]{1,50}$")
    allowed_domains: List[str] = Field(default_factory=list, max_length=50)
    jit: bool = False
    default_role: str = Field(default="user", pattern="^(user|approver)$")
    enforce: bool = False
    require_idp_mfa: bool = False


@admin_router.get("/settings")
async def get_sso_settings(request: Request, db: AsyncSession = Depends(get_db),
                           user: User = Depends(require_role(UserRole.admin))):
    return sso.settings_out(await sso.get_settings(db, user.org_id), redirect_uri(request))


@admin_router.put("/settings")
async def put_sso_settings(data: SsoSettingsIn, request: Request, db: AsyncSession = Depends(get_db),
                           user: User = Depends(require_role(UserRole.admin))):
    """Saving with SSO on checks the provider's discovery document first."""
    org_id, user_id = user.org_id, user.id
    try:
        issuer = sso.check_issuer(data.issuer)
    except sso.SsoError as exc:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, exc.code, detail=exc.detail[:200])
    domains = sorted({d.strip().lower().lstrip("@") for d in data.allowed_domains if d.strip()})
    if data.jit and not domains:
        # without domains, anyone with an account at the provider would get one here
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "sso.jit_needs_domains")
    row = await sso.get_settings(db, org_id)
    try:
        async with db.begin_nested():   # an unusable provider undoes only this change
            if row is None:
                row = sso.OidcSettings(org_id=org_id)
                db.add(row)
            row.enabled, row.issuer, row.client_id = data.enabled, issuer, data.client_id.strip()
            if data.client_secret:
                row.client_secret_encrypted = encrypt_secret(data.client_secret, org_id)
            row.email_claim, row.allowed_domains, row.jit = data.email_claim, domains, data.jit
            row.default_role, row.enforce, row.require_idp_mfa = data.default_role, data.enforce, data.require_idp_mfa
            row.updated_by = user_id
            await db.flush()
            if data.enabled:
                # the provider as stored - what every sign-in will use, through the SSRF-guarded client
                stored = await sso.get_settings(db, org_id)
                await sso.discovery(stored.issuer, refresh=True)
    except sso.SsoError as exc:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, exc.code, detail=exc.detail[:200])
    await db.commit()
    out = sso.settings_out(row, redirect_uri(request))
    await AuditService(db).log(org_id, user_id, "sso", org_id, "settings_updated",
                               {k: v for k, v in out.items() if k not in ("redirect_uri",)})
    return out
