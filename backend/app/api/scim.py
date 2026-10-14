# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
SCIM 2.0 provisioning (RFC 7643 / 7644) - the identity provider keeps the
organization's users in step: Okta, Microsoft Entra ID, JumpCloud, ...

  IdP (Bearer pvz_scim_...)            /api/v1/scim/v2
    GET    /ServiceProviderConfig, /ResourceTypes, /Schemas
    GET    /Users?filter=userName eq "a@b.c"&startIndex=1&count=100
    GET    /Users/{id}
    POST   /Users                      create (or adopt the existing user with that e-mail)
    PUT    /Users/{id}                 replace name, e-mail, externalId, active
    PATCH  /Users/{id}                 Operations: active, name, displayName, userName, externalId
    DELETE /Users/{id}                 deprovision

  admins                               /api/v1/scim
    GET  /settings   PUT /settings     on/off, the role new users get
    POST /token      DELETE /token     a new bearer token (shown once) / none

A user switched off - active false, or deleted - is offboarded
(services/offboarding.py): sessions end, their agents' keys are revoked and
the agents suspended. The IdP never sets roles: new users get the default
role (user or approver), an admin changes it in Provenza. The last active
admin cannot be switched off from the IdP, so the organization always keeps
a way in.
"""

import re
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Header, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core import rate_limit
from app.core.config import settings
from app.core.database import get_db
from app.core.errors import api_error
from app.core.security import get_password_hash, hash_api_key
from app.models.scim import ScimSettings
from app.models.user import User, UserRole
from app.services.audit_service import AuditService
from app.services.offboarding import offboard

scim_router = APIRouter()
admin_router = APIRouter()

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
MEDIA = "application/scim+json"
TOKEN_PREFIX = "pvz_scim_"
MAX_COUNT = 200
EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")
FILTER = re.compile(r'^\s*(userName|externalId|id|emails\.value|emails\[type eq "work"\]\.value)\s+eq\s+"([^"]*)"\s*$',
                    re.IGNORECASE)
DEFAULT_ROLES = ("user", "approver")


class ScimError(Exception):
    def __init__(self, status_code: int, detail: str, scim_type: Optional[str] = None):
        super().__init__(detail)
        self.status_code, self.detail, self.scim_type = status_code, detail, scim_type


def scim_response(body: Any, status_code: int = 200, headers: Optional[Dict[str, str]] = None) -> JSONResponse:
    return JSONResponse(content=body, status_code=status_code, media_type=MEDIA, headers=headers)


def error_response(e: ScimError) -> JSONResponse:
    body: Dict[str, Any] = {"schemas": [ERROR_SCHEMA], "status": str(e.status_code), "detail": e.detail}
    if e.scim_type:
        body["scimType"] = e.scim_type
    return scim_response(body, e.status_code)


def _base(request: Request) -> str:
    return (settings.PUBLIC_BASE_URL or str(request.base_url)).rstrip("/") + settings.API_V1_STR + "/scim/v2"


# ================================================================ auth

async def scim_org(request: Request, authorization: Optional[str] = Header(None),
                   db: AsyncSession = Depends(get_db)) -> ScimSettings:
    rate_limit.enforce(request, scope="scim", limit=600, window_seconds=60)
    token = authorization[7:].strip() if authorization and authorization.lower().startswith("bearer ") else ""
    row = None
    if token.startswith(TOKEN_PREFIX):
        row = (await db.execute(select(ScimSettings).where(ScimSettings.token_hash == hash_api_key(token),
                                                          ScimSettings.enabled.is_(True)))).scalar_one_or_none()
    if row is None:
        raise ScimError(401, "a valid SCIM bearer token is required")
    row.last_used_at = datetime.now(timezone.utc)
    return row


# ================================================================ representation

def user_out(u: User, base: str) -> Dict[str, Any]:
    out = {
        "schemas": [USER_SCHEMA], "id": str(u.id), "userName": u.email,
        "name": {"formatted": u.name}, "displayName": u.name,
        "emails": [{"value": u.email, "primary": True, "type": "work"}],
        "active": u.status == "active",
        "meta": {"resourceType": "User", "location": f"{base}/Users/{u.id}",
                 "created": u.created_at.isoformat() if u.created_at else None},
    }
    if u.scim_external_id:
        out["externalId"] = u.scim_external_id
    return out


def _bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().lower() in ("true", "false"):
        return v.strip().lower() == "true"    # Entra ID sends "False"
    raise ScimError(400, "active must be a boolean", "invalidValue")


def _email(v: Any) -> str:
    if not isinstance(v, str) or not EMAIL.match(v.strip()):
        raise ScimError(400, "userName must be an e-mail address", "invalidValue")
    return v.strip().lower()


def _name_of(body: Dict[str, Any], fallback: str) -> str:
    name = body.get("name") if isinstance(body.get("name"), dict) else {}
    text = name.get("formatted") or " ".join(p for p in (name.get("givenName"), name.get("familyName")) if p) \
        or body.get("displayName") or fallback
    return str(text).strip()[:255] or fallback


async def _json(request: Request) -> Dict[str, Any]:
    try:
        body = await request.json()
    except ValueError:
        raise ScimError(400, "the body is not JSON", "invalidSyntax")
    if not isinstance(body, dict):
        raise ScimError(400, "the body must be a JSON object", "invalidSyntax")
    return body


async def _user(db: AsyncSession, org_id: int, user_id: str) -> User:
    if not user_id.isdigit():
        raise ScimError(404, "no such user")
    u = (await db.execute(select(User).where(User.id == int(user_id), User.org_id == org_id))).scalar_one_or_none()
    if u is None:
        raise ScimError(404, "no such user")
    return u


async def _email_taken(db: AsyncSession, org_id: int, email: str, except_id: Optional[int] = None) -> bool:
    q = select(User.id).where(User.org_id == org_id, func.lower(User.email) == email)
    if except_id is not None:
        q = q.where(User.id != except_id)
    return (await db.execute(q)).first() is not None


async def _set_active(db: AsyncSession, u: User, active: bool) -> None:
    """Off: offboarding (commits). On: the user only - their agents stay suspended."""
    if not active and u.status == "active":
        if u.role == UserRole.admin.value:
            others = (await db.execute(select(func.count()).select_from(User).where(
                User.org_id == u.org_id, User.role == UserRole.admin.value, User.status == "active",
                User.id != u.id))).scalar_one()
            if not others:
                raise ScimError(409, "the last active admin cannot be deactivated from the identity provider",
                                "mutability")
        await offboard(db, u, actor_id=None, via="scim")
    elif active and u.status != "active":
        u.status = "active"
        await db.commit()
        await AuditService(db).log(u.org_id, None, "user", u.id, "status_changed",
                                   {"from": "disabled", "to": "active", "via": "scim"})


# ================================================================ discovery

@scim_router.get("/ServiceProviderConfig")
async def service_provider_config(org: ScimSettings = Depends(scim_org)):
    return scim_response({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True}, "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": MAX_COUNT}, "changePassword": {"supported": False},
        "sort": {"supported": False}, "etag": {"supported": False},
        "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token",
                                   "description": "The organization's SCIM token (pvz_scim_...)"}],
    })


@scim_router.get("/ResourceTypes")
async def resource_types(request: Request, org: ScimSettings = Depends(scim_org)):
    return scim_response({"schemas": [LIST_SCHEMA], "totalResults": 1, "Resources": [{
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "User", "name": "User",
        "endpoint": "/Users", "schema": USER_SCHEMA}]})


@scim_router.get("/Schemas")
async def schemas(org: ScimSettings = Depends(scim_org)):
    attr = lambda name, typ="string", **kw: {"name": name, "type": typ, "multiValued": False, "required": False,  # noqa: E731
                                             "mutability": "readWrite", "returned": "default", **kw}
    return scim_response({"schemas": [LIST_SCHEMA], "totalResults": 1, "Resources": [{
        "id": USER_SCHEMA, "name": "User", "attributes": [
            attr("userName", required=True, uniqueness="server"), attr("displayName"),
            attr("name", "complex"), attr("emails", "complex", multiValued=True), attr("active", "boolean"),
            attr("externalId")]}]})


# ================================================================ users

@scim_router.get("/Users")
async def list_users(request: Request, filter: Optional[str] = None, startIndex: int = 1, count: int = 100,
                     db: AsyncSession = Depends(get_db), org: ScimSettings = Depends(scim_org)):
    q = select(User).where(User.org_id == org.org_id)
    if filter:
        m = FILTER.match(filter)
        if not m:
            raise ScimError(400, 'supported filters: userName / externalId / emails.value / id eq "..."',
                            "invalidFilter")
        attr, value = m.group(1).lower(), m.group(2)
        if attr == "externalid":
            q = q.where(User.scim_external_id == value)
        elif attr == "id":
            q = q.where(User.id == (int(value) if value.isdigit() else -1))
        else:
            q = q.where(func.lower(User.email) == value.strip().lower())
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    start, count = max(1, startIndex), max(0, min(count, MAX_COUNT))
    rows = (await db.execute(q.order_by(User.id).offset(start - 1).limit(count))).scalars().all()
    await db.commit()   # last_used_at
    base = _base(request)
    return scim_response({"schemas": [LIST_SCHEMA], "totalResults": total, "startIndex": start,
                          "itemsPerPage": len(rows), "Resources": [user_out(u, base) for u in rows]})


@scim_router.get("/Users/{user_id}")
async def get_user(user_id: str, request: Request, db: AsyncSession = Depends(get_db),
                   org: ScimSettings = Depends(scim_org)):
    u = await _user(db, org.org_id, user_id)
    await db.commit()
    return scim_response(user_out(u, _base(request)))


@scim_router.post("/Users")
async def create_user(request: Request, db: AsyncSession = Depends(get_db), org: ScimSettings = Depends(scim_org)):
    body = await _json(request)
    email = _email(body.get("userName"))
    external = str(body["externalId"])[:255] if body.get("externalId") is not None else None
    active = _bool(body["active"]) if "active" in body else True
    existing = (await db.execute(select(User).where(User.org_id == org.org_id,
                                                    func.lower(User.email) == email))).scalar_one_or_none()
    org_id = org.org_id
    if existing is not None:
        if existing.scim_managed and existing.scim_external_id and external and existing.scim_external_id != external:
            raise ScimError(409, "a user with this userName is provisioned already", "uniqueness")
        # adopt the account an admin created before provisioning was switched on
        existing.scim_managed, existing.scim_external_id = True, external or existing.scim_external_id
        existing.name = _name_of(body, existing.name)
        await db.commit()
        await AuditService(db).log(org_id, None, "user", existing.id, "scim_linked", {"email": email})
        await _set_active(db, existing, active)
        await db.refresh(existing)
        return scim_response(user_out(existing, _base(request)), 201)
    u = User(org_id=org_id, email=email, name=_name_of(body, email.split("@")[0]),
             hashed_password=get_password_hash(secrets.token_urlsafe(32)),   # no password: the IdP signs them in
             role=org.default_role if org.default_role in DEFAULT_ROLES else UserRole.user.value,
             status="active" if active else "disabled", scim_managed=True, scim_external_id=external)
    db.add(u)
    await db.commit()
    await db.refresh(u)
    await AuditService(db).log(org_id, None, "user", u.id, "scim_created",
                               {"email": email, "role": u.role, "active": active})
    return scim_response(user_out(u, _base(request)), 201)


async def _apply(db: AsyncSession, u: User, changes: Dict[str, Any]) -> None:
    """name / email / externalId first, then active (which may offboard and commit)."""
    if "userName" in changes:
        email = _email(changes["userName"])
        if email != u.email.lower() and await _email_taken(db, u.org_id, email, u.id):
            raise ScimError(409, "another user has this userName", "uniqueness")
        u.email = email
    if "name" in changes:
        u.name = changes["name"]
    if "externalId" in changes:
        u.scim_external_id = str(changes["externalId"])[:255] if changes["externalId"] is not None else None
    u.scim_managed = True
    await db.commit()
    if "active" in changes:
        await _set_active(db, u, changes["active"])


@scim_router.put("/Users/{user_id}")
async def replace_user(user_id: str, request: Request, db: AsyncSession = Depends(get_db),
                       org: ScimSettings = Depends(scim_org)):
    u = await _user(db, org.org_id, user_id)
    body = await _json(request)
    changes: Dict[str, Any] = {"name": _name_of(body, u.name)}
    if "userName" in body:
        changes["userName"] = body["userName"]
    if "externalId" in body:
        changes["externalId"] = body["externalId"]
    if "active" in body:
        changes["active"] = _bool(body["active"])
    await _apply(db, u, changes)
    await db.refresh(u)
    return scim_response(user_out(u, _base(request)))


def _patch_changes(ops: List[Dict[str, Any]], current_name: str) -> Dict[str, Any]:
    changes: Dict[str, Any] = {}
    name_parts: Dict[str, str] = {}
    for op in ops:
        kind = str(op.get("op", "")).lower()
        if kind not in ("add", "replace", "remove"):
            raise ScimError(400, f"unsupported op {op.get('op')!r}", "invalidSyntax")
        path, value = op.get("path"), op.get("value")
        items: List[Tuple[str, Any]] = list(value.items()) if path is None and isinstance(value, dict) \
            else [(str(path or ""), value)]
        for key, val in items:
            key_l = key.lower()
            if key_l == "active":
                changes["active"] = False if kind == "remove" else _bool(val)
            elif key_l == "username":
                changes["userName"] = val
            elif key_l == "externalid":
                changes["externalId"] = None if kind == "remove" else val
            elif key_l in ("displayname", "name.formatted"):
                name_parts["formatted"] = str(val or "")
            elif key_l == "name.givenname":
                name_parts["givenName"] = str(val or "")
            elif key_l == "name.familyname":
                name_parts["familyName"] = str(val or "")
            elif key_l == "name" and isinstance(val, dict):
                name_parts.update({k: str(v) for k, v in val.items() if isinstance(v, str)})
            elif key_l.startswith("emails") and isinstance(val, (str, list)):
                v = val if isinstance(val, str) else next((e.get("value") for e in val if isinstance(e, dict)), None)
                if v:
                    changes["userName"] = v
            # anything else (title, department, manager ...) is not kept by Provenza
    if name_parts:
        changes["name"] = _name_of({"name": name_parts}, current_name)
    return changes


@scim_router.patch("/Users/{user_id}")
async def patch_user(user_id: str, request: Request, db: AsyncSession = Depends(get_db),
                     org: ScimSettings = Depends(scim_org)):
    u = await _user(db, org.org_id, user_id)
    body = await _json(request)
    ops = body.get("Operations")
    if not isinstance(ops, list) or not ops or len(ops) > 50:
        raise ScimError(400, "Operations: a list of 1..50 operations", "invalidSyntax")
    await _apply(db, u, _patch_changes(ops, u.name))
    await db.refresh(u)
    return scim_response(user_out(u, _base(request)))


@scim_router.delete("/Users/{user_id}")
async def delete_user(user_id: str, db: AsyncSession = Depends(get_db), org: ScimSettings = Depends(scim_org)):
    """Deprovisioned: offboarded and unlinked from the IdP. The row stays -
    the audit log and the agents' history refer to it."""
    u = await _user(db, org.org_id, user_id)
    await _set_active(db, u, False)
    u.scim_managed, u.scim_external_id = False, None
    await db.commit()
    await AuditService(db).log(u.org_id, None, "user", u.id, "scim_deprovisioned", {"email": u.email})
    return Response(status_code=204)


# ================================================================ admin

class ScimSettingsIn(BaseModel):
    enabled: Optional[bool] = None
    default_role: Optional[str] = None


async def _settings(db: AsyncSession, org_id: int) -> Optional[ScimSettings]:
    return (await db.execute(select(ScimSettings).where(ScimSettings.org_id == org_id))).scalar_one_or_none()


def _settings_out(row: Optional[ScimSettings], request: Request) -> Dict[str, Any]:
    return {"enabled": bool(row and row.enabled and row.token_hash), "has_token": bool(row and row.token_hash),
            "token_prefix": row.token_prefix if row else None,
            "default_role": row.default_role if row else "user", "base_url": _base(request),
            "last_used_at": row.last_used_at if row else None}


@admin_router.get("/settings")
async def get_settings(request: Request, db: AsyncSession = Depends(get_db),
                       user: User = Depends(require_role(UserRole.admin))):
    return _settings_out(await _settings(db, user.org_id), request)


@admin_router.put("/settings")
async def put_settings(data: ScimSettingsIn, request: Request, db: AsyncSession = Depends(get_db),
                       user: User = Depends(require_role(UserRole.admin))):
    if data.default_role is not None and data.default_role not in DEFAULT_ROLES:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "scim.bad_default_role")
    org_id, user_id = user.org_id, user.id
    row = await _settings(db, org_id) or ScimSettings(org_id=org_id, created_by=user_id)
    db.add(row)
    if data.enabled is not None:
        row.enabled = data.enabled and bool(row.token_hash)
    if data.default_role is not None:
        row.default_role = data.default_role
    await db.commit()
    await AuditService(db).log(org_id, user_id, "scim", org_id, "settings_updated",
                               {"enabled": row.enabled, "default_role": row.default_role})
    return _settings_out(row, request)


@admin_router.post("/token")
async def new_token(request: Request, db: AsyncSession = Depends(get_db),
                    user: User = Depends(require_role(UserRole.admin))):
    """A new token, shown once; the previous one stops working."""
    org_id, user_id = user.org_id, user.id
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    row = await _settings(db, org_id) or ScimSettings(org_id=org_id, created_by=user_id)
    db.add(row)
    row.token_hash, row.token_prefix, row.enabled = hash_api_key(raw), raw[:14], True
    await db.commit()
    await AuditService(db).log(org_id, user_id, "scim", org_id, "token_issued", {"prefix": raw[:14]})
    return {**_settings_out(row, request), "token": raw}


@admin_router.delete("/token")
async def drop_token(request: Request, db: AsyncSession = Depends(get_db),
                     user: User = Depends(require_role(UserRole.admin))):
    org_id, user_id = user.org_id, user.id
    row = await _settings(db, org_id)
    if row is not None:
        row.token_hash, row.token_prefix, row.enabled = None, None, False
        await db.commit()
    await AuditService(db).log(org_id, user_id, "scim", org_id, "token_revoked", {})
    return _settings_out(row, request)
