# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza - https://github.com/kironovlaziz-del/provenza

"""Export keys: read-only credentials an organization gives its SIEM/SOAR.

  GET  /                  the organization's keys, newest first (admin)
  POST /                  a new key; the key itself is returned this once (admin)
  POST /{id}/revoke       stop a key; it stays listed (admin)

A key is sent as X-Export-Key and reads what its scope allows - today the
egress sensor feed, GET /api/v1/egress-sensor/events (export_reader).
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, oauth2_scheme_optional, require_role
from app.core.database import get_db
from app.core.errors import api_error
from app.core.security import hash_api_key
from app.models.export_key import ExportKey
from app.models.user import User, UserRole
from app.schemas.export_key import ExportKeyCreate, ExportKeyCreated, ExportKeyOut
from app.services.audit_service import AuditService

router = APIRouter()

KEY_PREFIX = "pvx_"
# last_used_at is written at most this often, not on every poll of a SIEM
LAST_USED_RESOLUTION = timedelta(minutes=1)


@router.get("/", response_model=List[ExportKeyOut])
async def list_keys(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    rows = await db.execute(
        select(ExportKey).where(ExportKey.org_id == current_user.org_id).order_by(ExportKey.id.desc())
    )
    return rows.scalars().all()


@router.post("/", response_model=ExportKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_key(
    data: ExportKeyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    raw = KEY_PREFIX + secrets.token_urlsafe(32)
    key = ExportKey(
        org_id=current_user.org_id, name=data.name.strip(), scope="egress_events",
        key_hash=hash_api_key(raw), key_prefix=raw[:12], created_by=current_user.id,
    )
    db.add(key)
    await db.flush()
    await db.refresh(key)
    out = ExportKeyCreated(**ExportKeyOut.model_validate(key).model_dump(), api_key=raw)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "export_key", key.id, "created",
        {"name": key.name, "scope": key.scope, "key_prefix": key.key_prefix},
    )
    return out


@router.post("/{key_id}/revoke", response_model=ExportKeyOut)
async def revoke_key(
    key_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    key = (await db.execute(
        select(ExportKey).where(ExportKey.id == key_id, ExportKey.org_id == current_user.org_id)
    )).scalar_one_or_none()
    if key is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "export_key.not_found")
    if key.revoked_at is None:
        key.revoked_at = datetime.now(timezone.utc)
        key.revoked_by = current_user.id
        await db.flush()
        await AuditService(db).log(
            current_user.org_id, current_user.id, "export_key", key.id, "revoked",
            {"name": key.name, "key_prefix": key.key_prefix},
        )
        await db.refresh(key)
    return key


def export_reader(scope: str):
    """The organization a request reads for: an export key of this scope
    (X-Export-Key), or else an administrator's session, as before."""

    async def reader(
        request: Request,
        x_export_key: Optional[str] = Header(None, alias="X-Export-Key"),
        token: Optional[str] = Depends(oauth2_scheme_optional),
        db: AsyncSession = Depends(get_db),
    ) -> int:
        if x_export_key:
            key = (await db.execute(
                select(ExportKey).where(ExportKey.key_hash == hash_api_key(x_export_key))
            )).scalar_one_or_none()
            if key is None or key.revoked_at is not None or key.scope != scope:
                raise api_error(status.HTTP_401_UNAUTHORIZED, "export_key.invalid")
            now = datetime.now(timezone.utc)
            if key.last_used_at is None or now - key.last_used_at >= LAST_USED_RESOLUTION:
                key.last_used_at = now
                await db.commit()
            return key.org_id
        user = await get_current_user(request, token, None, db)
        if getattr(request.state, "agent", None) is not None or user.role != UserRole.admin.value:
            raise api_error(status.HTTP_403_FORBIDDEN, "rbac.insufficient_role", allowed=[UserRole.admin.value])
        return user.org_id

    return reader
