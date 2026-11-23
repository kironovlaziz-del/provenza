# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""OpenTelemetry export of PVP decisions (app/services/otel_export.py).

  GET  /        the organization's settings and the export's state (admin)
  PUT  /        change them; switched on, a test record is sent first (admin)
  POST /test    send one test record with the stored settings (admin)
"""

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
from app.models.user import User, UserRole
from app.services import otel_export
from app.services.audit_service import AuditService

router = APIRouter()
_admin = require_role(UserRole.admin)


class OtelExportIn(BaseModel):
    enabled: bool
    # the collector's OTLP/HTTP base URL (…:4318) or its /v1/logs URL
    endpoint: Optional[str] = Field(default=None, max_length=500)
    # one optional header, e.g. Authorization, x-honeycomb-team, DD-API-KEY;
    # no name removes it, a name without a value keeps the stored value
    header_name: Optional[str] = Field(default=None, max_length=100)
    header_value: Optional[str] = Field(default=None, max_length=4000)


@router.get("/")
async def get_settings(db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    return otel_export.settings_out(await otel_export.get_settings(db, current_user.org_id))


@router.put("/")
async def set_settings(data: OtelExportIn, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    org_id, user_id = current_user.org_id, current_user.id
    before = await otel_export.get_settings(db, org_id)
    old_name = before.header_name if before is not None else None
    old_set = bool(before is not None and before.header_value_enc)
    row = await otel_export.save_settings(db, org_id, user_id, enabled=data.enabled, endpoint=data.endpoint,
                                          header_name=data.header_name, header_value=data.header_value)
    await AuditService(db).log(org_id, user_id, "otel_export", org_id, "configured", {
        "enabled": row.enabled, "endpoint": row.endpoint, "header_name": row.header_name,
        # never the value; only whether it changed
        "header_changed": bool(data.header_value) or (old_set and not row.header_value_enc)
        or (old_name or "").lower() != (row.header_name or "").lower(),
    })
    return otel_export.settings_out(row)


@router.post("/test")
async def send_test(db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    return await otel_export.send_test(db, current_user.org_id)
