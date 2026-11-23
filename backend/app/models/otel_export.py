# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import BigInteger, Boolean, Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class OtelExportSettings(Base):
    """Where an organization's PVP decisions are sent as OpenTelemetry log
    records (app/services/otel_export.py). No row, or enabled false: nothing
    leaves the server. The endpoint is outbound traffic to the host it names.

    cursors holds, per kind of event, the id of the last row sent; an export
    starts from the moment it is switched on, not from the past. The
    authorization header's value is stored encrypted and never shown again."""

    __tablename__ = "otel_export_settings"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True)
    enabled = Column(Boolean, nullable=False, server_default="false")
    endpoint = Column(String(500))                 # OTLP/HTTP base URL or its /v1/logs URL
    header_name = Column(String(100))              # e.g. Authorization, x-honeycomb-team, DD-API-KEY
    header_value_enc = Column(Text)                # encrypted with the server ENCRYPTION_KEY
    cursors = Column(JSONB, nullable=False, server_default="{}")
    last_success_at = Column(DateTime(timezone=True))
    last_error = Column(String(500))
    last_error_at = Column(DateTime(timezone=True))
    exported_total = Column(BigInteger, nullable=False, server_default="0")
    # raised on every change an administrator saves; a run that started under
    # an older configuration does not write its cursors back
    config_rev = Column(Integer, nullable=False, server_default="0")
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), server_default=func.now())
