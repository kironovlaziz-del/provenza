# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class PVPGuardLog(Base):
    """A request the PVP Input Guard refused before it became a PVP message
    (app/pvp/guard.py). Only authenticated requests are logged - an
    anonymous one cannot make the server write rows.

    The request itself is never stored: its SHA-256 and size, and for each
    finding the JSON path and a reason code. No content, so a refused
    payload (an attack, or someone's personal data) does not land in the
    database through its own refusal.
    """

    __tablename__ = "pvp_guard_log"
    __table_args__ = (Index("ix_pvp_guard_log_org_created", "org_id", "created_at"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="SET NULL"), index=True)  # set for an agent key
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))                # the session / accountable human
    protocol = Column(String(20), nullable=False)   # rest, mcp, a2a
    route = Column(String(50), nullable=False)      # action.request, action.record, delegation, ...
    reason = Column(String(100), nullable=False)    # first finding's code, e.g. input.too_deep
    findings = Column(JSONB, nullable=False)        # [{"code": ..., "path": ...}], at most MAX_FINDINGS
    body_sha256 = Column(String(64), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    client_ip = Column(String(64))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
