# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class HttpTool(Base):
    """An HTTP API registered as a tool (app/pvp/http_tools.py): Provenza holds
    its address and credential and makes the call; the agent never sees
    either. `name` is the tool name rights, policies and the Tool Registry
    use. Disabled, not deleted, while actions refer to it."""

    __tablename__ = "http_tools"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_http_tool_name"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    method = Column(String(10), nullable=False)               # GET, POST, PUT, PATCH, DELETE
    url = Column(String(500), nullable=False)                 # may hold {argument} placeholders in the path
    input_schema = Column(JSONB)                              # JSON Schema of the arguments (object)
    auth_header = Column(String(100), nullable=False, default="Authorization")
    auth_secret_encrypted = Column(Text)                      # the full header value, e.g. "Bearer ..."
    timeout_seconds = Column(Integer, nullable=False, default=30)
    max_response_bytes = Column(Integer, nullable=False, default=1024 * 1024)
    send_permit = Column(Boolean, nullable=False, default=True)   # forward the signed permit (body methods)
    enabled = Column(Boolean, nullable=False, default=True)
    digest = Column(String(64), nullable=False)               # of the definition; pinned in the Tool Registry
    registry_entry_id = Column(Integer, ForeignKey("tool_registry_entries.id", ondelete="SET NULL"))
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
