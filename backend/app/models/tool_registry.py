# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class ToolRegistryEntry(Base):
    """
    A tool, MCP server or SDK that agents may call (OWASP ASI04 - agentic
    supply chain). `pattern` is an exact tool name ("github.create_issue")
    or a glob covering a whole server ("github.*").

    status: approved | pending | blocked | drifted
      pending - discovered automatically or awaiting review
      drifted - the reported version / manifest digest no longer matches
                the pinned one (e.g. a tool silently changed after approval)
    """

    __tablename__ = "tool_registry_entries"
    __table_args__ = (UniqueConstraint("org_id", "pattern", name="uq_tool_registry_pattern"),)

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    pattern = Column(String(200), nullable=False)
    kind = Column(String(20), nullable=False, default="tool")  # tool, mcp_server, sdk
    display_name = Column(String(255))
    source = Column(String(500))      # URL, package name, registry reference
    publisher = Column(String(255))
    pinned_version = Column(String(100))
    pinned_digest = Column(String(100))  # sha256 hex of the tool manifest
    status = Column(String(20), nullable=False, default="pending")
    discovered = Column(Boolean, nullable=False, default=False)  # added automatically on first use
    seen_count = Column(Integer, nullable=False, default=0)
    first_seen_at = Column(DateTime(timezone=True))
    last_seen_at = Column(DateTime(timezone=True))
    approved_by = Column(Integer, ForeignKey("users.id"))
    approved_at = Column(DateTime(timezone=True))
    drift_details = Column(JSONB)
    # capabilities an agent must hold (in its chain) to call a matching tool -
    # what actions are checked against, instead of anything the caller claims
    required_capabilities = Column(JSONB(none_as_null=True))
    notes = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class SupplyChainSettings(Base):
    """Per-organization mode: off | monitor (default) | enforce."""

    __tablename__ = "supply_chain_settings"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True)
    mode = Column(String(20), nullable=False, default="monitor")
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
