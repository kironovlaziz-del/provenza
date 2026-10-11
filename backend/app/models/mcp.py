# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import (Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func)
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class MCPServer(Base):
    """
    An upstream MCP server that agents reach only through Provenza's MCP
    gateway (app/pvp/mcp_gateway.py). Agents never see its URL or its
    credentials: the secret is encrypted (core/crypto, the organization's
    own key under BYOK) and decrypted only to make the upstream call.

    protocol: "auto" (detected on sync: the stateless 2026-07-28 revision,
    else the initialize-based ones) or a pinned version.
    """

    __tablename__ = "mcp_servers"
    __table_args__ = (UniqueConstraint("org_id", "slug", name="uq_mcp_servers_slug"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    slug = Column(String(40), nullable=False)          # tool names are exposed as "<slug>.<tool>"
    name = Column(String(255), nullable=False)
    url = Column(String(500), nullable=False)
    protocol = Column(String(20), nullable=False, default="auto")
    detected_version = Column(String(20))              # what the last sync spoke
    auth_header = Column(String(100), nullable=False, default="Authorization")
    auth_secret_encrypted = Column(Text)               # full header value, e.g. "Bearer ..."
    enabled = Column(Boolean, nullable=False, default=True)
    timeout_seconds = Column(Integer, nullable=False, default=30)
    server_info = Column(JSONB)                        # self-reported by the server: display only
    last_synced_at = Column(DateTime(timezone=True))
    last_error = Column(Text)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class MCPTool(Base):
    """
    A tool an upstream server offers, as last seen by a sync. Approval lives
    in the Tool Registry entry (pattern = exposed_name): agents are shown the
    definition only while its digest equals the entry's pinned digest, so
    what the model reads is always the definition an admin approved - a
    description changed upstream ("tool poisoning") never reaches it.
    """

    __tablename__ = "mcp_tools"
    __table_args__ = (UniqueConstraint("server_id", "name", name="uq_mcp_tools_name"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    server_id = Column(Integer, ForeignKey("mcp_servers.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(128), nullable=False)          # the upstream name
    exposed_name = Column(String(100), nullable=False)  # "<slug>.<name>", what policies and agents use
    definition = Column(JSONB, nullable=False)          # name, title, description, inputSchema, outputSchema, annotations
    digest = Column(String(64), nullable=False)         # supply_chain.manifest_digest(definition)
    registry_entry_id = Column(Integer, ForeignKey("tool_registry_entries.id", ondelete="SET NULL"))
    first_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True))
    removed_at = Column(DateTime(timezone=True))        # gone from the server's list at the last sync
