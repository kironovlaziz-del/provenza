# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class A2APeer(Base):
    """
    A remote A2A agent that the organization's agents reach only through
    Provenza's A2A gateway (app/pvp/a2a_gateway.py). Agents see a card that
    points at Provenza and asks for their own key; the peer's address and
    credentials stay here (the secret encrypted, core/crypto).

    The card is pinned like an MCP tool: approval lives in the Tool Registry
    entry "a2a.<slug>" (pinned digest of the card), so a peer whose card
    changed - new skills, another endpoint - is refused until re-approved.
    """

    __tablename__ = "a2a_peers"
    __table_args__ = (UniqueConstraint("org_id", "slug", name="uq_a2a_peers_slug"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    slug = Column(String(40), nullable=False)          # policies name the peer "a2a.<slug>"
    name = Column(String(255), nullable=False)
    card_url = Column(String(500), nullable=False)     # where the peer's agent card is fetched
    auth_header = Column(String(100), nullable=False, default="Authorization")
    auth_secret_encrypted = Column(Text)
    # where the credential lives: none, sealed (to egress proxies), local (a proxy's configuration);
    # auth_secret_encrypted is kept only until it is sealed (POST /egress/credentials/seal-legacy)
    credential_source = Column(String(10), nullable=False, default="none", server_default="none")
    enabled = Column(Boolean, nullable=False, default=True)
    timeout_seconds = Column(Integer, nullable=False, default=60)
    card = Column(JSONB)                               # as last synced (signatures removed)
    card_digest = Column(String(64))
    endpoint_url = Column(String(500))                 # the JSON-RPC interface the card declares
    protocol_version = Column(String(10))              # "1.0" or "0.3", from the card
    registry_entry_id = Column(Integer, ForeignKey("tool_registry_entries.id", ondelete="SET NULL"))
    last_synced_at = Column(DateTime(timezone=True))
    last_error = Column(Text)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class A2ATask(Base):
    """Which agent created which task at a peer. GetTask / CancelTask and
    follow-up messages are allowed only to that agent: a task id is a
    name, not a capability (A2A 1.0, section 13.1)."""

    __tablename__ = "a2a_tasks"
    __table_args__ = (UniqueConstraint("peer_id", "task_id", name="uq_a2a_tasks_task"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    peer_id = Column(Integer, ForeignKey("a2a_peers.id", ondelete="CASCADE"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    task_id = Column(String(200), nullable=False)
    context_id = Column(String(200))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
