# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class A2ASettings(Base):
    """Per-organization settings of agent-to-agent message security (OWASP ASI07)."""

    __tablename__ = "a2a_settings"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True)
    mode = Column(String(20), nullable=False, default="monitor")      # off, monitor, enforce
    allow_same_chain = Column(Boolean, nullable=False, default=True)  # members of one chain may talk
    max_age_seconds = Column(Integer, nullable=False, default=300)    # envelope freshness
    message_ttl_seconds = Column(Integer, nullable=False, default=3600)  # how long it may be received
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class A2AChannel(Base):
    """An explicitly allowed route between two agents. Disabled, never deleted."""

    __tablename__ = "a2a_channels"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    from_agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    to_agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    bidirectional = Column(Boolean, nullable=False, default=False)
    enabled = Column(Boolean, nullable=False, default=True)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    disabled_by = Column(Integer, ForeignKey("users.id"))
    disabled_at = Column(DateTime(timezone=True))


class A2AMessage(Base):
    """Attestation of one signed agent-to-agent message (the payload itself is not kept)."""

    __tablename__ = "a2a_messages"
    __table_args__ = (
        # replay protection: a nonce is accepted once per sender
        UniqueConstraint("org_id", "from_agent_id", "nonce", name="uq_a2a_nonce"),
    )

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    from_agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    to_agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    chain_id = Column(Integer, ForeignKey("delegation_chains.id", ondelete="SET NULL"))
    message_type = Column(String(50))
    payload_sha256 = Column(String(64))
    nonce = Column(String(128))          # NULL on rejected rows, so a rejected nonce cannot block a valid one
    issued_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    signature_valid = Column(Boolean, nullable=False, default=False)
    status = Column(String(20), nullable=False)   # accepted, quarantined, rejected
    reasons = Column(JSONB, nullable=False)
    findings = Column(JSONB, nullable=False)
    consumed_at = Column(DateTime(timezone=True))
    receive_attempts = Column(Integer, nullable=False, default=0)
