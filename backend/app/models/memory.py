# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class MemorySettings(Base):
    """Per-organization settings of the memory-integrity guard (OWASP ASI06)."""

    __tablename__ = "memory_settings"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True)
    mode = Column(String(20), nullable=False, default="monitor")  # off, monitor, enforce
    shared_namespaces = Column(JSONB, nullable=False)             # globs every agent may write / read
    default_ttl_days = Column(Integer, nullable=False, default=30)
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class MemoryEntry(Base):
    """Attestation of one piece of agent memory.

    The content itself stays in the agent's own store; Provenza keeps its
    SHA-256, where it came from and whether it may be used.
    """

    __tablename__ = "memory_entries"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    chain_id = Column(Integer, ForeignKey("delegation_chains.id", ondelete="SET NULL"))
    namespace = Column(String(200), nullable=False, index=True)
    key = Column(String(200))
    sha256 = Column(String(64), nullable=False, index=True)
    size_bytes = Column(BigInteger, nullable=False, default=0)
    source = Column(String(20), nullable=False)       # user, tool_output, document, agent
    source_ref = Column(String(300))
    status = Column(String(20), nullable=False)       # trusted, quarantined, revoked, rejected
    reasons = Column(JSONB, nullable=False)
    findings = Column(JSONB, nullable=False)
    expires_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    decided_by = Column(Integer, ForeignKey("users.id"))
    decided_at = Column(DateTime(timezone=True))
