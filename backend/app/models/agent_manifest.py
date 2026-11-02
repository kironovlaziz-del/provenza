# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Column, DateTime, ForeignKey, Integer, LargeBinary, String, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class AgentManifestRecord(Base):
    """An Agent Manifest (AgenTrust Agent Manifest v0.2) Provenza issued for an
    agent: the signed COSE envelope as it was handed out, and its payload for
    display. A new one is issued when what it binds changes; it names the one
    before it (previous_manifest_id). See app/services/agent_manifest.py."""

    __tablename__ = "agent_manifests"

    id = Column(Integer, primary_key=True)
    manifest_id = Column(String(36), nullable=False, unique=True)   # UUID v7
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    previous_manifest_id = Column(String(36))
    content_hash = Column(String(64), nullable=False)   # what it binds, without times and ids
    payload = Column(JSONB, nullable=False)             # the signed manifest document
    envelope = Column(LargeBinary, nullable=False)      # COSE_Sign / COSE_Sign1 bytes
    key_fingerprint = Column(String(80), nullable=False)
    issued_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    issued_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
