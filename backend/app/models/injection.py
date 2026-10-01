# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class InjectionSettings(Base):
    """Per-organization settings of the prompt-injection guard (OWASP ASI01)."""

    __tablename__ = "injection_settings"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True)
    mode = Column(String(20), nullable=False, default="monitor")  # off, monitor, enforce
    threshold = Column(Integer, nullable=False, default=60)       # score that counts as "injection"
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class InjectionDetection(Base):
    """One suspicious or injected value found in a tool argument or output.

    Only the matched phrase (<= 80 chars) is kept, never the whole value.
    """

    __tablename__ = "injection_detections"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    chain_id = Column(Integer, ForeignKey("delegation_chains.id", ondelete="SET NULL"))
    action_id = Column(Integer)
    detected_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    source = Column(String(20), nullable=False)    # argument, output
    tool_name = Column(String(100))
    path = Column(String(300))
    verdict = Column(String(20), nullable=False)   # suspicious, injection
    score = Column(Integer, nullable=False)
    findings = Column(JSONB, nullable=False)
    outcome = Column(String(20), nullable=False)   # flagged, blocked, tainted, held
