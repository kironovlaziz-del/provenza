# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class CodeExecSettings(Base):
    """Per-organization settings of the code-execution guard (OWASP ASI05)."""

    __tablename__ = "code_exec_settings"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True)
    mode = Column(String(20), nullable=False, default="monitor")      # off, monitor, enforce
    code_tools = Column(JSONB, nullable=False)                         # glob patterns of tools that run code
    approve_code_tools = Column(Boolean, nullable=False, default=True)  # enforce: every code-tool call is reviewed
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class CodeExecDetection(Base):
    """One tool call whose arguments looked like code to execute.

    Only the matched fragment (<= 80 chars) is kept, never the whole argument.
    """

    __tablename__ = "code_exec_detections"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    chain_id = Column(Integer, ForeignKey("delegation_chains.id", ondelete="SET NULL"))
    detected_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    tool_name = Column(String(100))
    code_tool = Column(Boolean, nullable=False, default=False)
    severity = Column(String(20), nullable=False)   # none (code tool, clean), medium, high, critical
    findings = Column(JSONB, nullable=False)
    outcome = Column(String(20), nullable=False)    # flagged, held, blocked
