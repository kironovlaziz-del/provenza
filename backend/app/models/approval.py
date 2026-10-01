# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class AgentActionApproval(Base):
    """
    The human decision on an action that required approval (OWASP ASI09,
    and the human-oversight record the EU AI Act asks for): who decided,
    when, and on exactly which arguments (input_sha256 at decision time).
    """

    __tablename__ = "agent_action_approvals"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    action_id = Column(Integer, ForeignKey("agent_actions.id", ondelete="CASCADE"), nullable=False, unique=True)
    decision = Column(String(20), nullable=False)  # approved, denied, expired
    decided_by = Column(Integer, ForeignKey("users.id"))  # NULL for automatic expiry
    decided_at = Column(DateTime(timezone=True), server_default=func.now())
    input_sha256 = Column(String(64), nullable=False)
    reason = Column(Text)
    self_approved = Column(Boolean, nullable=False, default=False)
    typed_confirmation = Column(Boolean, nullable=False, default=False)
    flags = Column(JSONB)  # e.g. ["high_risk_system", "argument_rule", "fatigue"]
