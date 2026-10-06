# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class AgentEnrollment(Base):
    """A one-time enrollment token issued by an admin (services/enrollment.py).

    purpose "new":   a new agent; its rights come from this template, never
                     from the agent's request.
    purpose "rekey": a new signing key for an existing agent (agent_id) whose
                     old key is lost or revoked.
    Either way the agent proves possession of its new key by signing a fresh
    server challenge. Only the token's hash is stored.
    """

    __tablename__ = "agent_enrollments"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    purpose = Column(String(10), nullable=False, default="new")  # new | rekey
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    token_prefix = Column(String(20), nullable=False)  # shown in lists to tell tokens apart
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True))
    used_at = Column(DateTime(timezone=True))
    # rekey: the agent to re-key; new: the agent created by the enrollment
    agent_id = Column(Integer, ForeignKey("agents.id"))

    # template - what the new agent may do (purpose "new")
    name = Column(String(255))           # None: the agent names itself
    description = Column(Text)
    agent_type = Column(String(50))
    owner_team = Column(String(100))
    team_id = Column(Integer, ForeignKey("teams.id"))
    role_id = Column(Integer, ForeignKey("role_templates.id"))
    capabilities = Column(JSONB)
    allowed_tools = Column(JSONB)
    allowed_models = Column(JSONB)
    max_delegation_depth = Column(Integer, nullable=False, default=3)
    require_hybrid = Column(Boolean, nullable=False, default=False)
    discovered_agent_id = Column(Integer, ForeignKey("discovered_agents.id", ondelete="SET NULL"))

    # proof of possession: one fresh challenge at a time, single use
    challenge = Column(String(64))
    challenge_expires_at = Column(DateTime(timezone=True))
    failed_attempts = Column(Integer, nullable=False, default=0)
