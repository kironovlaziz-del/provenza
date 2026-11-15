# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class TaskMandate(Base):
    """
    A task a person gave an agent, signed (app/services/task_mandates.py,
    docs/proof-of-authority.md): what the agent is to do, which of its tools
    it may use for it, and until when - signed with the person's session key,
    which their passkey certified. An action that names it carries it into its
    evidence, so Proof of Authority starts with the person who asked.
    """

    __tablename__ = "task_mandates"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    task = Column(Text, nullable=False)
    tools = Column(JSONB(none_as_null=True))           # None: all of the agent's tools
    expires_at = Column(DateTime(timezone=True), nullable=False)
    status = Column(String(12), nullable=False, default="active")   # active, ended
    # the signed statement and its proof (signing_sessions.verify_signed), and
    # SHA-256 of the canonical statement - what an action's evidence names
    signed = Column(JSONB, nullable=False)
    statement_sha256 = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    ended_at = Column(DateTime(timezone=True))
    ended_by = Column(Integer, ForeignKey("users.id"))
