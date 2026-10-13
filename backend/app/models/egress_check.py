# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class AgentEgressCheck(Base):
    """One check of an agent host's network (app/services/egress_check.py):
    the targets it had to fail to reach, the beacon only this server can see
    being reached, and the verdict."""

    __tablename__ = "agent_egress_checks"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    token = Column(String(64), nullable=False, unique=True)      # in the beacon URL
    targets = Column(JSONB, nullable=False)                      # ["host:port", ...]
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    beacon_hit_at = Column(DateTime(timezone=True))              # seen by this server: the host is open
    beacon_ip = Column(String(64))
    reported_at = Column(DateTime(timezone=True))
    results = Column(JSONB)                                      # [{"target", "reachable"}], signed by the agent
    verdict = Column(String(20), nullable=False, default="pending")   # pending | confined | open
