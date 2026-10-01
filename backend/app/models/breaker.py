# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Index, Integer, UniqueConstraint, func, text,
)

from app.core.database import Base


class AgentBreakerSettings(Base):
    """
    Circuit-breaker thresholds (OWASP ASI08 - cascading agent failures).

    One row with agent_id = NULL holds the organization default; rows with
    an agent_id override it for chains rooted at that agent. When no row
    exists the built-in defaults in services/circuit_breaker.py apply.
    """

    __tablename__ = "agent_breaker_settings"
    __table_args__ = (
        UniqueConstraint("org_id", "agent_id", name="uq_breaker_org_agent"),
        Index("uq_breaker_org_default", "org_id", unique=True, postgresql_where=text("agent_id IS NULL")),
    )

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"))
    enabled = Column(Boolean, nullable=False, default=True)
    window_seconds = Column(Integer, nullable=False)
    max_attempts = Column(Integer, nullable=False)
    max_denials = Column(Integer, nullable=False)
    max_incidents = Column(Integer, nullable=False)
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
