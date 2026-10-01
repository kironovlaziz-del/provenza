# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class AgentBaseline(Base):
    """Behavioural baseline of one agent (OWASP ASI10 - rogue agents),
    recomputed lazily from its own history."""

    __tablename__ = "agent_baselines"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, unique=True)
    computed_at = Column(DateTime(timezone=True))
    window_days = Column(Integer, nullable=False, default=14)
    sample_count = Column(Integer, nullable=False, default=0)
    span_days = Column(Float, nullable=False, default=0)
    tools = Column(JSONB)                 # {"db.read": 120, ...}
    hours = Column(JSONB)                 # 24 counts, UTC hour of day
    p95_per_5min = Column(Float, nullable=False, default=0)
    denial_rate = Column(Float, nullable=False, default=0)
    mature = Column(Boolean, nullable=False, default=False)
    quarantine_released_at = Column(DateTime(timezone=True))


class AgentAnomaly(Base):
    """One detected deviation from an agent's baseline."""

    __tablename__ = "agent_anomalies"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    detected_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    tool_name = Column(String(100))
    score = Column(Integer, nullable=False)
    signals = Column(JSONB, nullable=False)  # {"rate_spike": {...}, "new_tool": {...}}
    outcome = Column(String(20), nullable=False)  # flagged, quarantined


class BehaviorSettings(Base):
    """Per-organization settings of the behaviour monitor."""

    __tablename__ = "behavior_settings"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True)
    mode = Column(String(20), nullable=False, default="monitor")  # off, monitor, enforce
    threshold = Column(Integer, nullable=False, default=60)
    min_samples = Column(Integer, nullable=False, default=50)
    baseline_days = Column(Integer, nullable=False, default=14)
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
