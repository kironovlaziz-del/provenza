# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, func

from app.core.database import Base


class RetentionSettings(Base):
    """Per-organization retention of agent telemetry (services/retention.py)."""

    __tablename__ = "retention_settings"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True)
    # NULL = keep indefinitely. No Python-side default: an explicit None must
    # be stored as NULL, not replaced by 90 (services/retention.py fills a new
    # row's values itself); the database keeps its server default.
    agent_check_retention_days = Column(Integer, server_default="90")      # policy checks
    agent_content_retention_days = Column(Integer, server_default="90")    # agent content
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class RetentionRun(Base):
    """One retention run that changed something (or was started by hand)."""

    __tablename__ = "retention_runs"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    ran_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    trigger = Column(String(20), nullable=False)          # beat, manual
    purged_checks = Column(Integer, nullable=False, default=0)
    scrubbed_content = Column(Integer, nullable=False, default=0)
