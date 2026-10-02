# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, func

from app.core.database import Base


class QueueSettings(Base):
    """Per-organization time limits of the asynchronous request pipeline."""

    __tablename__ = "queue_settings"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True)
    queue_ttl_seconds = Column(Integer, nullable=False, default=900)       # queued -> must start within
    approval_ttl_hours = Column(Integer, nullable=False, default=72)       # pending_approval -> expires after
    raw_prompt_retention_days = Column(Integer)                            # NULL = keep encrypted raw prompts
    agent_check_retention_days = Column(Integer, default=90)               # NULL = keep policy checks
    agent_content_retention_days = Column(Integer, default=90)             # NULL = keep agent/LLM content
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class QueueSweep(Base):
    """One sweep that changed something (or was started by hand)."""

    __tablename__ = "queue_sweeps"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    ran_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    trigger = Column(String(20), nullable=False)          # beat, manual
    expired_queued = Column(Integer, nullable=False, default=0)
    expired_approvals = Column(Integer, nullable=False, default=0)
    failed_stuck = Column(Integer, nullable=False, default=0)
    purged_prompts = Column(Integer, nullable=False, default=0)
    purged_checks = Column(Integer, nullable=False, default=0)
    scrubbed_content = Column(Integer, nullable=False, default=0)
