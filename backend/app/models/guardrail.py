# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class GuardrailSettings(Base):
    """An organization's intent classifier (app/services/guardrail.py): a model
    on one of its own connections reads each prompt - already masked by the
    Prompt Firewall - and says whether it asks for something the organization
    forbids, whatever the words."""

    __tablename__ = "guardrail_settings"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True)
    enabled = Column(Boolean, nullable=False, server_default="false")
    provider_id = Column(Integer, ForeignKey("ai_providers.id", ondelete="SET NULL"))
    model = Column(String(200), nullable=False, server_default="llama-guard3")
    kind = Column(String(20), nullable=False, server_default="llama_guard")    # llama_guard | instruct
    mode = Column(String(10), nullable=False, server_default="monitor")        # monitor | enforce
    on_error = Column(String(10), nullable=False, server_default="allow")      # allow | block
    categories = Column(JSONB, nullable=False, server_default="[]")            # instruct: [{code, description}]
    blocked_categories = Column(JSONB, nullable=False, server_default="[]")    # codes that block; [] = all
    timeout_ms = Column(Integer, nullable=False, server_default="4000")
    surfaces = Column(JSONB, nullable=False, server_default='["playground", "gateway", "requests"]')
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
