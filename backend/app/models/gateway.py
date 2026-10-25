# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class GatewaySettings(Base):
    """Per-organization settings of the LLM gateway."""

    __tablename__ = "gateway_settings"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True)
    enabled = Column(Boolean, nullable=False, default=True)
    rpm_per_agent = Column(Integer, nullable=False, default=60)
    max_tokens_cap = Column(Integer, nullable=False, default=4096)
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class GatewayRoute(Base):
    """Which connection serves a model name. Disabled, never deleted."""

    __tablename__ = "gateway_routes"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    model = Column(String(200), nullable=False)            # exact name or glob ("gpt-4o*")
    provider_id = Column(Integer, ForeignKey("ai_providers.id", ondelete="CASCADE"), nullable=False)
    upstream_model = Column(String(200))                   # name sent upstream; NULL = same as requested
    enabled = Column(Boolean, nullable=False, default=True)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class GatewayCall(Base):
    """One call through the gateway: who, which model, the verdict, tokens and
    latency. What was sent and answered is not kept. A call that reached the
    policy decision is also a PVP action (action_id, executed by the gateway):
    this row keeps the numbers the LLM charts need."""

    __tablename__ = "gateway_calls"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    provider_id = Column(Integer, ForeignKey("ai_providers.id", ondelete="SET NULL"))
    model = Column(String(200))
    status = Column(String(20), nullable=False)   # completed, failed, rate_limited, denied, pending_approval
    reason = Column(String(500))
    flags = Column(JSONB, nullable=False)
    latency_ms = Column(Integer)
    prompt_tokens = Column(Integer)
    completion_tokens = Column(Integer)
    action_id = Column(Integer, ForeignKey("agent_actions.id", ondelete="SET NULL"), index=True)
    chain_id = Column(Integer, ForeignKey("delegation_chains.id", ondelete="SET NULL"))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
