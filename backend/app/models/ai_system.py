# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from app.core.database import Base


class AISystem(Base):
    """
    One entry in the AI Inventory: a model, agent, LLM provider, RAG app or
    detected shadow-AI tool, with an owner, a lifecycle stage and an EU AI
    Act risk tier (suggested by the classifier, confirmed by a human).

    Entries discovered from other modules carry a stable source_key
    ("agent:12", "provider:3", "shadow:chatgpt", ...) so syncing is
    idempotent; manually created entries have no source_key.
    """

    __tablename__ = "ai_systems"
    __table_args__ = (UniqueConstraint("org_id", "source_key", name="uq_ai_system_source"),)

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    kind = Column(String(30), nullable=False, default="other")  # agent, llm_provider, model, rag_app, shadow, other
    source_key = Column(String(120))

    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="SET NULL"))
    provider_id = Column(Integer, ForeignKey("ai_providers.id", ondelete="SET NULL"))
    deployment_id = Column(Integer, ForeignKey("model_deployments.id", ondelete="SET NULL"))
    use_case_id = Column(Integer, ForeignKey("ai_use_cases.id", ondelete="SET NULL"))
    shadow_tool = Column(String(255))

    owner_user_id = Column(Integer, ForeignKey("users.id"))
    business_owner = Column(String(255))

    lifecycle_stage = Column(String(20), nullable=False, default="idea")  # idea, development, validation, production, retired
    review_status = Column(String(20), nullable=False, default="unreviewed")  # unreviewed, reviewed

    domain = Column(String(50), nullable=False, default="general")
    risk_flags = Column(JSONB, nullable=False, default=list)
    suggested_risk_tier = Column(String(20))
    risk_assessment = Column(JSONB)  # classifier output: tier, rationale, notes, engine_version
    confirmed_risk_tier = Column(String(20))
    risk_justification = Column(Text)
    risk_confirmed_by = Column(Integer, ForeignKey("users.id"))
    risk_confirmed_at = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    data_links = relationship(
        "AISystemDataLink", cascade="all, delete-orphan", lazy="selectin",
        order_by="AISystemDataLink.id",
    )

    @property
    def effective_risk_tier(self):
        return self.confirmed_risk_tier or self.suggested_risk_tier

    @property
    def attention(self):
        out = []
        if self.review_status != "reviewed":
            out.append("unreviewed")
        if self.lifecycle_stage == "production" and not self.confirmed_risk_tier:
            out.append("in_production_without_confirmed_risk")
        if self.lifecycle_stage == "production" and self.effective_risk_tier == "unacceptable":
            out.append("unacceptable_in_production")
        return out

    @property
    def data_protection_notes(self):
        if any(link.contains_pii for link in (self.data_links or [])):
            return ["Processes personal data: GDPR applies and a DPIA (GDPR Art. 35) may be required."]
        return []


class AISystemDataLink(Base):
    """Which data an AI system was trained on or can access. Exactly one of
    dataset_id / collection_id / external_name identifies the data."""

    __tablename__ = "ai_system_data_links"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    system_id = Column(Integer, ForeignKey("ai_systems.id", ondelete="CASCADE"), nullable=False, index=True)
    relation = Column(String(20), nullable=False)  # trained_on, accesses
    dataset_id = Column(Integer, ForeignKey("datasets.id", ondelete="CASCADE"))
    collection_id = Column(Integer, ForeignKey("document_collections.id", ondelete="CASCADE"))
    external_name = Column(String(255))
    contains_pii = Column(Boolean, nullable=False, default=False)
    notes = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
