# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza - https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class ImpactAssessment(Base):
    """One version of an AI system's impact assessment: one questionnaire
    (services/impact_assessment.TEMPLATE) that serves as the ISO/IEC 42005
    impact assessment, the GDPR Art. 35 DPIA and the EU AI Act Art. 27
    fundamental rights impact assessment.

    A system has at most one draft, edited in place. Approving it freezes it:
    an approved version is never changed - the next change starts a new
    draft, the next version - so the history of what was decided stays.
    """

    __tablename__ = "ai_impact_assessments"
    __table_args__ = (UniqueConstraint("system_id", "version", name="uq_impact_assessment_version"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    system_id = Column(Integer, ForeignKey("ai_systems.id", ondelete="CASCADE"), nullable=False, index=True)
    version = Column(Integer, nullable=False)
    status = Column(String(20), nullable=False, default="draft")  # draft, approved
    template_version = Column(String(20), nullable=False)
    answers = Column(JSONB, nullable=False, default=dict)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    approved_by = Column(Integer, ForeignKey("users.id"))
    approved_at = Column(DateTime(timezone=True))
    review_due = Column(DateTime(timezone=True))
