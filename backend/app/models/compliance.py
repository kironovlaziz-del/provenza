# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class ComplianceAttestation(Base):
    """A person's statement about a requirement Provenza cannot check from its
    own data (technical documentation, DPIA, AI literacy...). Never edited:
    a new statement supersedes the previous one, the history stays."""

    __tablename__ = "compliance_attestations"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    requirement_id = Column(String(60), nullable=False, index=True)
    system_id = Column(Integer, ForeignKey("ai_systems.id", ondelete="CASCADE"))   # NULL = organization-wide
    status = Column(String(20), nullable=False)          # met, not_met, not_applicable
    note = Column(Text)
    evidence_url = Column(String(500))
    attested_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    attested_at = Column(DateTime(timezone=True), server_default=func.now())
    valid_until = Column(DateTime(timezone=True))


class ComplianceReport(Base):
    """An immutable snapshot of the compliance evaluation, for an auditor.
    sha256 covers the canonical JSON of `content`."""

    __tablename__ = "compliance_reports"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    frameworks = Column(JSONB, nullable=False)
    summary = Column(JSONB, nullable=False)
    content = Column(JSONB, nullable=False)
    sha256 = Column(String(64), nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
