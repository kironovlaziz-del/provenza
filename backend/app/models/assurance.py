# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza - https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Column, Date, DateTime, ForeignKey, Integer, String, Text, func

from app.core.database import Base


class AssuranceRecord(Base):
    """A test an AI system went through - an evaluation of its quality, a bias
    test, red teaming, a robustness test - recorded with who did it, when, the
    result and the evidence. Provenza does not run the tests; it keeps the
    record an auditor asks for (EU AI Act Art. 15, NIST AI RMF MEASURE).

    Records are never edited or deleted: a correction is a new record.
    """

    __tablename__ = "ai_assurance_records"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    system_id = Column(Integer, ForeignKey("ai_systems.id", ondelete="CASCADE"), nullable=False, index=True)
    kind = Column(String(20), nullable=False)          # evaluation, bias, red_team, robustness
    title = Column(String(255), nullable=False)
    performed_on = Column(Date, nullable=False)
    performed_by = Column(String(255))                 # a team, a person, an outside firm
    result = Column(String(30), nullable=False)        # passed, passed_with_findings, failed
    summary = Column(Text)
    findings = Column(Text)
    evidence_url = Column(String(500))
    next_due = Column(Date)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
