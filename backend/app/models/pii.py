# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""PII rules of the prompt firewall (services/pii_rules.py)."""

from sqlalchemy import (Boolean, CheckConstraint, Column, DateTime, ForeignKey, Index, Integer, String, Text, func,
                        text)
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class PiiSettings(Base):
    """Which built-in detectors run and what they do. `builtin` maps a type
    (EMAIL, CREDIT_CARD, ...) to {"enabled": bool, "action": "mask"|"block"};
    a type not listed keeps its default (on, mask)."""

    __tablename__ = "pii_settings"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True)
    builtin = Column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    revision = Column(Integer, nullable=False, server_default="1")
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class PiiRule(Base):
    """An organization's own pattern (a contract number, a tax id, ...).
    Never deleted: removing a rule sets deleted_at, and every change is in
    the audit log."""

    __tablename__ = "pii_rules"
    __table_args__ = (
        CheckConstraint("action IN ('mask', 'block')", name="ck_pii_rules_action"),
        Index("uq_pii_rules_label", "org_id", "label", unique=True, postgresql_where=text("deleted_at IS NULL")),
    )

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    label = Column(String(32), nullable=False)          # [MASKED:LABEL]
    description = Column(Text)
    pattern = Column(Text, nullable=False)
    ignore_case = Column(Boolean, nullable=False, server_default="false")
    action = Column(String(10), nullable=False, server_default="mask")
    enabled = Column(Boolean, nullable=False, server_default="true")
    revision = Column(Integer, nullable=False, server_default="1")
    # times the rule ran out of time on a prompt (the prompt was refused)
    timeouts = Column(Integer, nullable=False, server_default="0")
    last_timeout_at = Column(DateTime(timezone=True))
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    deleted_at = Column(DateTime(timezone=True))
