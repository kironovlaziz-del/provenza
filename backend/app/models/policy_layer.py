# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""One level of the policy hierarchy (core/policy_doc.py, services/hier_policy.py)."""

from sqlalchemy import CheckConstraint, Column, DateTime, ForeignKey, Index, Integer, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class PolicyLayer(Base):
    """The organization's policy (scope "org"), a team's ("team") or an
    agent's ("agent"). `document` is the validated policy; `source_yaml`
    is what the admin wrote (kept so the YAML tab shows their text and
    comments). Never deleted: clearing a level empties its document, and
    every change is in the audit log with the document before and after."""

    __tablename__ = "policy_layers"
    __table_args__ = (
        CheckConstraint("scope IN ('org', 'team', 'agent')", name="ck_policy_layers_scope"),
        CheckConstraint("(scope = 'team') = (team_id IS NOT NULL) AND (scope = 'agent') = (agent_id IS NOT NULL)",
                        name="ck_policy_layers_target"),
        Index("uq_policy_layers_org", "org_id", unique=True, postgresql_where=text("scope = 'org'")),
        Index("uq_policy_layers_team", "team_id", unique=True, postgresql_where=text("scope = 'team'")),
        Index("uq_policy_layers_agent", "agent_id", unique=True, postgresql_where=text("scope = 'agent'")),
    )

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    scope = Column(String(10), nullable=False)
    team_id = Column(Integer, ForeignKey("teams.id"))
    agent_id = Column(Integer, ForeignKey("agents.id"))
    document = Column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    source_yaml = Column(Text)
    revision = Column(Integer, nullable=False, server_default="1")
    updated_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
