# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class Team(Base):
    """A team inside an organization: org -> team (-> sub-team) -> agent.
    Agents belong to a team by id (agents.team_id), not by a free-text name."""

    __tablename__ = "teams"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_teams_org_name"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    parent_id = Column(Integer, ForeignKey("teams.id"))
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class RoleTemplate(Base):
    """A named set of rights for agents - capabilities, tools, models,
    delegation depth, key requirements. Org-wide (team_id NULL) or owned by a
    team. Agents enrolled with a role get exactly its rights, and keep them in
    step: changing the role changes every agent that has it."""

    __tablename__ = "role_templates"
    __table_args__ = (
        # one name per team, and one per organization for org-wide roles
        Index("uq_role_templates_team_name", "org_id", "team_id", "name", unique=True,
              postgresql_where=text("team_id IS NOT NULL")),
        Index("uq_role_templates_org_name", "org_id", "name", unique=True, postgresql_where=text("team_id IS NULL")),
    )

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    team_id = Column(Integer, ForeignKey("teams.id"))
    name = Column(String(100), nullable=False)
    description = Column(Text)
    capabilities = Column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    allowed_tools = Column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    allowed_models = Column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    max_delegation_depth = Column(Integer, nullable=False, default=3, server_default=text("3"))
    require_hybrid = Column(Boolean, nullable=False, default=False, server_default=text("false"))
    # enforced by attestation (phase E): agents of this role must prove where they run
    require_attestation = Column(Boolean, nullable=False, default=False, server_default=text("false"))
    # where agents of this role must prove they run (models/attestation.py)
    attestation_policy_id = Column(Integer, ForeignKey("attestation_policies.id"))
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
