# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Blocked terms: the one place they are kept (services/blocked_terms.py)."""

from sqlalchemy import (Boolean, CheckConstraint, Column, DateTime, ForeignKey, Index, Integer, String, Text, func,
                        text)

from app.core.database import Base


class BlockedTermCategory(Base):
    """A group of terms (projects, clients, confidential...) switched on or
    off together."""

    __tablename__ = "blocked_term_categories"
    __table_args__ = (Index("uq_blocked_term_categories_name", "org_id", "name", unique=True),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    enabled = Column(Boolean, nullable=False, server_default="true")
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class BlockedTerm(Base):
    """One term and where it applies:
        org      everything: the gateway, user AI requests, the playground
        agents   every agent's gateway calls
        team     gateway calls of the team's agents and of its sub-teams' agents
        agent    one agent's gateway calls
        policy   user requests of use cases governed by that policy, and the
                 playground while the policy is active
    `key` is the term reduced for matching (core/term_match.py). Never
    deleted: removing sets deleted_at, every change is in the audit log."""

    __tablename__ = "blocked_terms"
    __table_args__ = (
        CheckConstraint("scope IN ('org', 'agents', 'team', 'agent', 'policy')", name="ck_blocked_terms_scope"),
        # removed terms may lose their team (a team can be deleted once no live term names it)
        CheckConstraint("deleted_at IS NOT NULL OR ((scope = 'team') = (team_id IS NOT NULL) AND (scope = 'agent') = "
                        "(agent_id IS NOT NULL) AND (scope = 'policy') = (policy_id IS NOT NULL))",
                        name="ck_blocked_terms_target"),
        CheckConstraint("match IN ('word', 'substring')", name="ck_blocked_terms_match"),
        CheckConstraint("action IN ('block', 'monitor')", name="ck_blocked_terms_action"),
        Index("uq_blocked_terms_live", "org_id", "scope", text("coalesce(team_id, agent_id, policy_id, 0)"), "key",
              unique=True, postgresql_where=text("deleted_at IS NULL")),
    )

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    term = Column(String(200), nullable=False)
    key = Column(String(400), nullable=False)
    match = Column(String(10), nullable=False, server_default="word")
    action = Column(String(10), nullable=False, server_default="block")
    scope = Column(String(10), nullable=False, server_default="org")
    team_id = Column(Integer, ForeignKey("teams.id", ondelete="SET NULL"))
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="SET NULL"))
    policy_id = Column(Integer, ForeignKey("ai_policies.id", ondelete="SET NULL"))
    category_id = Column(Integer, ForeignKey("blocked_term_categories.id", ondelete="SET NULL"))
    enabled = Column(Boolean, nullable=False, server_default="true")
    note = Column(Text)
    hits = Column(Integer, nullable=False, server_default="0")
    last_hit_at = Column(DateTime(timezone=True))
    source = Column(String(40))  # where a migrated term came from: gateway, policy:3, layer:team:5 ...
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    deleted_at = Column(DateTime(timezone=True))
