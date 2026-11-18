# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Rule packs (services/rule_packs.py): ready-made policy documents an
administrator applies to a level of the policy hierarchy, and a record of
each application so it can be undone."""

from sqlalchemy import CheckConstraint, Column, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class PolicyPack(Base):
    """An organization's own pack. The built-in ones live in code
    (services/rule_packs_builtin.py) and are never stored. `kind`: a
    "profile" is a whole policy for a level and replaces it; a "guard" only
    adds restrictions to it (deny, approval, lower limits)."""

    __tablename__ = "policy_packs"
    __table_args__ = (
        CheckConstraint("kind IN ('profile', 'guard')", name="ck_policy_packs_kind"),
        CheckConstraint("level IN ('org', 'team', 'agent', 'any')", name="ck_policy_packs_level"),
        Index("uq_policy_packs_name", "org_id", "name", unique=True),
    )

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    kind = Column(String(10), nullable=False)
    level = Column(String(10), nullable=False, server_default="any")
    document = Column(JSONB, nullable=False)
    source_yaml = Column(Text, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class PolicyPackApplication(Base):
    """A pack applied to one level. `delta` says what a guard added (so its
    undo takes out exactly that); `previous` is the level a profile replaced
    (so its undo puts it back); `applied` is the level's document right
    after, to tell whether it was edited since."""

    __tablename__ = "policy_pack_applications"
    __table_args__ = (
        CheckConstraint("scope IN ('org', 'team', 'agent')", name="ck_policy_pack_applications_scope"),
    )

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    pack_ref = Column(String(120), nullable=False)       # "builtin:<slug>" or "own:<id>"
    pack_name = Column(String(100), nullable=False)
    kind = Column(String(10), nullable=False)
    scope = Column(String(10), nullable=False)
    team_id = Column(Integer, ForeignKey("teams.id", ondelete="CASCADE"))
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"))
    delta = Column(JSONB)
    previous = Column(JSONB)
    applied = Column(JSONB, nullable=False)
    revision = Column(Integer, nullable=False)          # the level's revision the application wrote
    applied_by = Column(Integer, ForeignKey("users.id"))
    applied_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    undone_by = Column(Integer, ForeignKey("users.id"))
    undone_at = Column(DateTime(timezone=True))
