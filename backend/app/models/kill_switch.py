# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""A kill-switch decision and its undo (services/kill_switch.py)."""

from sqlalchemy import CheckConstraint, Column, DateTime, ForeignKey, Index, Integer, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class KillSwitchEvent(Base):
    """One stop: an agent, a team (with its sub-teams), every agent of the
    organization, or all of its AI traffic (every agent, the gateway and
    AI requests).

    `stopped` records exactly what this decision changed, so lifting it
    gives back that and nothing more:
        agents:   [{"id", "name", "status"}]  agents it suspended, with the status they had
        chains:   [id]                        delegation chains it terminated (they stay terminated)
        team_ids: [id]                        the team and its sub-teams at the time (scope team)
    While the event is active, whatever it covers stays stopped: an agent
    created in its scope starts suspended and is added to `agents`, and an
    agent it covers cannot be switched back on by hand.
    `lift_result` says what lifting did: restored, kept (still held by
    another active stop, which now restores it) and skipped (changed since)."""

    __tablename__ = "kill_switch_events"
    __table_args__ = (
        CheckConstraint("scope IN ('agent', 'team', 'all_agents', 'org_traffic')", name="ck_kill_switch_scope"),
        Index("ix_kill_switch_active", "org_id", postgresql_where=text("lifted_at IS NULL")),
    )

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    scope = Column(String(12), nullable=False)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="SET NULL"))
    team_id = Column(Integer, ForeignKey("teams.id", ondelete="SET NULL"))
    target_name = Column(String(255))  # kept when the team is gone
    reason = Column(Text, nullable=False)
    stopped = Column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    lifted_at = Column(DateTime(timezone=True))
    lifted_by = Column(Integer, ForeignKey("users.id"))
    lift_reason = Column(Text)
    lift_result = Column(JSONB)
