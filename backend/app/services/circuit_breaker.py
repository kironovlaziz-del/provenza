# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Chain circuit breaker - OWASP Agentic Top 10, ASI08 (cascading failures).

A delegation chain is one tree of agents working on one task. When any
agent in that tree starts failing - a storm of policy denials, a burst of
incidents, or a runaway loop of attempts - the breaker "trips": the whole
chain goes to status "tripped", an incident is raised, and the policy
engine denies every further action and delegation in the chain.

It never closes by itself: an admin resumes the chain (counting restarts
from that moment) or terminates it.

What is counted inside the window, per chain:
  attempts  - every /actions/check, plus legacy records made without a check
  denials   - the subset of attempts the policy engine denied
  incidents - agent incidents raised on the chain (excluding breaker trips)

Thresholds come from the chain's ROOT agent override, else the organization
setting, else DEFAULTS. A threshold is reached when count >= threshold.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.agent_action import ActionCheck, AgentAction, AgentIncident
from app.models.breaker import AgentBreakerSettings
from app.models.delegation import DelegationChain

TRIP_INCIDENT = "cascade_breaker_tripped"

DEFAULTS = {
    "enabled": True,
    "window_seconds": 300,
    "max_attempts": 200,
    "max_denials": 10,
    "max_incidents": 3,
}

# Guard rails for settings: nothing that trips on the first action, nothing
# so wide it never trips. Also enforced by the Pydantic schema.
BOUNDS = {
    "window_seconds": (30, 86400),
    "max_attempts": (10, 100000),
    "max_denials": (2, 10000),
    "max_incidents": (1, 1000),
}

FIELDS = ("enabled", "window_seconds", "max_attempts", "max_denials", "max_incidents")


def _row_to_cfg(row: AgentBreakerSettings) -> dict:
    return {f: getattr(row, f) for f in FIELDS}


class CircuitBreaker:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------ settings
    async def _row(self, org_id: int, agent_id: Optional[int]) -> Optional[AgentBreakerSettings]:
        cond = AgentBreakerSettings.agent_id.is_(None) if agent_id is None else AgentBreakerSettings.agent_id == agent_id
        return (await self.db.execute(
            select(AgentBreakerSettings).where(AgentBreakerSettings.org_id == org_id, cond)
        )).scalar_one_or_none()

    async def org_config(self, org_id: int) -> dict:
        row = await self._row(org_id, None)
        return {**(_row_to_cfg(row) if row else DEFAULTS), "source": "org" if row else "default"}

    async def effective(self, org_id: int, agent_id: Optional[int]) -> dict:
        if agent_id is not None:
            row = await self._row(org_id, agent_id)
            if row:
                return {**_row_to_cfg(row), "source": "agent"}
        return await self.org_config(org_id)

    async def overrides(self, org_id: int) -> list:
        rows = (await self.db.execute(
            select(AgentBreakerSettings, Agent.name)
            .join(Agent, Agent.id == AgentBreakerSettings.agent_id)
            .where(AgentBreakerSettings.org_id == org_id, AgentBreakerSettings.agent_id.isnot(None))
            .order_by(Agent.name)
        )).all()
        return [{**_row_to_cfg(r), "agent_id": r.agent_id, "agent_name": name} for r, name in rows]

    async def save(self, org_id: int, agent_id: Optional[int], cfg: dict, user_id: int) -> tuple:
        """Upsert settings; returns (before, after) for the audit log."""
        if agent_id is not None:
            ok = (await self.db.execute(
                select(Agent.id).where(Agent.id == agent_id, Agent.org_id == org_id)
            )).scalar_one_or_none()
            if not ok:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        row = await self._row(org_id, agent_id)
        before = _row_to_cfg(row) if row else None
        if row is None:
            row = AgentBreakerSettings(org_id=org_id, agent_id=agent_id)
            self.db.add(row)
        for f in FIELDS:
            setattr(row, f, cfg[f])
        row.updated_by = user_id
        await self.db.commit()
        return before, {f: cfg[f] for f in FIELDS}

    async def delete_override(self, org_id: int, agent_id: int) -> dict:
        row = await self._row(org_id, agent_id)
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No override for this agent")
        before = _row_to_cfg(row)
        await self.db.delete(row)
        await self.db.commit()
        return before

    # ------------------------------------------------------------------ evaluation
    async def _counts(self, chain_id: int, since: datetime) -> dict:
        checks = (await self.db.execute(
            select(func.count(), func.count().filter(ActionCheck.decision == "denied"))
            .where(ActionCheck.chain_id == chain_id, ActionCheck.created_at >= since)
        )).one()
        legacy = (await self.db.execute(
            select(func.count(), func.count().filter(AgentAction.policy_check_result == "denied"))
            .where(AgentAction.chain_id == chain_id, AgentAction.check_id.is_(None),
                   AgentAction.created_at >= since)
        )).one()
        incidents = (await self.db.execute(
            select(func.count()).select_from(AgentIncident).where(
                AgentIncident.chain_id == chain_id, AgentIncident.created_at >= since,
                AgentIncident.incident_type != TRIP_INCIDENT)
        )).scalar_one()
        return {
            "attempts": checks[0] + legacy[0],
            "denials": checks[1] + legacy[1],
            "incidents": incidents,
        }

    async def evaluate(self, org_id: int, chain_id: int) -> Optional[dict]:
        """Trip the chain if a threshold is reached. Returns the trip details
        when it tripped now, else None. Safe to call on every event."""
        chain = (await self.db.execute(
            select(DelegationChain)
            .where(DelegationChain.id == chain_id, DelegationChain.org_id == org_id)
            .with_for_update()
        )).scalar_one_or_none()
        if not chain or chain.status != "active":
            return None
        cfg = await self.effective(org_id, chain.root_agent_id)
        if not cfg["enabled"]:
            return None

        now = datetime.now(timezone.utc)
        since = now - timedelta(seconds=cfg["window_seconds"])
        if chain.breaker_reset_at and chain.breaker_reset_at > since:
            since = chain.breaker_reset_at  # a resumed chain starts counting afresh

        counts = await self._counts(chain.id, since)
        thresholds = {
            "attempts": cfg["max_attempts"],
            "denials": cfg["max_denials"],
            "incidents": cfg["max_incidents"],
        }
        exceeded = [k for k in ("denials", "incidents", "attempts") if counts[k] >= thresholds[k]]
        if not exceeded:
            return None

        details = {
            "exceeded": exceeded,
            "counts": counts,
            "thresholds": thresholds,
            "window_seconds": cfg["window_seconds"],
            "settings_source": cfg["source"],
            "tripped_at": now.isoformat(),
        }
        chain.status = "tripped"
        chain.breaker_tripped_at = now
        chain.breaker_details = details
        self.db.add(AgentIncident(
            org_id=org_id, chain_id=chain.id, agent_id=chain.root_agent_id,
            incident_type=TRIP_INCIDENT, severity="critical", details=details,
        ))
        await self.db.commit()
        return details

    # ------------------------------------------------------------------ operator actions
    async def _chain(self, org_id: int, chain_id: int) -> DelegationChain:
        chain = (await self.db.execute(
            select(DelegationChain).where(DelegationChain.id == chain_id, DelegationChain.org_id == org_id)
        )).scalar_one_or_none()
        if not chain:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delegation chain not found")
        return chain

    async def resume(self, org_id: int, chain_id: int) -> None:
        chain = await self._chain(org_id, chain_id)
        if chain.status != "tripped":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail=f"Only a tripped chain can be resumed (chain is {chain.status})")
        chain.status = "active"
        chain.breaker_reset_at = datetime.now(timezone.utc)
        await self.db.commit()

    async def terminate(self, org_id: int, chain_id: int) -> str:
        chain = await self._chain(org_id, chain_id)
        if chain.status not in ("active", "tripped"):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail=f"Chain is already {chain.status}")
        previous = chain.status
        chain.status = "terminated"
        chain.completed_at = datetime.now(timezone.utc)
        await self.db.commit()
        return previous

    async def breaker_chains(self, org_id: int, limit: int = 50) -> list:
        """Chains that tripped at least once, newest first."""
        rows = (await self.db.execute(
            select(DelegationChain, Agent.name)
            .join(Agent, Agent.id == DelegationChain.root_agent_id)
            .where(DelegationChain.org_id == org_id, DelegationChain.breaker_tripped_at.isnot(None))
            .order_by(DelegationChain.breaker_tripped_at.desc())
            .limit(limit)
        )).all()
        return [
            {
                "id": c.id,
                "root_agent_id": c.root_agent_id,
                "root_agent_name": name,
                "root_task": c.root_task,
                "status": c.status,
                "breaker_tripped_at": c.breaker_tripped_at,
                "breaker_reset_at": c.breaker_reset_at,
                "breaker_details": c.breaker_details,
            }
            for c, name in rows
        ]
