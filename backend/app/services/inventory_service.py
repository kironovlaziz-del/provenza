# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
AI Inventory: one registry of every AI system in the organization.

The registry stays current without manual data entry: sync() discovers
agents, LLM providers and active shadow-AI sightings that have no
inventory entry yet and creates one (review_status="unreviewed"). It is
idempotent (unique source_key per org) and cheap enough to run whenever
the inventory is listed.

Two governance rules are enforced here, not in the UI:
  - a system can move to production only after a human confirmed its risk tier
  - a system confirmed as "unacceptable" (EU AI Act Art. 5) can never go to production
"""

import re
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.agent_action import AgentAction, AgentIncident
from app.models.ai_provider import AIProvider
from app.models.ai_request import AIRequest
from app.models.ai_system import AISystem, AISystemDataLink
from app.models.ai_use_case import AIUseCase
from app.models.shadow_ai_sighting import ShadowAISighting
from app.models.user import User
from app.services.risk_classifier import classify

ACTIVE_SHADOW_STATUSES = ("new", "reviewing", "confirmed_shadow")
INACTIVE_SOURCE_STATUSES = ("retired", "inactive", "disabled", "archived", "deleted", "stopped")

# Trust-signal thresholds (hints for a reviewer, not verdicts)
HIGH_RATE_THRESHOLD = 0.10
MIN_EVENTS_FOR_RATE = 10


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")[:100] or "unknown"


def _stage_for(source_status: Optional[str]) -> str:
    # Something that already runs IS in production - even if nobody assessed it.
    # That gap is exactly what the "attention" flags surface.
    return "retired" if (source_status or "").lower() in INACTIVE_SOURCE_STATUSES else "production"



class InventoryService:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _classify(system: AISystem) -> None:
        result = classify(system.domain, system.risk_flags or [])
        system.suggested_risk_tier = result.tier
        system.risk_assessment = result.as_dict()

    async def _check_refs(self, org_id: int, values: dict) -> None:
        if values.get("owner_user_id") is not None:
            ok = (await self.db.execute(
                select(User.id).where(User.id == values["owner_user_id"], User.org_id == org_id)
            )).scalar_one_or_none()
            if not ok:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Owner user not found")
        if values.get("use_case_id") is not None:
            ok = (await self.db.execute(
                select(AIUseCase.id).where(AIUseCase.id == values["use_case_id"], AIUseCase.org_id == org_id)
            )).scalar_one_or_none()
            if not ok:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Use case not found")

    async def get(self, system_id: int, org_id: int) -> AISystem:
        system = (await self.db.execute(
            select(AISystem)
            .where(AISystem.id == system_id, AISystem.org_id == org_id)
            .execution_options(populate_existing=True)
        )).scalar_one_or_none()
        if not system:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI system not found")
        return system

    # ------------------------------------------------------------------ discovery
    async def _candidates(self, org_id: int) -> List[dict]:
        out: List[dict] = []

        for a in (await self.db.execute(select(Agent).where(Agent.org_id == org_id))).scalars():
            out.append(dict(
                source_key=f"agent:{a.id}", kind="agent", name=a.name, description=a.description,
                agent_id=a.id, owner_user_id=a.owner_user_id, business_owner=a.owner_team,
                lifecycle_stage=_stage_for(a.status),
            ))

        for p in (await self.db.execute(select(AIProvider).where(AIProvider.org_id == org_id))).scalars():
            out.append(dict(
                source_key=f"provider:{p.id}", kind="llm_provider", name=p.name,
                description=f"LLM provider connection ({p.type})", provider_id=p.id,
                lifecycle_stage=_stage_for(p.status),
            ))

        seen = set()
        for s in (await self.db.execute(
            select(ShadowAISighting)
            .where(
                ShadowAISighting.org_id == org_id,
                ShadowAISighting.status.in_(ACTIVE_SHADOW_STATUSES),
                ShadowAISighting.registered_provider_id.is_(None),
            )
            .order_by(ShadowAISighting.id)
        )).scalars():
            key = f"shadow:{_slug(s.tool_name)}"
            if key in seen:
                continue
            seen.add(key)
            out.append(dict(
                source_key=key, kind="shadow", name=s.tool_name, shadow_tool=s.tool_name,
                description=f"Unsanctioned AI tool detected via {s.detected_via or 'unknown'}",
                lifecycle_stage="production",
            ))
        return out

    async def sync(self, org_id: int) -> List[dict]:
        """Create inventory entries for discovered systems that have none.
        Returns [{id, source_key, name}] of created entries."""
        existing = set((await self.db.execute(
            select(AISystem.source_key).where(AISystem.org_id == org_id, AISystem.source_key.isnot(None))
        )).scalars())
        created: List[dict] = []
        try:
            for cand in await self._candidates(org_id):
                if cand["source_key"] in existing:
                    continue
                system = AISystem(org_id=org_id, domain="general", risk_flags=[],
                                  review_status="unreviewed", **cand)
                self._classify(system)
                self.db.add(system)
                await self.db.flush()
                created.append({"id": system.id, "source_key": system.source_key, "name": system.name})
                existing.add(cand["source_key"])
            if created:
                await self.db.commit()
        except IntegrityError:
            # a concurrent sync created the same entries first - nothing lost
            await self.db.rollback()
            return []
        return created

    # ------------------------------------------------------------------ queries
    async def list(self, org_id: int, *, kind=None, stage=None, tier=None, review_status=None,
                   q=None, skip: int = 0, limit: int = 50) -> Tuple[List[AISystem], int]:
        effective = func.coalesce(AISystem.confirmed_risk_tier, AISystem.suggested_risk_tier)
        conds = [AISystem.org_id == org_id]
        if kind:
            conds.append(AISystem.kind == kind)
        if stage:
            conds.append(AISystem.lifecycle_stage == stage)
        if tier:
            conds.append(effective == tier)
        if review_status:
            conds.append(AISystem.review_status == review_status)
        if q:
            conds.append(AISystem.name.ilike(f"%{q}%"))
        total = (await self.db.execute(select(func.count()).select_from(AISystem).where(*conds))).scalar_one()
        items = (await self.db.execute(
            select(AISystem).where(*conds).order_by(AISystem.id.desc()).offset(skip).limit(limit)
        )).scalars().all()
        return list(items), total

    async def summary(self, org_id: int) -> dict:
        effective = func.coalesce(AISystem.confirmed_risk_tier, AISystem.suggested_risk_tier)
        base = AISystem.org_id == org_id
        by_tier = dict((await self.db.execute(
            select(effective, func.count()).where(base).group_by(effective)
        )).all())
        by_stage = dict((await self.db.execute(
            select(AISystem.lifecycle_stage, func.count()).where(base).group_by(AISystem.lifecycle_stage)
        )).all())
        unreviewed = (await self.db.execute(
            select(func.count()).select_from(AISystem).where(base, AISystem.review_status != "reviewed")
        )).scalar_one()
        prod_unconfirmed = (await self.db.execute(
            select(func.count()).select_from(AISystem).where(
                base, AISystem.lifecycle_stage == "production", AISystem.confirmed_risk_tier.is_(None))
        )).scalar_one()
        return {
            "total": sum(by_stage.values()),
            "by_tier": {k or "unknown": v for k, v in by_tier.items()},
            "by_stage": by_stage,
            "unreviewed": unreviewed,
            "in_production_without_confirmed_risk": prod_unconfirmed,
        }

    # ------------------------------------------------------------------ mutations
    async def create(self, org_id: int, data) -> int:
        values = data.model_dump()
        await self._check_refs(org_id, values)
        system = AISystem(org_id=org_id, review_status="unreviewed", **values)
        self._classify(system)
        self.db.add(system)
        await self.db.flush()
        system_id = system.id
        await self.db.commit()
        return system_id

    async def update(self, system_id: int, org_id: int, data) -> Tuple[dict, bool]:
        system = await self.get(system_id, org_id)
        changes = data.model_dump(exclude_unset=True)
        for key in ("name", "domain", "risk_flags"):
            if key in changes and changes[key] is None:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                    detail=f"{key} cannot be null")
        await self._check_refs(org_id, changes)
        for key, value in changes.items():
            setattr(system, key, value)
        reset = False
        if "domain" in changes or "risk_flags" in changes:
            self._classify(system)
            # the inputs of a confirmed assessment changed -> it no longer holds
            if system.confirmed_risk_tier:
                system.confirmed_risk_tier = None
                system.risk_justification = None
                system.risk_confirmed_by = None
                system.risk_confirmed_at = None
                system.review_status = "unreviewed"
                reset = True
        await self.db.commit()
        return changes, reset

    async def set_stage(self, system_id: int, org_id: int, stage: str) -> str:
        system = await self.get(system_id, org_id)
        if stage == "production":
            if not system.confirmed_risk_tier:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                    detail="Confirm the risk tier before moving the system to production")
            if system.confirmed_risk_tier == "unacceptable":
                raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                    detail="A system with an unacceptable (EU AI Act Art. 5) risk tier cannot go to production")
        previous = system.lifecycle_stage
        system.lifecycle_stage = stage
        self.last_source_change = None
        if stage == "retired" and previous != "retired":
            # retiring an entry stops what it describes - otherwise the inventory
            # says "retired" while the agent / connection / model keeps working
            self.last_source_change = await self._stop_source(system)
        await self.db.commit()
        return previous

    async def _stop_source(self, system: AISystem) -> Optional[dict]:
        """Stop what a retired entry describes. Never restarts anything: going
        back from "retired" is a separate, deliberate action on the source."""
        if system.kind == "agent" and system.agent_id:
            agent = (await self.db.execute(
                select(Agent).where(Agent.id == system.agent_id, Agent.org_id == system.org_id)
            )).scalar_one_or_none()
            if agent is not None and agent.status != "retired":
                before, agent.status = agent.status, "retired"
                return {"agent_id": agent.id, "from": before, "to": "retired"}
        elif system.kind == "llm_provider" and system.provider_id:
            provider = (await self.db.execute(
                select(AIProvider).where(AIProvider.id == system.provider_id, AIProvider.org_id == system.org_id)
            )).scalar_one_or_none()
            if provider is not None and provider.status == "active":
                before, provider.status = provider.status, "inactive"
                return {"provider_id": provider.id, "from": before, "to": "inactive"}
        return None

    async def confirm_risk(self, system_id: int, org_id: int, user_id: int,
                           tier: str, justification: Optional[str]) -> Optional[str]:
        system = await self.get(system_id, org_id)
        justification = (justification or "").strip() or None
        suggested = system.suggested_risk_tier
        if tier != suggested and not justification:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="A justification is required when the confirmed tier differs from the suggested one")
        system.confirmed_risk_tier = tier
        system.risk_justification = justification
        system.risk_confirmed_by = user_id
        system.risk_confirmed_at = datetime.now(timezone.utc)
        system.review_status = "reviewed"
        await self.db.commit()
        return suggested

    async def add_data_link(self, system_id: int, org_id: int, data) -> int:
        system = await self.get(system_id, org_id)
        link = AISystemDataLink(org_id=org_id, system_id=system.id, **data.model_dump())
        self.db.add(link)
        await self.db.flush()
        link_id = link.id
        await self.db.commit()
        return link_id

    async def remove_data_link(self, system_id: int, org_id: int, link_id: int) -> None:
        await self.get(system_id, org_id)
        link = (await self.db.execute(
            select(AISystemDataLink).where(
                AISystemDataLink.id == link_id,
                AISystemDataLink.system_id == system_id,
                AISystemDataLink.org_id == org_id,
            )
        )).scalar_one_or_none()
        if not link:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Data link not found")
        await self.db.delete(link)
        await self.db.commit()

    # ------------------------------------------------------------------ trust metrics
    async def metrics(self, system_id: int, org_id: int, days: int = 30) -> dict:
        """Activity and trust signals for one system, computed on the fly from
        the events other modules already record (nothing is stored here):
          agent        -> agent_actions / agent_incidents
          llm_provider -> ai_requests
          shadow       -> shadow_ai_sightings
        Signals are prompts for a reviewer, not verdicts."""
        system = await self.get(system_id, org_id)
        since = datetime.now(timezone.utc) - timedelta(days=days)
        counts: dict = {}
        rates: dict = {}
        signals: List[str] = []
        source = None
        last = None

        if system.kind == "agent" and system.agent_id:
            source = "agent_actions"
            rows = (await self.db.execute(
                select(AgentAction.policy_check_result, func.count())
                .where(AgentAction.org_id == org_id, AgentAction.agent_id == system.agent_id,
                       AgentAction.created_at >= since)
                .group_by(AgentAction.policy_check_result)
            )).all()
            by = {(k or "unknown"): v for k, v in rows}
            total = sum(by.values())
            counts = {
                "actions": total,
                "allowed": by.get("allowed", 0),
                "denied": by.get("denied", 0),
                "pending_approval": by.get("pending_approval", 0),
            }
            counts["incidents"] = (await self.db.execute(
                select(func.count()).select_from(AgentIncident).where(
                    AgentIncident.org_id == org_id, AgentIncident.agent_id == system.agent_id,
                    AgentIncident.created_at >= since)
            )).scalar_one()
            counts["open_incidents"] = (await self.db.execute(
                select(func.count()).select_from(AgentIncident).where(
                    AgentIncident.org_id == org_id, AgentIncident.agent_id == system.agent_id,
                    AgentIncident.resolved.is_(False))
            )).scalar_one()
            last = (await self.db.execute(
                select(func.max(AgentAction.created_at)).where(
                    AgentAction.org_id == org_id, AgentAction.agent_id == system.agent_id)
            )).scalar_one()
            if total:
                rates["denial_rate"] = round(counts["denied"] / total, 3)
                if total >= MIN_EVENTS_FOR_RATE and rates["denial_rate"] > HIGH_RATE_THRESHOLD:
                    signals.append("high_denial_rate")
            if counts["open_incidents"]:
                signals.append("open_incidents")
            if counts["pending_approval"]:
                signals.append("actions_awaiting_approval")

        elif system.kind == "llm_provider" and system.provider_id:
            source = "ai_requests"
            rows = (await self.db.execute(
                select(AIRequest.status, func.count())
                .where(AIRequest.org_id == org_id, AIRequest.provider_id == system.provider_id,
                       AIRequest.created_at >= since)
                .group_by(AIRequest.status)
            )).all()
            by = {(k or "unknown"): v for k, v in rows}
            total = sum(by.values())
            counts = {
                "requests": total,
                "completed": by.get("completed", 0),
                "blocked": by.get("blocked", 0),
                "pending_approval": by.get("pending_approval", 0),
                "other": total - by.get("completed", 0) - by.get("blocked", 0) - by.get("pending_approval", 0),
            }
            last = (await self.db.execute(
                select(func.max(AIRequest.created_at)).where(
                    AIRequest.org_id == org_id, AIRequest.provider_id == system.provider_id)
            )).scalar_one()
            if total:
                rates["block_rate"] = round(counts["blocked"] / total, 3)
                if total >= MIN_EVENTS_FOR_RATE and rates["block_rate"] > HIGH_RATE_THRESHOLD:
                    signals.append("high_block_rate")
            if counts["pending_approval"]:
                signals.append("requests_awaiting_approval")

        elif system.kind == "shadow" and system.shadow_tool:
            source = "shadow_ai_sightings"
            seen_at = func.coalesce(ShadowAISighting.last_seen_at, ShadowAISighting.created_at)
            base = (ShadowAISighting.org_id == org_id,
                    func.lower(ShadowAISighting.tool_name) == system.shadow_tool.lower())
            row = (await self.db.execute(
                select(func.count(), func.coalesce(func.sum(ShadowAISighting.seen_count), 0),
                       func.count(func.distinct(ShadowAISighting.user_hint)))
                .where(*base, seen_at >= since)
            )).one()
            counts = {"reports": row[0], "times_seen": int(row[1]), "distinct_users": row[2]}
            last = (await self.db.execute(select(func.max(seen_at)).where(*base))).scalar_one()
            if row[0]:
                signals.append("shadow_still_in_use")

        if source and system.lifecycle_stage == "production" and (last is None or last < since):
            signals.append("no_recent_activity")

        return {
            "window_days": days,
            "source": source,
            "counts": counts,
            "rates": rates,
            "last_activity_at": last,
            "signals": signals,
        }

