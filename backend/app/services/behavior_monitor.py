# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Behaviour monitor - OWASP Agentic Top 10, ASI10 (rogue agents).

An agent can break no rule and still behave unlike itself: new tools, a
sudden burst of calls, a run of denials, activity at hours it never works.
Each agent gets a baseline from its own recent history (excluding the last
hour, so a burst cannot normalise itself) and every /actions/check is scored
against it:

    rate_spike    50   attempts in the last 5 min >= max(20, 3 x baseline p95)
    denial_spike  40   >= 10 attempts in the last hour and denial rate
                       > max(0.3, 3 x baseline rate)        (no baseline needed)
    new_tool      30   a tool never used in the baseline    (mature baseline only)
    off_hours     15   an hour of day never seen            (mature baseline only)

mode "monitor" (default) records anomalies; mode "enforce" quarantines the
agent when the score reaches the threshold: status -> "quarantined" (the
policy engine refuses all its actions), chains it roots are tripped, and a
rogue_agent_quarantined incident is raised. Only an admin releases it; the
signal windows then restart from the release time.

A baseline is "mature" only after min_samples attempts spread over >= 3
days - otherwise every new agent would look suspicious.
"""

import math
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.agent_action import ActionCheck, AgentAction, AgentIncident
from app.models.behavior import AgentAnomaly, AgentBaseline, BehaviorSettings
from app.models.delegation import DelegationChain

MODES = ("off", "monitor", "enforce")
DEFAULTS = {"mode": "monitor", "threshold": 60, "min_samples": 50, "baseline_days": 14}
BOUNDS = {"threshold": (15, 200), "min_samples": (20, 100000), "baseline_days": (3, 90)}
WEIGHTS = {"rate_spike": 50, "denial_spike": 40, "new_tool": 30, "off_hours": 15}

BASELINE_TTL = timedelta(hours=1)
EXCLUDE_RECENT = timedelta(hours=1)
MIN_SPAN_DAYS = 3
RATE_WINDOW = timedelta(minutes=5)
RATE_MIN, RATE_MULTIPLIER = 20, 3
DENIAL_WINDOW = timedelta(hours=1)
DENIAL_MIN_ATTEMPTS, DENIAL_FLOOR, DENIAL_MULTIPLIER = 10, 0.3, 3
DEDUP = timedelta(minutes=10)
QUARANTINE_INCIDENT = "rogue_agent_quarantined"


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _p95(values: List[int]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return float(ordered[idx])


class BehaviorMonitor:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------ settings
    async def _settings_row(self, org_id: int) -> Optional[BehaviorSettings]:
        return (await self.db.execute(
            select(BehaviorSettings).where(BehaviorSettings.org_id == org_id)
        )).scalar_one_or_none()

    async def settings(self, org_id: int) -> dict:
        row = await self._settings_row(org_id)
        if not row:
            return {**DEFAULTS, "source": "default"}
        return {"mode": row.mode, "threshold": row.threshold, "min_samples": row.min_samples,
                "baseline_days": row.baseline_days, "source": "org"}

    async def save_settings(self, org_id: int, values: dict, user_id: int) -> tuple:
        row = await self._settings_row(org_id)
        before = None if row is None else {k: getattr(row, k) for k in DEFAULTS}
        if row is None:
            row = BehaviorSettings(org_id=org_id)
            self.db.add(row)
        for k in DEFAULTS:
            setattr(row, k, values[k])
        row.updated_by = user_id
        await self.db.commit()
        return before, {k: values[k] for k in DEFAULTS}

    # ------------------------------------------------------------------ event sources
    # Every attempt = a /actions/check, plus legacy records made without one.
    # All aggregation happens in SQL - a busy agent can have millions of rows.
    @staticmethod
    def _sources(agent_id: int, since: datetime, until: Optional[datetime]):
        c = [ActionCheck.agent_id == agent_id, ActionCheck.created_at >= since]
        a = [AgentAction.agent_id == agent_id, AgentAction.check_id.is_(None), AgentAction.created_at >= since]
        if until is not None:
            c.append(ActionCheck.created_at < until)
            a.append(AgentAction.created_at < until)
        return (
            (ActionCheck.created_at, ActionCheck.tool_name, ActionCheck.decision == "denied", c),
            (AgentAction.created_at, AgentAction.tool_name, AgentAction.policy_check_result == "denied", a),
        )

    async def _count(self, agent_id: int, since: datetime, until: Optional[datetime] = None) -> tuple:
        """(attempts, denied, first_at, last_at)"""
        total, denied, first, last = 0, 0, None, None
        for col, _tool, is_denied, cond in self._sources(agent_id, since, until):
            n, d, lo, hi = (await self.db.execute(
                select(func.count(), func.count().filter(is_denied), func.min(col), func.max(col)).where(*cond)
            )).one()
            total += n
            denied += d
            lo, hi = _aware(lo), _aware(hi)
            first = lo if first is None or (lo and lo < first) else first
            last = hi if last is None or (hi and hi > last) else last
        return total, denied, first, last

    # ------------------------------------------------------------------ baseline
    async def baseline(self, org_id: int, agent_id: int, force: bool = False) -> AgentBaseline:
        cfg = await self.settings(org_id)
        row = (await self.db.execute(
            select(AgentBaseline).where(AgentBaseline.agent_id == agent_id)
        )).scalar_one_or_none()
        now = datetime.now(timezone.utc)
        if row and not force and row.computed_at and now - _aware(row.computed_at) < BASELINE_TTL \
                and row.window_days == cfg["baseline_days"]:
            return row

        since, until = now - timedelta(days=cfg["baseline_days"]), now - EXCLUDE_RECENT
        total, denied, first, last = await self._count(agent_id, since, until)
        tools: dict = {}
        hours = [0] * 24
        buckets: dict = {}
        bucket_seconds = RATE_WINDOW.total_seconds()
        for col, tool_col, _d, cond in self._sources(agent_id, since, until):
            for tool, n in (await self.db.execute(select(tool_col, func.count()).where(*cond).group_by(tool_col))).all():
                if tool:
                    tools[tool] = tools.get(tool, 0) + n
            hour_expr = func.extract("hour", func.timezone("UTC", col))
            for h, n in (await self.db.execute(select(hour_expr, func.count()).where(*cond).group_by(hour_expr))).all():
                hours[int(h)] += n
            bucket_expr = func.floor(func.extract("epoch", col) / bucket_seconds)
            for b, n in (await self.db.execute(select(bucket_expr, func.count()).where(*cond).group_by(bucket_expr))).all():
                buckets[int(b)] = buckets.get(int(b), 0) + n
        span = (last - first).total_seconds() / 86400 if first and last else 0.0

        if row is None:
            row = AgentBaseline(org_id=org_id, agent_id=agent_id)
            self.db.add(row)
        row.computed_at = now
        row.window_days = cfg["baseline_days"]
        row.sample_count = total
        row.span_days = round(span, 2)
        row.tools = tools
        row.hours = hours
        row.p95_per_5min = _p95(list(buckets.values()))
        row.denial_rate = round(denied / total, 4) if total else 0.0
        row.mature = total >= cfg["min_samples"] and span >= MIN_SPAN_DAYS
        await self.db.flush()
        return row

    # ------------------------------------------------------------------ evaluation
    async def evaluate(self, org_id: int, agent_id: int, tool: Optional[str]) -> Optional[dict]:
        cfg = await self.settings(org_id)
        if cfg["mode"] == "off":
            return None
        agent = (await self.db.execute(
            select(Agent).where(Agent.id == agent_id, Agent.org_id == org_id)
        )).scalar_one_or_none()
        if not agent or agent.status != "active":
            return None

        bl = await self.baseline(org_id, agent_id)
        now = datetime.now(timezone.utc)
        released = _aware(bl.quarantine_released_at)
        signals: dict = {}

        rate_since = max(now - RATE_WINDOW, released) if released else now - RATE_WINDOW
        recent, _, _, _ = await self._count(agent_id, rate_since)
        rate_limit = max(RATE_MIN, RATE_MULTIPLIER * bl.p95_per_5min)
        if bl.mature and recent >= rate_limit:
            signals["rate_spike"] = {"attempts_5min": recent, "limit": rate_limit,
                                     "baseline_p95": bl.p95_per_5min}

        den_since = max(now - DENIAL_WINDOW, released) if released else now - DENIAL_WINDOW
        attempts_1h, denied_1h, _, _ = await self._count(agent_id, den_since)
        if attempts_1h >= DENIAL_MIN_ATTEMPTS:
            rate = denied_1h / attempts_1h
            limit = max(DENIAL_FLOOR, DENIAL_MULTIPLIER * bl.denial_rate)
            if rate > limit:
                signals["denial_spike"] = {"denial_rate_1h": round(rate, 3), "limit": round(limit, 3),
                                           "attempts_1h": attempts_1h, "baseline_rate": bl.denial_rate}

        if bl.mature and tool and tool not in (bl.tools or {}):
            signals["new_tool"] = {"tool": tool, "known_tools": sorted((bl.tools or {}).keys())[:20]}
        if bl.mature and (bl.hours or [0] * 24)[now.hour] == 0:
            signals["off_hours"] = {"utc_hour": now.hour}

        if not signals:
            await self.db.commit()  # persist a recomputed baseline
            return None
        score = sum(WEIGHTS[k] for k in signals)
        quarantine = cfg["mode"] == "enforce" and score >= cfg["threshold"]

        last = (await self.db.execute(
            select(AgentAnomaly).where(AgentAnomaly.agent_id == agent_id)
            .order_by(AgentAnomaly.detected_at.desc()).limit(1)
        )).scalar_one_or_none()
        duplicate = (not quarantine and last is not None and last.outcome == "flagged"
                     and now - _aware(last.detected_at) < DEDUP
                     and sorted(last.signals.keys()) == sorted(signals.keys()))
        if not duplicate:
            self.db.add(AgentAnomaly(org_id=org_id, agent_id=agent_id, tool_name=tool, score=score,
                                     signals=signals, outcome="quarantined" if quarantine else "flagged"))
        result = {"score": score, "signals": signals, "quarantined": quarantine, "threshold": cfg["threshold"]}
        if quarantine:
            await self._quarantine(org_id, agent, result)
        await self.db.commit()
        return result

    async def _quarantine(self, org_id: int, agent: Agent, result: dict) -> None:
        agent.status = "quarantined"
        now = datetime.now(timezone.utc)
        chains = (await self.db.execute(
            select(DelegationChain).where(DelegationChain.org_id == org_id,
                                          DelegationChain.root_agent_id == agent.id,
                                          DelegationChain.status == "active")
        )).scalars().all()
        for chain in chains:
            chain.status = "tripped"
            chain.breaker_tripped_at = now
            chain.breaker_details = {"exceeded": ["root_agent_quarantined"], "counts": {}, "thresholds": {},
                                     "window_seconds": 0, "settings_source": "behavior_monitor",
                                     "tripped_at": now.isoformat()}
        self.db.add(AgentIncident(
            org_id=org_id, agent_id=agent.id, incident_type=QUARANTINE_INCIDENT, severity="critical",
            details={**result, "tripped_chains": [c.id for c in chains]},
        ))

    # ------------------------------------------------------------------ operator actions
    async def release(self, org_id: int, agent_id: int) -> None:
        agent = (await self.db.execute(
            select(Agent).where(Agent.id == agent_id, Agent.org_id == org_id)
        )).scalar_one_or_none()
        if not agent:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        if agent.status != "quarantined":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail=f"Agent is {agent.status}, not quarantined")
        agent.status = "active"
        bl = await self.baseline(org_id, agent_id)
        bl.quarantine_released_at = datetime.now(timezone.utc)
        await self.db.commit()

    async def overview(self, org_id: int) -> dict:
        agents = (await self.db.execute(
            select(Agent).where(Agent.org_id == org_id).order_by(Agent.name)
        )).scalars().all()
        baselines = {b.agent_id: b for b in (await self.db.execute(
            select(AgentBaseline).where(AgentBaseline.org_id == org_id)
        )).scalars().all()}
        anomalies = (await self.db.execute(
            select(AgentAnomaly, Agent.name)
            .join(Agent, Agent.id == AgentAnomaly.agent_id)
            .where(AgentAnomaly.org_id == org_id)
            .order_by(AgentAnomaly.detected_at.desc()).limit(50)
        )).all()
        rows = []
        for a in agents:
            b = baselines.get(a.id)
            top = sorted((b.tools or {}).items(), key=lambda kv: -kv[1])[:5] if b else []
            rows.append({
                "agent_id": a.id, "name": a.name, "status": a.status,
                "baseline": None if not b else {
                    "mature": b.mature, "samples": b.sample_count, "span_days": b.span_days,
                    "p95_per_5min": b.p95_per_5min, "denial_rate": b.denial_rate,
                    "top_tools": [t for t, _ in top], "computed_at": b.computed_at,
                },
            })
        return {
            "settings": await self.settings(org_id),
            "agents": rows,
            "anomalies": [
                {"id": x.id, "agent_id": x.agent_id, "agent_name": name, "detected_at": x.detected_at,
                 "tool_name": x.tool_name, "score": x.score, "signals": x.signals, "outcome": x.outcome}
                for x, name in anomalies
            ],
        }
