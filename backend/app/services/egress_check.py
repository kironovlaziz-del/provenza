# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Egress checks: is an agent's host confined to Provenza?

Provenza cannot close a network; the infrastructure does (docs/egress-lockdown.md
and the generator in app/services/egress_lockdown.py: the agent may reach the
egress proxy and nothing else). This checks that it did:

  1. the agent asks for a check (POST /agents/egress-check): a few targets on
     the internet, and a beacon URL with a fresh token on this server;
  2. the agent's host tries them all directly (a TCP connect; an HTTP GET for
     the beacon) and reports what it reached, signed with its key;
  3. verdict: "open" if any target was reached, or if the beacon was - which
     this server sees itself, whatever the report says, even after it;
     "confined" otherwise.

With the organization's require_confined_egress on, an agent acts only
while its latest verdict is "confined" and recent (egress_check_max_age_hours).

What it is, and what it is not: it catches a host whose lockdown is missing
or broken - the common case. An agent that wants to cheat can skip the
beacon and report nothing reachable; only the network rule itself stops it.
The beacon is served at /egress-beacon/..., outside /api/v1, so the proxy's
relay (which passes only /api/v1) cannot carry it.
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_signing import verify_agent_signature
from app.core.config import settings
from app.core.errors import api_error
from app.models.agent import Agent
from app.models.agent_action import AgentIncident
from app.models.egress_check import AgentEgressCheck

CHECK_TTL = timedelta(minutes=10)
BEACON_PATH = "/egress-beacon/"
INCIDENT = "egress_unconfined"
MAX_TARGETS = 10


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def targets() -> List[str]:
    out = []
    for item in (settings.EGRESS_PROBE_TARGETS or "").split(","):
        host, _, port = item.strip().rpartition(":")
        if host and port.isdigit() and 0 < int(port) < 65536:
            out.append(f"{host}:{int(port)}")
    return out[:MAX_TARGETS]


def beacon_base(request_base: str) -> str:
    return (settings.EGRESS_BEACON_BASE_URL or settings.PUBLIC_BASE_URL or request_base).rstrip("/")


def signed_payload(agent_id: int, check_id: int, results: List[Dict[str, Any]], beacon_reached: bool) -> Dict[str, Any]:
    """What the agent signs: the results sorted by target, so every SDK signs the same bytes."""
    return {"type": "egress.report", "agent_id": agent_id, "check_id": check_id,
            "results": sorted(({"target": r["target"], "reachable": bool(r["reachable"])} for r in results),
                              key=lambda r: r["target"]),
            "beacon_reached": bool(beacon_reached)}


def out(row: AgentEgressCheck) -> Dict[str, Any]:
    return {"check_id": row.id, "agent_id": row.agent_id, "verdict": row.verdict, "targets": row.targets,
            "created_at": row.created_at, "reported_at": row.reported_at, "beacon_hit_at": row.beacon_hit_at,
            "results": row.results}


async def start(db: AsyncSession, agent: Agent, request_base: str) -> Dict[str, Any]:
    token = secrets.token_urlsafe(24)
    row = AgentEgressCheck(org_id=agent.org_id, agent_id=agent.id, token=token, targets=targets(),
                           expires_at=_now() + CHECK_TTL)
    db.add(row)
    await db.commit()
    return {"check_id": row.id, "targets": row.targets, "beacon_url": beacon_base(request_base) + BEACON_PATH + token,
            "expires_at": row.expires_at}


def _open(db: AsyncSession, row: AgentEgressCheck, how: str) -> None:
    row.verdict = "open"
    db.add(AgentIncident(org_id=row.org_id, agent_id=row.agent_id, incident_type=INCIDENT, severity="high",
                         details={"check_id": row.id, "detected_by": how, "beacon_ip": row.beacon_ip,
                                  "reached": [r["target"] for r in (row.results or []) if r.get("reachable")]}))


async def beacon(db: AsyncSession, token: str, client_ip: Optional[str]) -> bool:
    """The beacon was reached from somewhere: the host that asked for this
    check is not confined, whatever it reports. Unknown or expired tokens are
    ignored (the answer is the same, so it tells a scanner nothing)."""
    row = (await db.execute(select(AgentEgressCheck).where(AgentEgressCheck.token == token[:64])
                            .with_for_update())).scalar_one_or_none()
    if row is None or _aware(row.expires_at) < _now() or row.beacon_hit_at is not None:
        return False
    row.beacon_hit_at, row.beacon_ip = _now(), (client_ip or "")[:64]
    if row.verdict != "open" and row.reported_at is not None:
        _open(db, row, "beacon_after_report")
    await db.commit()
    return True


async def report(db: AsyncSession, agent: Agent, check_id: int, results: List[Dict[str, Any]],
                 beacon_reached: bool, signature: str, pq_signature: Optional[str]) -> Dict[str, Any]:
    row = (await db.execute(select(AgentEgressCheck).where(
        AgentEgressCheck.id == check_id, AgentEgressCheck.agent_id == agent.id).with_for_update())).scalar_one_or_none()
    if row is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "egress_check.not_found")
    if row.reported_at is not None:
        raise api_error(status.HTTP_409_CONFLICT, "egress_check.already_reported")
    if _aware(row.expires_at) < _now():
        raise api_error(status.HTTP_410_GONE, "egress_check.expired")
    if sorted(r.get("target") for r in results) != sorted(row.targets) or len(results) != len(row.targets):
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "egress_check.targets_mismatch")
    payload = signed_payload(agent.id, row.id, results, beacon_reached)
    if not verify_agent_signature(payload, signature, pq_signature, agent.public_key, agent.pq_public_key):
        raise api_error(status.HTTP_401_UNAUTHORIZED, "egress_check.invalid_signature")
    row.results, row.reported_at = payload["results"], _now()
    if beacon_reached or row.beacon_hit_at is not None or any(r["reachable"] for r in payload["results"]):
        _open(db, row, "beacon" if row.beacon_hit_at is not None else "report")
    else:
        row.verdict = "confined"
    await db.commit()
    return out(row)


async def latest(db: AsyncSession, org_id: int, agent_id: int) -> Optional[AgentEgressCheck]:
    return (await db.execute(
        select(AgentEgressCheck).where(AgentEgressCheck.org_id == org_id, AgentEgressCheck.agent_id == agent_id,
                                       AgentEgressCheck.reported_at.is_not(None))
        .order_by(AgentEgressCheck.reported_at.desc()).limit(1))).scalar_one_or_none()


async def refusal(db: AsyncSession, agent: Agent) -> Optional[str]:
    """None when the agent may act; else the error code."""
    from app.services.agent_identity import org_settings

    cfg = await org_settings(db, agent.org_id)
    if not cfg.get("require_confined_egress"):
        return None
    row = await latest(db, agent.org_id, agent.id)
    if row is None:
        return "agent.egress_unchecked"
    if row.verdict != "confined" or row.beacon_hit_at is not None:
        return "agent.egress_unconfined"
    if _aware(row.reported_at) < _now() - timedelta(hours=cfg.get("egress_check_max_age_hours") or 24):
        return "agent.egress_check_stale"
    return None


async def prune(db: AsyncSession, keep_days: int = 30) -> int:
    """Old checks go; each agent's latest reported one stays."""
    from sqlalchemy import delete, func

    latest_ids = select(func.max(AgentEgressCheck.id)).where(AgentEgressCheck.reported_at.is_not(None)) \
        .group_by(AgentEgressCheck.agent_id)
    res = await db.execute(delete(AgentEgressCheck).where(
        AgentEgressCheck.created_at < _now() - timedelta(days=keep_days), AgentEgressCheck.id.not_in(latest_ids)))
    await db.commit()
    return res.rowcount or 0


async def overview(db: AsyncSession, org_id: int) -> List[Dict[str, Any]]:
    """Each agent's latest verdict, for the identity page."""
    rows = (await db.execute(
        select(AgentEgressCheck).where(AgentEgressCheck.org_id == org_id, AgentEgressCheck.reported_at.is_not(None))
        .order_by(AgentEgressCheck.agent_id, AgentEgressCheck.reported_at.desc())
        .distinct(AgentEgressCheck.agent_id))).scalars().all()
    return [out(r) for r in rows]
