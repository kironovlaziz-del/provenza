# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Protection coverage: what of Provenza's protection actually works now, for
the setup checklist (GET /api/v1/system/setup).

The setup checklist says what has been configured. Coverage says whether it
works: a proxy that was registered but has not been heard from protects
nothing, an agent that was never shown to be confined can still call an API
directly. Each item is one of

    ok         working, with the facts that show it
    attention  configured, but not working as it should
    missing    not set up

and carries the facts it was judged on (counts, numbers), so the interface
says why. Items marked optional are protection not every organization needs
(the sensor needs Linux; discovery is a choice); they never count as gaps
in the summary of what is required.

It only reads: nothing here changes what is enforced.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.egress_check import AgentEgressCheck
from app.models.egress_proxy import EgressProxy
from app.models.egress_sensor import EgressSensor
from app.models.endpoint_device import EndpointDevice
from app.models.ingestion_source import IngestionSource
from app.models.user import User

OK, ATTENTION, MISSING = "ok", "attention", "missing"

PROXY_ONLINE = timedelta(minutes=10)      # a proxy asks for its policy and configuration well within this
SENSOR_ONLINE = timedelta(minutes=5)      # a sensor's heartbeat is every 30 s
DEVICE_RECENT = timedelta(hours=2)        # the endpoint agent says it is alive every 15 minutes
BROWSER_RECENT = timedelta(days=7)        # the extension reports visits only: no heartbeat
CHECK_VALID = timedelta(days=30)          # an egress self-check older than this proves little about today


def _item(key: str, state: str, href: str, optional: bool = False, **facts: Any) -> Dict[str, Any]:
    return {"key": key, "state": state, "href": href, "optional": optional, "facts": facts}


async def _signed_policy(db: AsyncSession, user: User) -> Dict[str, Any]:
    from app.services import policy_release

    st = await policy_release.state(db, user)
    cur, draft = st.get("in_force"), st.get("draft")
    facts: Dict[str, Any] = {"draft": draft["number"] if draft else None}
    if cur is None:
        return _item("signed_policy", MISSING, "/policy-hierarchy", **facts)
    facts.update(number=cur["number"], unsigned=st.get("unsigned_count") or 0,
                 problem=bool(cur.get("problem") or cur.get("expired")))
    bad = facts["problem"] or facts["unsigned"] or draft is not None
    return _item("signed_policy", ATTENTION if bad else OK, "/policy-hierarchy", **facts)


async def _proxies(db: AsyncSession, org_id: int, now: datetime, policy_in_force: bool) -> Dict[str, Any]:
    rows = (await db.execute(select(EgressProxy.last_seen_at).where(
        EgressProxy.org_id == org_id, EgressProxy.enabled.is_(True), EgressProxy.revoked_at.is_(None)))).scalars().all()
    online = sum(1 for seen in rows if seen is not None and now - seen <= PROXY_ONLINE)
    facts = {"total": len(rows), "online": online, "policy": policy_in_force}
    if not rows:
        return _item("proxy", MISSING, "/gateway?tab=egress", **facts)
    # a proxy without a signed release refuses every request: up, but not protecting anything yet
    good = online == len(rows) and policy_in_force
    return _item("proxy", OK if good else ATTENTION, "/gateway?tab=egress", **facts)


async def _agents(db: AsyncSession, org_id: int, now: datetime) -> List[Dict[str, Any]]:
    agents = (await db.execute(select(Agent.id, Agent.public_key).where(
        Agent.org_id == org_id, Agent.status == "active"))).all()
    total = len(agents)
    signing = sum(1 for a in agents if a.public_key)
    sign = _item("agents_signing", MISSING if total == 0 else (OK if signing == total else ATTENTION),
                 "/agents", agents=total, signing=signing)

    # the latest finished self-check of each active agent within the validity window
    latest: Dict[int, str] = {}
    if total:
        rows = (await db.execute(
            select(AgentEgressCheck.agent_id, AgentEgressCheck.verdict)
            .where(AgentEgressCheck.org_id == org_id, AgentEgressCheck.verdict.in_(("confined", "open")),
                   AgentEgressCheck.created_at >= now - CHECK_VALID,
                   AgentEgressCheck.agent_id.in_([a.id for a in agents]))
            .order_by(AgentEgressCheck.agent_id, AgentEgressCheck.created_at.desc(), AgentEgressCheck.id.desc())
        )).all()
        for agent_id, verdict in rows:
            latest.setdefault(agent_id, verdict)
    confined = sum(1 for v in latest.values() if v == "confined")
    opened = sum(1 for v in latest.values() if v == "open")
    unchecked = total - len(latest)
    if total == 0 or not latest:
        state = MISSING
    elif confined == total:
        state = OK
    else:
        state = ATTENTION
    conf = _item("agents_confined", state, "/gateway?tab=egress",
                 agents=total, confined=confined, open=opened, unchecked=unchecked)
    return [sign, conf]


async def _sensors(db: AsyncSession, org_id: int, now: datetime) -> Dict[str, Any]:
    rows = (await db.execute(select(EgressSensor.last_seen_at, EgressSensor.enforcing, EgressSensor.errors).where(
        EgressSensor.org_id == org_id, EgressSensor.enabled.is_(True), EgressSensor.revoked_at.is_(None)))).all()
    online = [r for r in rows if r.last_seen_at is not None and now - r.last_seen_at <= SENSOR_ONLINE]
    enforcing = sum(1 for r in online if r.enforcing)
    problems = sum(1 for r in online if r.errors)
    facts = {"total": len(rows), "online": len(online), "enforcing": enforcing, "problems": problems}
    if not rows:
        return _item("sensors", MISSING, "/runtime", optional=True, **facts)
    good = len(online) == len(rows) and enforcing == len(rows) and problems == 0
    return _item("sensors", OK if good else ATTENTION, "/runtime", optional=True, **facts)


async def _collector(db: AsyncSession, org_id: int, now: datetime, key: str, source_type: str,
                     recent: timedelta) -> Dict[str, Any]:
    sources = int(await db.scalar(select(func.count()).select_from(IngestionSource).where(
        IngestionSource.org_id == org_id, IngestionSource.source_type == source_type,
        IngestionSource.enabled.is_(True))) or 0)
    seen = (await db.execute(
        select(EndpointDevice.last_seen_at).join(IngestionSource, IngestionSource.id == EndpointDevice.ingestion_source_id)
        .where(EndpointDevice.org_id == org_id, IngestionSource.source_type == source_type,
               IngestionSource.enabled.is_(True)))).scalars().all()
    reporting = sum(1 for s in seen if s is not None and now - s <= recent)
    facts = {"sources": sources, "devices": len(seen), "reporting": reporting}
    if sources == 0:
        state = MISSING
    elif reporting == 0:
        state = ATTENTION                     # a key was made, but nothing reports with it
    else:
        state = OK
    return _item(key, state, "/ingestion-sources", optional=True, **facts)


async def coverage(db: AsyncSession, user: User) -> Dict[str, Any]:
    org_id = user.org_id
    now = datetime.now(timezone.utc)
    policy = await _signed_policy(db, user)
    items = [policy,
             await _proxies(db, org_id, now, policy["facts"].get("number") is not None),
             *await _agents(db, org_id, now),
             await _sensors(db, org_id, now),
             await _collector(db, org_id, now, "endpoint_agents", "endpoint", DEVICE_RECENT),
             await _collector(db, org_id, now, "browsers", "browser_extension", BROWSER_RECENT)]
    summary = {s: sum(1 for i in items if i["state"] == s) for s in (OK, ATTENTION, MISSING)}
    # what needs a person: anything that stopped working, and required protection not set up
    summary["needs_action"] = sum(1 for i in items if i["state"] == ATTENTION
                                  or (i["state"] == MISSING and not i["optional"]))
    return {"items": items, "summary": summary}
