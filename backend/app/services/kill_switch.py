# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Kill switch: stop an agent, a team, every agent, or all of the
organization's AI traffic - and undo exactly that.

Levels (KillSwitchEvent.scope):
    agent        one agent
    team         every agent of a team and of its sub-teams
    all_agents   every agent of the organization
    org_traffic  every agent, the gateway and AI requests

Agents are stopped by suspending them: every place that lets an agent act
already refuses a non-active one (agent keys, the policy engine, the
gateway, delegation). The event records which agents it suspended and
with what status, and which delegation chains it terminated. While it is
active, whatever it covers stays stopped:
  * an agent created in its scope (registration, enrollment, assignment to
    a stopped team, a team moved under a stopped team) starts suspended and
    is added to the event;
  * an agent it covers cannot be switched back on by hand (status change,
    quarantine release) - lift the stop instead.
org_traffic also stops the gateway and AI requests while it is active
(gateway_service, request_service ask traffic_stop()).

Lifting gives back what the event stopped and nothing else: agents it
suspended return to the status they had, unless
  * they changed since (retired, ...): skipped;
  * another active stop still covers them: kept, and that stop now
    restores them when it is lifted.
Terminated delegation chains stay terminated: the agents start new ones.

Engaging, lifting and agent creation take one advisory lock per
organization, so a stop never misses an agent created at the same moment.
"""

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import api_error
from app.models.agent import Agent
from app.models.delegation import DelegationChain
from app.models.kill_switch import KillSwitchEvent
from app.models.team import Team

SCOPES = ("agent", "team", "all_agents", "org_traffic")
ORG_WIDE = ("all_agents", "org_traffic")
# a stop at a wider level wins when several cover one agent
_ORDER = {"org_traffic": 0, "all_agents": 1, "team": 2, "agent": 3}
NOTIFY_EVENT = "kill_switch"
NOTIFY_WAIT_SECONDS = 3


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def lock(db: AsyncSession, org_id: int) -> None:
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext('provenza.kill_switch'), :org)"),
                     {"org": int(org_id)})


async def active_events(db: AsyncSession, org_id: int, for_update: bool = False) -> List[KillSwitchEvent]:
    q = select(KillSwitchEvent).where(KillSwitchEvent.org_id == org_id, KillSwitchEvent.lifted_at.is_(None))
    if for_update:
        q = q.with_for_update()
    rows = list((await db.execute(q.order_by(KillSwitchEvent.id))).scalars())
    return sorted(rows, key=lambda e: (_ORDER[e.scope], e.id))


async def _ancestors(db: AsyncSession, org_id: int, team_id: Optional[int]) -> set:
    """The team and every team above it."""
    if team_id is None:
        return set()
    parents = dict((await db.execute(select(Team.id, Team.parent_id).where(Team.org_id == org_id))).all())
    out, t = set(), team_id
    while t is not None and t not in out:
        out.add(t)
        t = parents.get(t)
    return out


async def covering(db: AsyncSession, agent: Agent,
                   events: Optional[List[KillSwitchEvent]] = None) -> Optional[KillSwitchEvent]:
    """The active stop that holds this agent, if any (the widest first): an
    organization-wide stop; a stop that suspended it (even if it was moved
    out of the stopped team since); an agent stop for it; or a team stop of
    its team or of a team above it (sub-teams made or moved there later
    included)."""
    ancestors = None
    for e in events if events is not None else await active_events(db, agent.org_id):
        if e.scope in ORG_WIDE:
            return e
        s = e.stopped or {}
        if any(a.get("id") == agent.id for a in s.get("agents") or []):
            return e
        if e.scope == "agent" and e.agent_id == agent.id:
            return e
        if e.scope == "team" and agent.team_id is not None:
            if ancestors is None:
                ancestors = await _ancestors(db, agent.org_id, agent.team_id)
            if (e.team_id is not None and e.team_id in ancestors) or agent.team_id in (s.get("team_ids") or []):
                return e
    return None


async def traffic_stop(db: AsyncSession, org_id: int) -> Optional[KillSwitchEvent]:
    """The active stop of the organization's AI traffic, if any."""
    return (await db.execute(
        select(KillSwitchEvent).where(KillSwitchEvent.org_id == org_id, KillSwitchEvent.scope == "org_traffic",
                                      KillSwitchEvent.lifted_at.is_(None))
        .order_by(KillSwitchEvent.id).limit(1)
    )).scalars().first()


def _add_agent(event: KillSwitchEvent, agent: Agent, previous: str) -> None:
    stopped = dict(event.stopped or {})
    agents = list(stopped.get("agents") or [])
    if not any(a["id"] == agent.id for a in agents):
        agents.append({"id": agent.id, "name": agent.name, "status": previous})
    stopped["agents"] = agents
    event.stopped = stopped  # a new dict: JSONB changes are seen on assignment


async def hold_new_agent(db: AsyncSession, agent: Agent) -> Optional[KillSwitchEvent]:
    """For an agent being created or moved into a team: while a stop covers
    it, it starts suspended and the stop gives it back when lifted. Takes
    the organization's kill-switch lock (held until the caller commits)."""
    await lock(db, agent.org_id)
    if agent.status != "active":
        return None
    event = await covering(db, agent)
    if event is not None:
        agent.status = "suspended"
        _add_agent(event, agent, "active")
    return event


async def check_reactivation(db: AsyncSession, agent: Agent) -> None:
    """Switching an agent back on by hand is refused while a stop covers it."""
    await lock(db, agent.org_id)
    event = await covering(db, agent)
    if event is not None:
        raise api_error(status.HTTP_409_CONFLICT, "kill_switch.holds_agent", event_id=event.id,
                        scope=event.scope)


async def hold_moved_team(db: AsyncSession, org_id: int, team_id: int) -> List[int]:
    """A team moved under a stopped team: its running agents (and those of its
    sub-teams) stop too and come back with that stop. Called with the teams
    hierarchy lock held (teams lock first, then this one - as engage does)."""
    await lock(db, org_id)
    events = [e for e in await active_events(db, org_id) if e.scope == "team"]
    if not events:
        return []
    ids = await _team_ids(db, org_id, team_id)
    held = []
    for agent in (await db.execute(
        select(Agent).where(Agent.org_id == org_id, Agent.team_id.in_(ids), Agent.status == "active")
        .order_by(Agent.id).with_for_update()
    )).scalars():
        event = await covering(db, agent, events)
        if event is not None:
            agent.status = "suspended"
            _add_agent(event, agent, "active")
            held.append(agent.id)
    return held


async def _team_ids(db: AsyncSession, org_id: int, team_id: int) -> List[int]:
    """The team and every team below it."""
    rows = (await db.execute(select(Team.id, Team.parent_id).where(Team.org_id == org_id))).all()
    children: Dict[Optional[int], List[int]] = {}
    for tid, parent in rows:
        children.setdefault(parent, []).append(tid)
    out, todo = [], [team_id]
    while todo:
        t = todo.pop()
        if t in out:
            continue
        out.append(t)
        todo.extend(children.get(t, []))
    return sorted(out)


async def engage(db: AsyncSession, org_id: int, user_id: Optional[int], scope: str, target_id: Optional[int],
                 reason: str, terminate_chains: bool = True) -> KillSwitchEvent:
    """Stop the scope now. The caller writes the audit record (which commits)."""
    if scope not in SCOPES:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "kill_switch.bad_scope")
    reason = (reason or "").strip()
    if len(reason) < 3:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "kill_switch.reason_required")
    if scope == "team":
        # the sub-teams cannot change while they are collected (teams lock first, then ours)
        from app.services.teams import _lock_hierarchy

        await _lock_hierarchy(db, org_id)
    await lock(db, org_id)

    # created_at set here: the response reads it without another round trip
    event = KillSwitchEvent(org_id=org_id, scope=scope, reason=reason[:2000], created_by=user_id, created_at=_now())
    stopped: Dict[str, Any] = {"agents": [], "chains": []}
    in_scope = Agent.org_id == org_id
    if scope == "agent":
        agent = (await db.execute(
            select(Agent).where(Agent.id == target_id, Agent.org_id == org_id))).scalar_one_or_none()
        if agent is None:
            raise api_error(status.HTTP_404_NOT_FOUND, "agent.not_found")
        if agent.status == "retired":
            raise api_error(status.HTTP_409_CONFLICT, "agent.retired_final")
        event.agent_id, event.target_name = agent.id, agent.name
        in_scope = in_scope & (Agent.id == agent.id)
    elif scope == "team":
        team = (await db.execute(
            select(Team).where(Team.id == target_id, Team.org_id == org_id))).scalar_one_or_none()
        if team is None:
            raise api_error(status.HTTP_404_NOT_FOUND, "team.not_found")
        event.team_id, event.target_name = team.id, team.name
        stopped["team_ids"] = await _team_ids(db, org_id, team.id)
        in_scope = in_scope & Agent.team_id.in_(stopped["team_ids"])
    elif target_id is not None:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "kill_switch.no_target_expected")

    for e in await active_events(db, org_id):
        same = e.scope == scope and (scope in ORG_WIDE or (e.agent_id or e.team_id) == target_id)
        if same:
            raise api_error(status.HTTP_409_CONFLICT, "kill_switch.already_active", event_id=e.id)

    agents = list((await db.execute(
        select(Agent).where(in_scope, Agent.status != "retired").order_by(Agent.id).with_for_update()
    )).scalars())
    for a in agents:
        if a.status == "active":  # quarantined / suspended ones are already stopped: not ours to give back
            stopped["agents"].append({"id": a.id, "name": a.name, "status": a.status})
            a.status = "suspended"

    if terminate_chains and agents:
        chains = (await db.execute(
            select(DelegationChain).where(DelegationChain.org_id == org_id,
                                          DelegationChain.root_agent_id.in_([a.id for a in agents]),
                                          DelegationChain.status.in_(("active", "tripped")))
        )).scalars().all()
        for c in chains:
            c.status = "terminated"
            c.completed_at = _now()
            stopped["chains"].append(c.id)

    event.stopped = stopped
    db.add(event)
    await db.flush()
    return event


async def get_event(db: AsyncSession, org_id: int, event_id: int, for_update: bool = False) -> KillSwitchEvent:
    q = select(KillSwitchEvent).where(KillSwitchEvent.id == event_id, KillSwitchEvent.org_id == org_id)
    if for_update:
        q = q.with_for_update()
    e = (await db.execute(q)).scalar_one_or_none()
    if e is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "kill_switch.not_found")
    return e


async def lift(db: AsyncSession, org_id: int, user_id: Optional[int], event_id: int,
               reason: Optional[str]) -> KillSwitchEvent:
    """Undo one stop. The caller writes the audit record (which commits)."""
    await lock(db, org_id)
    event = await get_event(db, org_id, event_id, for_update=True)
    if event.lifted_at is not None:
        raise api_error(status.HTTP_409_CONFLICT, "kill_switch.already_lifted")
    event.lifted_at = _now()
    event.lifted_by = user_id
    event.lift_reason = (reason or "").strip()[:2000] or None
    others = [e for e in await active_events(db, org_id, for_update=True) if e.id != event.id]

    from app.services.teams import role_requires_hybrid

    restored: List[Dict[str, Any]] = []
    kept: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    for rec in (event.stopped or {}).get("agents") or []:
        agent = (await db.execute(
            select(Agent).where(Agent.id == rec["id"], Agent.org_id == org_id).with_for_update()
        )).scalar_one_or_none()
        if agent is None or agent.status != "suspended":
            # changed since the stop (retired, switched on, quarantined): leave it
            skipped.append({"id": rec["id"], "name": rec.get("name"),
                            "status": agent.status if agent else "deleted"})
            continue
        holder = await covering(db, agent, others)
        if holder is not None:
            _add_agent(holder, agent, rec.get("status") or "active")
            kept.append({"id": agent.id, "name": agent.name, "event_id": holder.id})
            continue
        previous = rec.get("status") or "active"
        if previous == "active" and not agent.pq_public_key and await role_requires_hybrid(db, agent):
            # its role now wants a hybrid key: it comes back only with one
            skipped.append({"id": agent.id, "name": agent.name, "status": "suspended",
                            "why": "role.requires_hybrid"})
            continue
        agent.status = previous
        restored.append({"id": agent.id, "name": agent.name})
    event.lift_result = {"restored": restored, "kept": kept, "skipped": skipped,
                         "chains_not_resumed": len((event.stopped or {}).get("chains") or [])}
    await db.flush()
    return event


def event_out(e: KillSwitchEvent, users: Optional[Dict[int, str]] = None) -> Dict[str, Any]:
    users = users or {}
    s = e.stopped or {}
    return {
        "id": e.id, "scope": e.scope, "agent_id": e.agent_id, "team_id": e.team_id,
        "target_name": e.target_name, "reason": e.reason, "active": e.lifted_at is None,
        "agents": s.get("agents") or [], "chains": s.get("chains") or [], "team_ids": s.get("team_ids") or [],
        "created_at": e.created_at, "created_by": e.created_by, "created_by_email": users.get(e.created_by),
        "lifted_at": e.lifted_at, "lifted_by": e.lifted_by, "lifted_by_email": users.get(e.lifted_by),
        "lift_reason": e.lift_reason, "lift_result": e.lift_result,
    }


async def emails(db: AsyncSession, ids) -> Dict[int, str]:
    from app.models.user import User

    ids = {i for i in ids if i}
    if not ids:
        return {}
    return dict((await db.execute(select(User.id, User.email).where(User.id.in_(ids)))).all())


async def list_events(db: AsyncSession, org_id: int, limit: int = 100) -> List[Dict[str, Any]]:
    rows = list((await db.execute(
        select(KillSwitchEvent).where(KillSwitchEvent.org_id == org_id)
        .order_by(KillSwitchEvent.lifted_at.is_(None).desc(), KillSwitchEvent.id.desc()).limit(limit)
    )).scalars())
    users = await emails(db, [r.created_by for r in rows] + [r.lifted_by for r in rows])
    return [event_out(r, users) for r in rows]


async def overview(db: AsyncSession, org_id: int) -> Dict[str, Any]:
    from sqlalchemy import func

    events = await active_events(db, org_id)
    counts = dict((await db.execute(
        select(Agent.status, func.count()).where(Agent.org_id == org_id).group_by(Agent.status))).all())
    users = await emails(db, [e.created_by for e in events])
    return {
        "traffic_stopped": any(e.scope == "org_traffic" for e in events),
        "all_agents_stopped": any(e.scope in ORG_WIDE for e in events),
        "active": [event_out(e, users) for e in events],
        "agents": {k: int(v) for k, v in counts.items()},
    }


async def notify(db: AsyncSession, event: KillSwitchEvent, lifted: bool) -> None:
    """Tell the organization's channels; delivery problems never undo the stop."""
    from app.services.notification_service import notify as send

    what = {"agent": f"agent {event.target_name}", "team": f"team {event.target_name}",
            "all_agents": "all agents", "org_traffic": "all AI traffic"}[event.scope]
    if lifted:
        r = event.lift_result or {}
        subject = f"Kill switch lifted: {what}"
        message = (f"The stop of {what} was lifted. Restored {len(r.get('restored') or [])} agent(s), "
                   f"{len(r.get('kept') or [])} still held by another stop.")
    else:
        subject = f"Kill switch: {what} stopped"
        message = (f"{what.capitalize()} stopped. Reason: {event.reason}. "
                   f"Agents suspended: {len((event.stopped or {}).get('agents') or [])}.")
    try:  # a slow channel must not hold the emergency button: deliveries go on in their threads
        await asyncio.wait_for(send(db, event.org_id, NOTIFY_EVENT, subject, message,
                                    {"event_id": event.id, "scope": event.scope, "lifted": lifted}),
                               NOTIFY_WAIT_SECONDS)
    except Exception:  # pragma: no cover - a channel failing or timing out must not fail the stop
        pass
