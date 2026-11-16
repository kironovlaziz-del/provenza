# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Automatic containment - an agent that keeps reaching past its boundaries is
stopped without waiting for a person.

A refused call is not a problem by itself: an agent learns what it may do by
trying. An agent that is refused for reaching past what it was given - a
tool, a model, a route or a task it has no right to, a capability it was not
delegated - again and again in a short time is looking for another way in.
Each such refusal is marked on its check (ActionCheck.boundary, set from
Decision.boundary by the policy engine, the egress catalog, the egress
proxy's route rules and the task check). Refusals that are not the agent's
doing do not count: the agent stopped, a chain halted, a tool that changed
upstream, a task that ended or ran out, a call that waits for a person.

    containment_max_boundary   such refusals ...           (default 3)
    containment_window_seconds ... within this window       (default 600)
    tripwire_tools             tool patterns no agent has a reason to call
                               (decoys): one call is enough (default none)

reached -> the agent is quarantined at once, whatever the behaviour
monitor's mode (app/services/behavior_monitor.py): status "quarantined"
(every later call is refused), the chains it roots are tripped, a critical
rogue_agent_quarantined incident names the refusals that led to it, and the
calls it left waiting for a person are closed - an approval given after this
releases nothing. Counting restarts at the release, which a person signs
with their session key (release_statement / release).
"""

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from fastapi import status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_signing import content_hash
from app.core.errors import api_error
from app.core.policy_doc import matches
from app.models.agent import Agent
from app.models.agent_action import ActionCheck, AgentAction, AgentIncident
from app.models.approval import AgentActionApproval
from app.models.behavior import AgentBaseline
from app.models.user import User
from app.services import signing_sessions
from app.services.audit_service import AuditService

RELEASE = "provenza.agent.release"
V = 1
KEPT = 10          # boundary refusals named in the incident
MAX_TRIPWIRES = 50


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def released_at(db: AsyncSession, agent_id: int) -> Optional[datetime]:
    """When a person last released the agent from quarantine, or None."""
    return _aware((await db.execute(select(AgentBaseline.quarantine_released_at).where(
        AgentBaseline.agent_id == agent_id))).scalar_one_or_none())


async def _settings(db: AsyncSession, org_id: int) -> dict:
    from app.services.behavior_monitor import BehaviorMonitor

    return await BehaviorMonitor(db).settings(org_id)


async def _locked_agent(db: AsyncSession, org_id: int, agent_id: int) -> Optional[Agent]:
    """One decision at a time per agent: two refusals at once must not both
    quarantine it, nor both miss the limit."""
    return (await db.execute(select(Agent).where(Agent.id == agent_id, Agent.org_id == org_id)
                             .with_for_update())).scalar_one_or_none()


async def tripwire(db: AsyncSession, org_id: int, agent_id: int, tool_name: Optional[str]) -> bool:
    """Before the verdict: a call to a tripwire tool quarantines the agent, so
    this very call is already refused. True when it did."""
    if not tool_name:
        return False
    cfg = await _settings(db, org_id)
    if not cfg["containment_enabled"] or not cfg["tripwire_tools"] or not matches(tool_name, cfg["tripwire_tools"]):
        return False
    agent = await _locked_agent(db, org_id, agent_id)
    if agent is None or agent.status != "active":
        await db.commit()
        return False
    await _contain(db, org_id, agent, {"reason": "tripwire", "tool": tool_name,
                                       "tripwire_tools": cfg["tripwire_tools"]})
    return True


async def after_check(db: AsyncSession, org_id: int, chk: ActionCheck) -> bool:
    """After the verdict: count the agent's boundary refusals since the window
    opened (or since its last release) and quarantine it at the limit. True
    when it did."""
    if not chk.boundary:
        return False
    cfg = await _settings(db, org_id)
    if not cfg["containment_enabled"]:
        return False
    agent = await _locked_agent(db, org_id, chk.agent_id)
    if agent is None or agent.status != "active":
        await db.commit()
        return False
    now = datetime.now(timezone.utc)
    since = now - timedelta(seconds=cfg["containment_window_seconds"])
    released = await released_at(db, agent.id)
    if released is not None and released > since:
        since = released
    cond = (ActionCheck.org_id == org_id, ActionCheck.agent_id == agent.id, ActionCheck.boundary.is_(True),
            ActionCheck.created_at >= since)
    count = (await db.execute(select(func.count()).select_from(ActionCheck).where(*cond))).scalar_one()
    if count < cfg["containment_max_boundary"]:
        await db.commit()
        return False
    rows = (await db.execute(select(ActionCheck).where(*cond).order_by(ActionCheck.id.desc()).limit(KEPT))).scalars()
    await _contain(db, org_id, agent, {
        "reason": "boundary_refusals", "count": count, "limit": cfg["containment_max_boundary"],
        "window_seconds": cfg["containment_window_seconds"],
        "refusals": [{"check_id": r.id, "tool": r.tool_name, "action_type": r.action_type, "reason": r.reason,
                      "at": _aware(r.created_at).isoformat() if r.created_at else None} for r in rows],
    })
    return True


async def _contain(db: AsyncSession, org_id: int, agent: Agent, why: Dict[str, Any]) -> None:
    from app.services.behavior_monitor import BehaviorMonitor

    closed = await _close_pending(db, org_id, agent.id)
    await BehaviorMonitor(db)._quarantine(org_id, agent, {"contained": why, "closed_approvals": closed})
    await AuditService(db).log(org_id, None, "agent", agent.id, "contained",
                               {"reason": why["reason"], "closed_approvals": closed})
    await db.commit()


async def _close_pending(db: AsyncSession, org_id: int, agent_id: int) -> list:
    """The agent's calls waiting for a person are closed as the approval
    window closing is: denied, with an "expired" decision. An approval
    already given and not used yet is not redeemed either
    (app/pvp/approvals.py looks only after the release)."""
    pending = (await db.execute(select(AgentAction).where(
        AgentAction.org_id == org_id, AgentAction.agent_id == agent_id,
        AgentAction.policy_check_result == "pending_approval").with_for_update())).scalars().all()
    for action in pending:
        action.policy_check_result = "denied"
        action.reason = (action.reason or "") + " | agent quarantined"
        db.add(AgentActionApproval(org_id=org_id, action_id=action.id, decision="expired",
                                   input_sha256=content_hash(action.input_data or {}), reason="agent quarantined"))
    return [a.id for a in pending]


# ---------------------------------------------------------------------------- release, signed

async def _quarantined(db: AsyncSession, org_id: int, agent_id: int, lock: bool = False) -> Agent:
    q = select(Agent).where(Agent.id == agent_id, Agent.org_id == org_id)
    agent = (await db.execute(q.with_for_update() if lock else q)).scalar_one_or_none()
    if agent is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "agent.not_found")
    if agent.status != "quarantined":
        raise api_error(status.HTTP_409_CONFLICT, "containment.not_quarantined", status=agent.status)
    from app.services import kill_switch

    await kill_switch.check_reactivation(db, agent)
    return agent


async def _last_quarantine(db: AsyncSession, org_id: int, agent_id: int) -> Optional[int]:
    from app.services.behavior_monitor import QUARANTINE_INCIDENT

    return (await db.execute(select(AgentIncident.id).where(
        AgentIncident.org_id == org_id, AgentIncident.agent_id == agent_id,
        AgentIncident.incident_type == QUARANTINE_INCIDENT).order_by(AgentIncident.id.desc()).limit(1))
    ).scalar_one_or_none()


def build_release(user: User, session_id: str, agent: Agent, incident_id: Optional[int]) -> Dict[str, Any]:
    """The release statement, without issued_at (taken from what the browser
    signed). It names the quarantine it ends: a signature over it releases
    that one, never a later one."""
    return {"type": RELEASE, "v": V, "org_id": user.org_id, "user_id": user.id, "session_id": session_id,
            "agent_id": agent.id, "incident_id": incident_id}


async def release_statement(db: AsyncSession, user: User, agent_id: int) -> Dict[str, Any]:
    """What the person's session key signs to release the agent."""
    s = signing_sessions.require_certified(getattr(user, "_signing_session", None))
    agent = await _quarantined(db, user.org_id, agent_id)
    return dict(build_release(user, s.id, agent, await _last_quarantine(db, user.org_id, agent.id)),
                issued_at=int(time.time()))


async def release(db: AsyncSession, user: User, agent_id: int, signed_statement: Any, signature: Any) -> dict:
    s = signing_sessions.require_certified(getattr(user, "_signing_session", None))
    agent = await _quarantined(db, user.org_id, agent_id, lock=True)
    incident_id = await _last_quarantine(db, user.org_id, agent.id)
    proof = await signing_sessions.verify_signed(db, s, build_release(user, s.id, agent, incident_id),
                                                 signed_statement, signature)
    from app.services.behavior_monitor import BehaviorMonitor

    bl = await BehaviorMonitor(db).baseline(user.org_id, agent.id)
    agent.status = "active"
    bl.quarantine_released_at = datetime.now(timezone.utc)
    bl.quarantine_release = proof
    await AuditService(db).log(user.org_id, user.id, "agent", agent.id, "quarantine_released", {
        "incident_id": incident_id, "statement_sha256": content_hash(proof["statement"])})
    await db.commit()
    return {"agent_id": agent.id, "status": "active", "incident_id": incident_id}


def clean_tripwires(values: Any) -> list:
    out = sorted({str(v).strip() for v in (values or []) if str(v).strip()})
    if len(out) > MAX_TRIPWIRES or any(len(v) > 100 for v in out):
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "containment.bad_tripwires", max=MAX_TRIPWIRES)
    return out
