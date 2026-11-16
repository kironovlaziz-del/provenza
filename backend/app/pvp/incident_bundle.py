# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Incident bundle - one file with what is needed to investigate an agent
incident, every piece that can be signed checked offline
(docs/incident-bundle.md):

  signed, checked by tools/provenza_audit.py incident
    actions       every action Provenza recorded for the agent in the window,
                  shown to be all of them (a completeness report, app/pvp/completeness.py)
    audit         the audit log records about the agent (quarantined with
                  the refusals that led to it, released, stopped, its tasks,
                  its key) and about what governs every agent (the kill
                  switch, the behaviour monitor's settings, policy releases,
                  agent identity, the Tool Registry), each with its inclusion proof
    checks        each check whose request the agent signed carries that
                  signed request: the agent itself asked for that call
    tasks         the tasks a person gave the agent in the window, signed,
                  and what ended them
    approvals     the decisions people signed on its held calls
    release       the signed release from quarantine, when there is one
    delegation    the hops of the chains it is part of, signed by the
                  delegating agents

  the server's word (named so by the verifier)
    the incident itself and the agent's other incidents of the window, the
    checks the agent did not sign, the agent as it is now, the chains' state.

Like a receipt the file holds ids, hashes, verdicts and reasons - never the
input or output of a call.
"""

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_signing import key_fingerprint
from app.core.errors import api_error
from app.models.agent import Agent
from app.models.agent_action import ActionCheck, AgentAction, AgentIncident
from app.models.approval import AgentActionApproval
from app.models.audit_log import AIAuditLog
from app.models.behavior import AgentBaseline
from app.models.delegation import DelegationChain, DelegationHop
from app.models.task_mandate import TaskMandate
from app.services import audit_proofs

TYPE = "incident"
V = 1
BEFORE = 3600              # default window: an hour before the incident ...
AFTER = 900                # ... and a quarter of an hour after it
MAX_WINDOW = 7 * 86400
MAX_CHECKS = 5000
MAX_AUDIT = 1000
MAX_CHAINS = 50
MAX_INCIDENTS = 500
# what governs every agent: changes to it in the window belong to any agent's story
CONTEXT = ("kill_switch", "behavior_monitor", "policy_release", "agent_identity", "tool_registry")


def _ts(dt: Optional[datetime]) -> Optional[int]:
    if dt is None:
        return None
    return int((dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp())


def _incident_out(i: AgentIncident) -> Dict[str, Any]:
    return {"id": i.id, "incident_type": i.incident_type, "severity": i.severity, "agent_id": i.agent_id,
            "chain_id": i.chain_id, "resolved": i.resolved, "at": _ts(i.created_at), "details": i.details}


def _check_out(c: ActionCheck) -> Dict[str, Any]:
    # never the token: it is what an agent presents to record the action. The
    # time to the millisecond, for the order of the timeline.
    at = c.created_at if c.created_at.tzinfo else c.created_at.replace(tzinfo=timezone.utc)
    return {"check_id": c.id, "at": round(at.timestamp(), 3), "chain_id": c.chain_id, "action_type": c.action_type,
            "tool_name": c.tool_name, "input_sha256": c.input_sha256, "decision": c.decision, "reason": c.reason,
            "incident_type": c.incident_type, "boundary": bool(c.boundary), "policy_id": c.policy_id,
            "mandate_id": c.mandate_id, "mandate_sha256": c.mandate_sha256, "release_number": c.release_number,
            "agent_signed": bool(c.agent_signed), "requested": c.requested}


async def build(db: AsyncSession, org_id: int, incident_id: int, since: Optional[int] = None,
                until: Optional[int] = None) -> Dict[str, Any]:
    inc = (await db.execute(select(AgentIncident).where(
        AgentIncident.id == incident_id, AgentIncident.org_id == org_id))).scalar_one_or_none()
    if inc is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "incident.not_found")
    if inc.agent_id is None:
        raise api_error(status.HTTP_409_CONFLICT, "incident.no_agent")
    agent = await db.get(Agent, inc.agent_id)
    at = _ts(inc.created_at) or int(time.time())
    now = int(time.time())
    since = at - BEFORE if since is None else since
    until = min(at + AFTER, now) if until is None else until
    if until < since or until - since > MAX_WINDOW:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "incident.bad_window", max_days=MAX_WINDOW // 86400)
    # the window's seconds are whole: `until` takes in all of its last second
    start, end = datetime.fromtimestamp(since, timezone.utc), datetime.fromtimestamp(until + 1, timezone.utc)

    # every action recorded in the window, shown to be all of them
    from app.pvp import completeness

    report, gap = None, None
    try:
        report = await completeness.build(db, org_id, agent.id, since, until)
    except HTTPException as e:
        d = e.detail
        gap = d.get("code") if isinstance(d, dict) else str(d)

    checks = list((await db.execute(select(ActionCheck).where(
        ActionCheck.org_id == org_id, ActionCheck.agent_id == agent.id,
        ActionCheck.created_at >= start, ActionCheck.created_at < end)
        .order_by(ActionCheck.id).limit(MAX_CHECKS + 1))).scalars())

    # the tasks in force at some time of the window (a chain's root's task covers its helpers)
    tasks = list((await db.execute(select(TaskMandate).where(
        TaskMandate.org_id == org_id, TaskMandate.agent_id == agent.id, TaskMandate.created_at < end,
        TaskMandate.expires_at >= start, or_(TaskMandate.ended_at.is_(None), TaskMandate.ended_at >= start))
        .order_by(TaskMandate.id))).scalars())
    named = {c.mandate_id for c in checks if c.mandate_id} - {t.id for t in tasks}
    if named:
        tasks += list((await db.execute(select(TaskMandate).where(
            TaskMandate.org_id == org_id, TaskMandate.id.in_(named)))).scalars())
    task_ids = [t.id for t in tasks]

    incidents = list((await db.execute(select(AgentIncident).where(
        AgentIncident.org_id == org_id, AgentIncident.agent_id == agent.id,
        AgentIncident.created_at >= start, AgentIncident.created_at < end, AgentIncident.id != inc.id)
        .order_by(AgentIncident.id).limit(MAX_INCIDENTS))).scalars())

    about = [and_(AIAuditLog.entity_type == "agent", AIAuditLog.entity_id == agent.id),
             AIAuditLog.entity_type.in_(CONTEXT)]
    if task_ids:
        about.append(and_(AIAuditLog.entity_type == "task_mandate", AIAuditLog.entity_id.in_(task_ids)))
    log_ids = list((await db.execute(select(AIAuditLog.id).where(
        AIAuditLog.org_id == org_id, AIAuditLog.created_at >= start, AIAuditLog.created_at < end, or_(*about))
        .order_by(AIAuditLog.seq).limit(MAX_AUDIT + 1))).scalars())
    proofs = await audit_proofs.inclusion_proofs(db, org_id, log_ids[:MAX_AUDIT])

    approvals = (await db.execute(select(AgentActionApproval, AgentAction).join(
        AgentAction, AgentAction.id == AgentActionApproval.action_id).where(
        AgentActionApproval.org_id == org_id, AgentAction.agent_id == agent.id,
        AgentActionApproval.decided_at >= start, AgentActionApproval.decided_at < end)
        .order_by(AgentActionApproval.id))).all()

    member = select(DelegationHop.chain_id).where(DelegationHop.org_id == org_id,
                                                  DelegationHop.to_agent_id == agent.id)
    chains = list((await db.execute(select(DelegationChain).where(
        DelegationChain.org_id == org_id, DelegationChain.started_at < end,
        or_(DelegationChain.root_agent_id == agent.id, DelegationChain.id.in_(member)))
        .order_by(DelegationChain.id.desc()).limit(MAX_CHAINS))).scalars())
    from app.pvp.authority import delegation

    delegations = []
    for ch in chains:
        d = await delegation(db, org_id, ch.id)
        delegations.append({**d, "status": ch.status, "breaker_tripped_at": _ts(ch.breaker_tripped_at),
                            "breaker_details": ch.breaker_details})

    release = (await db.execute(select(AgentBaseline.quarantine_release).where(
        AgentBaseline.agent_id == agent.id))).scalar_one_or_none()
    issued = ((release or {}).get("statement") or {}).get("issued_at")
    if not (isinstance(issued, int) and since <= issued <= until):
        release = None   # a release outside the window is another incident's

    from app.services import task_mandates

    return {
        "pvp": "pvp/1", "type": TYPE, "v": V, "org_id": org_id, "issued_at": now,
        "window": {"since": since, "until": until},
        "incident": _incident_out(inc),
        "agent": {"id": agent.id, "name": agent.name, "status": agent.status,
                  "owner_user_id": agent.owner_user_id, "allowed_tools": sorted(agent.allowed_tools or []),
                  "key_fingerprint": key_fingerprint(agent.public_key, agent.pq_public_key)
                  if agent.public_key else None},
        "completeness": report,
        "completeness_gap": gap,
        "checks": [_check_out(c) for c in checks[:MAX_CHECKS]],
        "checks_truncated": len(checks) > MAX_CHECKS,
        "audit": [proofs[i] for i in log_ids[:MAX_AUDIT]],
        "audit_truncated": len(log_ids) > MAX_AUDIT,
        "tasks": [task_mandates.proof(t) for t in tasks],
        "approvals": [{"approval_id": ap.id, "action_id": ap.action_id, "decision": ap.decision,
                       "decided_at": _ts(ap.decided_at), "signed": ap.signed,
                       "action": {"agent_id": a.agent_id, "chain_id": a.chain_id, "action_type": a.action_type,
                                  "tool_name": a.tool_name, "input_sha256": ap.input_sha256}}
                      for ap, a in approvals],
        "release": release,
        "delegation": delegations,
        "other_incidents": [_incident_out(i) for i in incidents],
    }
