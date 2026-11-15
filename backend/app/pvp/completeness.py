# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Completeness report - every action of one agent over a period, shown to be
all of them (docs/proof-of-authority.md, "Completeness").

Actions are sealed in batches (app/pvp/seal.py) and each seal names the one
before it, so the seals form a chain in the signed audit log. The report
carries a run of consecutive seals that covers the period, each with every
action it seals (all agents' - an action's evidence holds ids, hashes and
signatures, never its input or output) and the inclusion proof of its audit
record. tools/provenza_audit.py completeness then checks offline that

  - each seal's record is in the signed log and its root is exactly the
    Merkle root of the evidence given for it - nothing added or dropped;
  - each seal names the one before it - no seal left out in between;

so the agent's actions in those seals are all the actions Provenza recorded
for it between the first and the last of them.

What it cannot show: an action Provenza never saw (an agent calling a tool
directly, without the egress lockdown or the sensor), and actions before the
first chained seal (seals written before the chain existed name no
predecessor).
"""

import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import api_error
from app.models.agent import Agent
from app.models.agent_action import AgentAction
from app.models.pvp_seal import PVPActionSeal
from app.pvp import seal as seals
from app.services import audit_proofs

TYPE = "completeness"
V = 1
MAX_SEALS = 500
MAX_ACTIONS = 20_000


async def _seal_everything(db: AsyncSession, org_id: int) -> None:
    for _ in range(100):
        s = await seals.seal_org(db, org_id)
        if s is None or s.size < seals.MAX_BATCH:
            return


async def build(db: AsyncSession, org_id: int, agent_id: int, since: int, until: int) -> Dict[str, Any]:
    if until < since:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "pvp.bad_period")
    agent = (await db.execute(select(Agent.id).where(Agent.id == agent_id, Agent.org_id == org_id))).first()
    if agent is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "agent.not_found")
    await _seal_everything(db, org_id)
    start = datetime.fromtimestamp(since, timezone.utc)
    end = datetime.fromtimestamp(until, timezone.utc)
    # the seals holding any of the organization's actions of the period
    lo_hi = (await db.execute(select(func.min(AgentAction.seal_id), func.max(AgentAction.seal_id)).where(
        AgentAction.org_id == org_id, AgentAction.seal_id.is_not(None),
        and_(AgentAction.created_at >= start, AgentAction.created_at <= end)))).first()
    if lo_hi is None or lo_hi[0] is None:
        raise api_error(status.HTTP_409_CONFLICT, "pvp.no_actions_in_period")
    # one seal on each side as well: its actions, recorded before and after
    # the period, show the run of seals reaches past both ends of it
    lo = (await db.execute(select(func.max(PVPActionSeal.id)).where(
        PVPActionSeal.org_id == org_id, PVPActionSeal.id < lo_hi[0]))).scalar() or lo_hi[0]
    hi = (await db.execute(select(func.min(PVPActionSeal.id)).where(
        PVPActionSeal.org_id == org_id, PVPActionSeal.id > lo_hi[1]))).scalar() or lo_hi[1]
    rows = list((await db.execute(select(PVPActionSeal).where(
        PVPActionSeal.org_id == org_id, PVPActionSeal.id >= lo, PVPActionSeal.id <= hi)
        .order_by(PVPActionSeal.id).limit(MAX_SEALS + 1))).scalars())
    if len(rows) > MAX_SEALS or sum(r.size for r in rows) > MAX_ACTIONS:
        raise api_error(status.HTTP_409_CONFLICT, "pvp.period_too_large", max_actions=MAX_ACTIONS)
    proofs = await audit_proofs.inclusion_proofs(db, org_id, [r.audit_log_id for r in rows])
    # seals written before the chain existed name no predecessor: the report starts after them
    while rows and "prev_seal_id" not in (proofs[rows[0].audit_log_id]["record"]["payload"].get("metadata") or {}):
        rows.pop(0)
    if not rows:
        raise api_error(status.HTTP_409_CONFLICT, "pvp.period_before_seal_chain")
    out: List[Dict[str, Any]] = []
    for r in rows:
        members = list((await db.execute(select(AgentAction.evidence).where(
            AgentAction.seal_id == r.id).order_by(AgentAction.id))).scalars())
        out.append({"seal_id": r.id, "audit_proof": proofs[r.audit_log_id], "members": members})
    return {"pvp": "pvp/1", "type": TYPE, "v": V, "org_id": org_id, "agent_id": agent_id,
            "period": {"since": since, "until": until}, "issued_at": int(time.time()), "seals": out}
