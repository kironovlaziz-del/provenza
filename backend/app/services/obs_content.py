# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Content of one agent event for the live terminal, on request.

reveal()  what the agent sent and got back for ONE event, as stored. Only
          for admins, on an explicit request; the API writes an audit entry
          for every call. The live feed itself carries metadata only.

The LLM gateway keeps no prompt or answer, so an LLM call has only its
verdict reason.
"""

import json
from collections import defaultdict
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent_action import ActionCheck, AgentAction, AgentIncident
from app.models.delegation import DelegationHop
from app.models.gateway import GatewayCall

RAW_LIMIT = 20000     # characters returned by reveal()


def _dump(value) -> Optional[str]:
    if value is None or value == {} or value == []:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, default=str)


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else f"{text[:limit]} … (+{len(text) - limit} chars)"


async def _sections(db: AsyncSession, org_id: int, kind: str, ids: List[int]) -> Dict[int, List[dict]]:
    """{event id: [{"label", "text"}]}"""
    out: Dict[int, List[dict]] = defaultdict(list)

    def add(i, label, value):
        text = _dump(value)
        if text:
            out[i].append({"label": label, "text": text})

    if kind == "action.recorded":
        rows = (await db.execute(select(AgentAction.id, AgentAction.input_data, AgentAction.output_data,
                                        AgentAction.reason)
                                 .where(AgentAction.org_id == org_id, AgentAction.id.in_(ids)))).all()
        for r in rows:
            add(r.id, "input", r.input_data)
            add(r.id, "output", r.output_data)
            add(r.id, "reason", r.reason)
    elif kind == "action.checked":
        rows = (await db.execute(select(ActionCheck.id, ActionCheck.reason, ActionCheck.action_capabilities)
                                 .where(ActionCheck.org_id == org_id, ActionCheck.id.in_(ids)))).all()
        for r in rows:
            add(r.id, "reason", r.reason)
            add(r.id, "capabilities", r.action_capabilities)
    elif kind == "incident.created":
        rows = (await db.execute(select(AgentIncident.id, AgentIncident.details)
                                 .where(AgentIncident.org_id == org_id, AgentIncident.id.in_(ids)))).all()
        for r in rows:
            add(r.id, "details", r.details)
    elif kind == "llm.call":
        rows = (await db.execute(select(GatewayCall.id, GatewayCall.reason)
                                 .where(GatewayCall.org_id == org_id, GatewayCall.id.in_(ids)))).all()
        for r in rows:
            add(r.id, "reason", r.reason)
    elif kind == "delegation.hop":
        rows = (await db.execute(select(DelegationHop.id, DelegationHop.task_description,
                                        DelegationHop.delegated_capabilities, DelegationHop.depth)
                                 .where(DelegationHop.org_id == org_id, DelegationHop.id.in_(ids)))).all()
        for r in rows:
            add(r.id, "task", r.task_description)
            add(r.id, "capabilities", r.delegated_capabilities)
    return out


async def reveal(db: AsyncSession, org_id: int, kind: str, event_id: int) -> Optional[List[dict]]:
    """The content of one event, or None when it does not exist."""
    secs = (await _sections(db, org_id, kind, [event_id])).get(event_id)
    if secs is None:
        return None
    return [{"label": s["label"], "text": _cut(s["text"], RAW_LIMIT)} for s in secs]
