# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Task mandates - a task a person gives an agent, signed (docs/proof-of-authority.md).

An agent gets its goal from a person and decides on its own how to reach it.
The person's request is the first link of the chain of authority, so it is
signed like an approval: the server builds the statement, the person's
browser signs it with their session key, which their passkey certified
(app/services/signing_sessions.py).

    {"type": "provenza.mandate", "v": 1, "org_id", "user_id", "session_id",
     "agent_id", "task": "<what to do>", "tools": [...] | null,
     "valid_hours": n, "nonce", "issued_at"}

valid until issued_at + valid_hours * 3600. `tools` (a subset of the agent's
allowed tools; null = all of them) narrows what the agent may use for this
task. An agent names the mandate on its calls (`mandate_id` in its signed
action.request); the check then refuses a call outside it - another agent,
another tool, after it ended or expired - and the action's evidence names it.
With the organization's require_task_mandate on, a call that names none is
refused. A task counts only when the agent named it inside its verified
signed request: named by anyone holding only the agent's API key, it is
refused.

One mandate is in force per agent: giving a new one ends the one before.
A delegated agent acts under the mandate of its chain's root agent.
"""

import hashlib
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_signing import canonical_bytes
from app.core.errors import api_error
from app.models.agent import Agent
from app.models.delegation import DelegationChain
from app.models.task_mandate import TaskMandate
from app.models.user import User
from app.services import signing_sessions
from app.services.audit_service import AuditService

MANDATE = "provenza.mandate"
V = 1
MAX_TASK = 2000
MAX_HOURS = 24 * 7
NONCE = re.compile(r"^[0-9a-f]{32}$")
ENTITY = "task_mandate"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def statement_sha256(statement: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(statement)).hexdigest()


async def _agent(db: AsyncSession, org_id: int, agent_id: int) -> Agent:
    agent = (await db.execute(select(Agent).where(Agent.id == agent_id, Agent.org_id == org_id))
             ).scalar_one_or_none()
    if agent is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "agent.not_found")
    if agent.status != "active":
        raise api_error(status.HTTP_409_CONFLICT, "mandate.agent_not_active")
    return agent


def _clean(agent: Agent, task: Any, tools: Optional[List[str]], hours: Any) -> Tuple[str, Optional[List[str]], int]:
    task = task.strip() if isinstance(task, str) else ""
    if not task or len(task) > MAX_TASK:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "mandate.bad_task", max=MAX_TASK)
    if isinstance(hours, bool) or not isinstance(hours, int) or not 1 <= hours <= MAX_HOURS:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "mandate.bad_hours", max=MAX_HOURS)
    if tools is not None:
        tools = sorted({str(t) for t in tools})
        outside = [t for t in tools if t not in set(agent.allowed_tools or [])]
        if not tools or outside:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "mandate.bad_tools",
                            tools=", ".join(outside) or "-")
    return task, tools, hours


def build(user: User, session_id: int, agent: Agent, task: str, tools: Optional[List[str]], hours: int,
          nonce: str) -> Dict[str, Any]:
    """The statement, without issued_at (taken from what the browser signed)."""
    return {"type": MANDATE, "v": V, "org_id": user.org_id, "user_id": user.id, "session_id": session_id,
            "agent_id": agent.id, "task": task, "tools": tools, "valid_hours": hours, "nonce": nonce}


async def statement(db: AsyncSession, user: User, agent_id: int, task: Any, tools: Optional[List[str]],
                    hours: Any) -> Dict[str, Any]:
    """What the person's session key signs to give the task."""
    s = signing_sessions.require_certified(getattr(user, "_signing_session", None))
    agent = await _agent(db, user.org_id, agent_id)
    task, tools, hours = _clean(agent, task, tools, hours)
    return dict(build(user, s.id, agent, task, tools, hours, secrets.token_hex(16)), issued_at=int(time.time()))


async def give(db: AsyncSession, user: User, agent_id: int, task: Any, tools: Optional[List[str]], hours: Any,
               signed_statement: Any, signature: Any) -> TaskMandate:
    s = signing_sessions.require_certified(getattr(user, "_signing_session", None))
    agent = await _agent(db, user.org_id, agent_id)
    task, tools, hours = _clean(agent, task, tools, hours)
    nonce = signed_statement.get("nonce") if isinstance(signed_statement, dict) else None
    if not isinstance(nonce, str) or not NONCE.match(nonce):
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "session.statement_mismatch")
    proof = await signing_sessions.verify_signed(db, s, build(user, s.id, agent, task, tools, hours, nonce),
                                                 signed_statement, signature)
    st = proof["statement"]
    if (await db.execute(select(TaskMandate.id).where(TaskMandate.org_id == user.org_id,
                                                      TaskMandate.signed["statement"]["nonce"].astext == nonce))
            ).first() is not None:
        raise api_error(status.HTTP_409_CONFLICT, "mandate.replayed")
    now = _now()
    # one task in force per agent: the new one ends the one before
    await db.execute(update(TaskMandate).where(
        TaskMandate.org_id == user.org_id, TaskMandate.agent_id == agent.id, TaskMandate.status == "active")
        .values(status="ended", ended_at=now, ended_by=user.id))
    row = TaskMandate(org_id=user.org_id, agent_id=agent.id, user_id=user.id, task=task, tools=tools,
                      expires_at=datetime.fromtimestamp(st["issued_at"], timezone.utc) + timedelta(hours=hours),
                      status="active", signed=proof, statement_sha256=statement_sha256(st))
    db.add(row)
    await db.flush()
    await AuditService(db).log(user.org_id, user.id, ENTITY, row.id, "given", {
        "agent_id": agent.id, "statement_sha256": row.statement_sha256, "tools": tools, "valid_hours": hours})
    await db.refresh(row)
    return row


async def end(db: AsyncSession, user: User, agent_id: int, mandate_id: int) -> TaskMandate:
    row = (await db.execute(select(TaskMandate).where(
        TaskMandate.id == mandate_id, TaskMandate.org_id == user.org_id, TaskMandate.agent_id == agent_id))
    ).scalar_one_or_none()
    if row is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "mandate.not_found")
    if row.status == "active":
        row.status, row.ended_at, row.ended_by = "ended", _now(), user.id
        await AuditService(db).log(user.org_id, user.id, ENTITY, row.id, "ended", {"agent_id": agent_id})
        await db.refresh(row)
    return row


def in_force(row: TaskMandate, now: Optional[datetime] = None) -> bool:
    now = now or _now()
    exp = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
    return row.status == "active" and exp > now


async def current(db: AsyncSession, org_id: int, agent_id: int) -> Optional[TaskMandate]:
    """The agent's task in force, or None."""
    row = (await db.execute(select(TaskMandate).where(
        TaskMandate.org_id == org_id, TaskMandate.agent_id == agent_id, TaskMandate.status == "active")
        .order_by(TaskMandate.id.desc()).limit(1))).scalar_one_or_none()
    return row if row is not None and in_force(row) else None


async def history(db: AsyncSession, org_id: int, agent_id: int, limit: int = 20) -> List[TaskMandate]:
    return list((await db.execute(select(TaskMandate).where(
        TaskMandate.org_id == org_id, TaskMandate.agent_id == agent_id)
        .order_by(TaskMandate.id.desc()).limit(limit))).scalars())


async def refusal(db: AsyncSession, org_id: int, mandate_id: int, agent_id: int, chain_id: Optional[int],
                  tool_name: Optional[str], action_type: Optional[str]) -> Tuple[Optional[TaskMandate], Optional[str]]:
    """(the mandate, None) when the call is inside it; (None or it, why) when not."""
    row = await db.get(TaskMandate, mandate_id)
    if row is None or row.org_id != org_id:
        return None, f"task #{mandate_id} does not exist"
    if row.status != "active":
        return row, f"task #{row.id} was ended"
    if not in_force(row):
        return row, f"task #{row.id} expired"
    acting_for = row.agent_id == agent_id
    if not acting_for and chain_id is not None:
        root = (await db.execute(select(DelegationChain.root_agent_id).where(
            DelegationChain.id == chain_id, DelegationChain.org_id == org_id))).scalar_one_or_none()
        acting_for = root == row.agent_id
    if not acting_for:
        return row, f"task #{row.id} was given to agent #{row.agent_id}"
    if row.tools is not None and action_type != "model_call" and tool_name not in row.tools:
        return row, f"task #{row.id} does not include the tool {tool_name}"
    return row, None


def out(row: TaskMandate) -> Dict[str, Any]:
    return {"id": row.id, "agent_id": row.agent_id, "user_id": row.user_id, "task": row.task, "tools": row.tools,
            "status": row.status if in_force(row) or row.status == "ended" else "expired",
            "expires_at": row.expires_at, "created_at": row.created_at, "ended_at": row.ended_at,
            "ended_by": row.ended_by, "statement_sha256": row.statement_sha256}


def proof(row: TaskMandate) -> Dict[str, Any]:
    """The mandate as Proof of Authority carries it: the signed statement with
    the session signature, its certificate and the passkey, and its state."""
    return {"mandate_id": row.id, "status": row.status,
            "ended_at": int(row.ended_at.timestamp()) if row.ended_at else None, **row.signed}
