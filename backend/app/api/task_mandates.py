# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Task mandates (app/services/task_mandates.py): a person gives an agent a
task, signed with their session key, and can end it. The agent reads the
task in force with its own key and names it on its calls.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.core.errors import api_error
from app.models.user import User, UserRole
from app.services import task_mandates

router = APIRouter()
_signer = require_role(UserRole.admin, UserRole.approver)


class MandateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task: str = Field(min_length=1, max_length=task_mandates.MAX_TASK)
    # None: all of the agent's tools
    tools: Optional[List[str]] = Field(default=None, max_length=200)
    valid_hours: int = Field(ge=1, le=task_mandates.MAX_HOURS)


class SignedMandateIn(MandateIn):
    # the statement from POST .../statement with the session key's signature
    statement: dict
    signature: str = Field(max_length=200)


@router.post("/{agent_id}/mandates/statement")
async def mandate_statement(agent_id: int, data: MandateIn, db: AsyncSession = Depends(get_db),
                            user: User = Depends(_signer)):
    """What the person's session key signs to give the agent this task."""
    return {"statement": await task_mandates.statement(db, user, agent_id, data.task, data.tools,
                                                       data.valid_hours)}


@router.post("/{agent_id}/mandates")
async def give_mandate(agent_id: int, data: SignedMandateIn, db: AsyncSession = Depends(get_db),
                       user: User = Depends(_signer)):
    """Give the task: the signed statement. Ends the agent's task before it."""
    row = await task_mandates.give(db, user, agent_id, data.task, data.tools, data.valid_hours,
                                   data.statement, data.signature)
    return task_mandates.out(row)


@router.get("/{agent_id}/mandates")
async def list_mandates(agent_id: int, db: AsyncSession = Depends(get_db),
                        user: User = Depends(get_current_user)):
    """The task in force and the ones before it."""
    current = await task_mandates.current(db, user.org_id, agent_id)
    return {"current": task_mandates.out(current) if current else None,
            "history": [task_mandates.out(r) for r in await task_mandates.history(db, user.org_id, agent_id)]}


@router.get("/{agent_id}/mandates/current")
async def current_mandate(agent_id: int, request: Request, db: AsyncSession = Depends(get_db),
                          user: User = Depends(get_current_user)):
    """The task in force - what the agent names on its calls (mandate_id).
    The agent reads it with its own key (X-Agent-Key), and only its own."""
    agent = getattr(request.state, "agent", None)
    if agent is not None and agent.id != agent_id:
        raise api_error(403, "http_tool.not_this_agent")
    row = await task_mandates.current(db, user.org_id, agent_id)
    return {"mandate": task_mandates.out(row) if row else None}


class SignedEndIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # the statement from POST .../end/statement with the session key's signature
    statement: dict
    signature: str = Field(max_length=200)


@router.post("/{agent_id}/mandates/{mandate_id}/end/statement")
async def end_statement(agent_id: int, mandate_id: int, db: AsyncSession = Depends(get_db),
                        user: User = Depends(_signer)):
    """What the person's session key signs to end the task."""
    return {"statement": await task_mandates.end_statement(db, user, agent_id, mandate_id)}


@router.post("/{agent_id}/mandates/{mandate_id}/end")
async def end_mandate(agent_id: int, mandate_id: int, data: SignedEndIn, db: AsyncSession = Depends(get_db),
                      user: User = Depends(_signer)):
    """End the task, signed: the agent's calls that name it are refused from now on."""
    return task_mandates.out(await task_mandates.end(db, user, agent_id, mandate_id, data.statement,
                                                     data.signature))
