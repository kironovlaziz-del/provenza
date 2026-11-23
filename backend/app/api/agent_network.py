# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza - https://github.com/kironovlaziz-del/provenza

"""
An agent's own network (app/services/agent_network.py):

    GET  /api/v1/agents/{id}/network           its workload, where it runs, where it went
    POST /api/v1/agents/{id}/network           a workload in observe mode, for an agent made before
    POST /api/v1/agents/{id}/network/enforce   allow these destinations, refuse the rest

Administrators only, as every egress workload.
"""

import ipaddress
import re
from datetime import datetime
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
from app.core.errors import api_error
from app.models.user import User, UserRole
from app.services import agent_network as net
from app.services.agent_registry import AgentRegistry

router = APIRouter()

_NAME = re.compile(r"^(\*\.)?[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$")


class NetworkWorkloadOut(BaseModel):
    id: int
    name: str
    mode: str
    dns: str
    enabled: bool
    isolated: bool
    egress_allow: List[dict]


class RunningOut(BaseModel):
    sensor_id: int
    sensor: str
    hostname: Optional[str] = None
    cgroups: int
    processes: int
    last_seen_at: Optional[datetime] = None


class DestinationOut(BaseModel):
    dest: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    count: int
    last_at: datetime
    address: Optional[str] = None
    named: bool
    blocked: bool


class NetworkOut(BaseModel):
    agent_id: int
    workload: Optional[NetworkWorkloadOut] = None
    running: List[RunningOut] = Field(default_factory=list)
    destinations: List[DestinationOut] = Field(default_factory=list)


class DestinationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dest: str = Field(min_length=1, max_length=255)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    protocol: Optional[Literal["tcp", "udp"]] = None

    @field_validator("dest")
    @classmethod
    def _dest(cls, v: str) -> str:
        v = v.strip().lower().rstrip(".")
        try:
            return str(ipaddress.ip_network(v, strict=False))
        except ValueError:
            pass
        if not _NAME.match(v):
            raise ValueError("not a host name, an address or a network")
        return v


class EnforceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    destinations: List[DestinationIn] = Field(max_length=500)


async def _agent(db: AsyncSession, agent_id: int, user: User):
    return await AgentRegistry(db).get_agent(agent_id, user.org_id)  # 404 for another organization's


@router.get("/{agent_id}/network", response_model=NetworkOut, summary="The agent's own network")
async def get_network(agent_id: int, db: AsyncSession = Depends(get_db),
                      current_user: User = Depends(require_role(UserRole.admin))):
    return await net.network_state(db, await _agent(db, agent_id, current_user))


@router.post("/{agent_id}/network", response_model=NetworkOut, status_code=status.HTTP_201_CREATED,
             summary="Observe the agent's network (a workload in observe mode)")
async def observe_network(agent_id: int, db: AsyncSession = Depends(get_db),
                          current_user: User = Depends(require_role(UserRole.admin))):
    agent = await _agent(db, agent_id, current_user)
    await net.ensure_agent_workload(db, agent, current_user.id)
    await db.commit()
    return await net.network_state(db, agent)


@router.post("/{agent_id}/network/enforce", response_model=NetworkOut,
             summary="Allow these destinations to the agent and refuse the rest")
async def enforce_network(agent_id: int, data: EnforceIn, db: AsyncSession = Depends(get_db),
                          current_user: User = Depends(require_role(UserRole.admin))):
    agent = await _agent(db, agent_id, current_user)
    w = await net.agent_workload(db, agent.org_id, agent.id)
    if w is None:
        raise api_error(status.HTTP_409_CONFLICT, "agent_network.not_observed")
    rules = net.allow_rules([d.model_dump() for d in data.destinations])
    await net.enforce(db, agent, w, rules, current_user.id)
    await db.commit()
    return await net.network_state(db, agent)
