# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Runtime daemon (daemon/, eBPF): administration, and the API daemons use.

Admins (/api/v1/runtime):
  workloads    cgroups whose outbound connections are governed, and how
  violations   connections outside a workload's policy, as daemons reported them

Daemons, with an endpoint ingestion key in X-Ingestion-Key (/api/v1/runtime-daemon):
  GET  /config       the organization's enabled workloads
  POST /violations   what they observed, alerted on or blocked

A daemon's discoveries (AI agents found by exec) go to the Shadow AI pipeline,
POST /api/v1/shadow-ai/ingest, with the same key - like the endpoint agent's.
"""

import ipaddress
import re
from datetime import datetime
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_ingestion_source, require_role
from app.core.database import get_db
from app.core.errors import api_error
from app.models.agent import Agent
from app.models.ingestion_source import IngestionSource
from app.models.runtime import RuntimeViolation, RuntimeWorkload
from app.models.user import User, UserRole
from app.services import runtime_daemon as svc
from app.services.audit_service import AuditService

admin_router = APIRouter()
daemon_router = APIRouter()
_admin = require_role(UserRole.admin)

Mode = Literal["observe", "alert", "enforce"]
_SEGMENT = re.compile(r"^[A-Za-z0-9._@:*?\[\]\\-]{1,255}$")
_WILDCARD_ONLY = re.compile(r"^[*?\[\]\\-]+$")


def _patterns(v: Optional[List[str]]) -> Optional[List[str]]:
    """cgroup v2 paths relative to the cgroup root, with shell wildcards per segment."""
    if v is None:
        return v
    if not v or len(v) > 20:
        raise ValueError("1..20 cgroup patterns")
    out = []
    for p in v:
        p = p.strip().strip("/")
        segments = p.split("/") if p else []
        if not segments or len(p) > 500:
            raise ValueError(f"cgroup pattern {p!r}: empty or too long")
        for s in segments:
            if s in (".", "..") or not _SEGMENT.fullmatch(s):
                raise ValueError(f"cgroup pattern {p!r}: bad segment {s!r}")
        if all(_WILDCARD_ONLY.fullmatch(s) for s in segments):
            raise ValueError(f"cgroup pattern {p!r} names nothing: it would govern every process on the host")
        out.append(p)
    return out


class Allow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cidr: str
    ports: List[int] = Field(default_factory=list, max_length=20)   # [] = any port

    @field_validator("cidr")
    @classmethod
    def _cidr(cls, v):
        try:
            return str(ipaddress.ip_network(v.strip(), strict=False))
        except ValueError:
            raise ValueError(f"not an IP network: {v!r}")

    @field_validator("ports")
    @classmethod
    def _ports(cls, v):
        if len(set(v)) != len(v) or any(not 1 <= p <= 65535 for p in v):
            raise ValueError("ports: 1..65535, no repeats")
        return sorted(v)


class WorkloadIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=255)
    agent_id: Optional[int] = None
    cgroup_patterns: List[str]
    egress_allow: List[Allow] = Field(default_factory=list, max_length=100)
    allow_dns: bool = True
    mode: Mode = "observe"
    enabled: bool = True

    @field_validator("cgroup_patterns")
    @classmethod
    def _pat(cls, v):
        return _patterns(v)


class WorkloadUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    agent_id: Optional[int] = None
    unlink_agent: bool = False
    cgroup_patterns: Optional[List[str]] = None
    egress_allow: Optional[List[Allow]] = Field(default=None, max_length=100)
    allow_dns: Optional[bool] = None
    mode: Optional[Mode] = None
    enabled: Optional[bool] = None

    @field_validator("cgroup_patterns")
    @classmethod
    def _pat(cls, v):
        return _patterns(v)


class WorkloadOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    agent_id: Optional[int]
    cgroup_patterns: List[str]
    egress_allow: List[Allow]
    allow_dns: bool
    mode: str
    enabled: bool
    created_at: datetime


async def _get_workload(db: AsyncSession, org_id: int, workload_id: int) -> RuntimeWorkload:
    w = (await db.execute(select(RuntimeWorkload).where(RuntimeWorkload.id == workload_id,
                                                        RuntimeWorkload.org_id == org_id)
                          .execution_options(populate_existing=True))).scalar_one_or_none()
    if w is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "runtime.workload_not_found")
    return w


async def _check_agent(db: AsyncSession, org_id: int, agent_id: Optional[int]) -> None:
    if agent_id is not None and (await db.execute(select(Agent.id).where(
            Agent.id == agent_id, Agent.org_id == org_id))).scalar_one_or_none() is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "runtime.agent_not_found")


# ================================================================ admin: workloads

@admin_router.get("/workloads", response_model=List[WorkloadOut])
async def list_workloads(db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    return list((await db.execute(select(RuntimeWorkload).where(RuntimeWorkload.org_id == user.org_id)
                                  .order_by(RuntimeWorkload.name))).scalars())


@admin_router.post("/workloads", response_model=WorkloadOut)
async def create_workload(data: WorkloadIn, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    await _check_agent(db, org_id, data.agent_id)
    w = RuntimeWorkload(org_id=org_id, name=data.name, agent_id=data.agent_id, cgroup_patterns=data.cgroup_patterns,
                        egress_allow=[a.model_dump() for a in data.egress_allow], allow_dns=data.allow_dns,
                        mode=data.mode, enabled=data.enabled, created_by=user_id)
    try:
        async with db.begin_nested():     # a taken name undoes only this insert
            db.add(w)
            await db.flush()
    except IntegrityError:
        raise api_error(status.HTTP_409_CONFLICT, "runtime.name_taken", name=data.name)
    workload_id = w.id
    await AuditService(db).log(org_id, user_id, "runtime_workload", workload_id, "created",
                               {"name": data.name, "mode": data.mode, "cgroup_patterns": data.cgroup_patterns,
                                "egress_allow": [a.model_dump() for a in data.egress_allow]})
    return await _get_workload(db, org_id, workload_id)


@admin_router.patch("/workloads/{workload_id}", response_model=WorkloadOut)
async def update_workload(workload_id: int, data: WorkloadUpdate, db: AsyncSession = Depends(get_db),
                          user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    w = await _get_workload(db, org_id, workload_id)
    before = {"mode": w.mode, "enabled": w.enabled}
    await _check_agent(db, org_id, data.agent_id)
    changes = data.model_dump(exclude_unset=True, exclude={"unlink_agent"})
    try:
        async with db.begin_nested():
            for key, value in changes.items():
                if value is not None:
                    setattr(w, key, value)
            if data.unlink_agent:
                w.agent_id = None
            await db.flush()
    except IntegrityError:
        raise api_error(status.HTTP_409_CONFLICT, "runtime.name_taken", name=data.name)
    await db.commit()
    await AuditService(db).log(org_id, user_id, "runtime_workload", workload_id, "updated",
                               {"fields": sorted(changes), "before": before})
    return await _get_workload(db, org_id, workload_id)


@admin_router.delete("/workloads/{workload_id}")
async def delete_workload(workload_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    w = await _get_workload(db, org_id, workload_id)
    name = w.name
    await db.delete(w)
    await db.commit()
    await AuditService(db).log(org_id, user_id, "runtime_workload", workload_id, "deleted", {"name": name})
    return {"deleted": True}


class ViolationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    workload_id: Optional[int]
    agent_id: Optional[int]
    host: str
    action: str
    protocol: str
    dst_ip: str
    dst_port: int
    comm: Optional[str]
    cgroup: Optional[str]
    count: int
    first_seen_at: datetime
    last_seen_at: datetime


@admin_router.get("/violations", response_model=List[ViolationOut])
async def list_violations(workload_id: Optional[int] = None, action: Optional[str] = None,
                          db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    q = select(RuntimeViolation).where(RuntimeViolation.org_id == user.org_id)
    if workload_id is not None:
        q = q.where(RuntimeViolation.workload_id == workload_id)
    if action is not None:
        q = q.where(RuntimeViolation.action == action)
    return list((await db.execute(q.order_by(RuntimeViolation.last_seen_at.desc()).limit(500))).scalars())


# ================================================================ the daemons' API

async def current_daemon(source: IngestionSource = Depends(get_ingestion_source)) -> IngestionSource:
    """Only endpoint keys: a browser extension's key ships inside the extension."""
    if source.source_type != "endpoint":
        raise api_error(status.HTTP_403_FORBIDDEN, "runtime.endpoint_key_required")
    return source


@daemon_router.get("/config")
async def daemon_config(db: AsyncSession = Depends(get_db), source: IngestionSource = Depends(current_daemon)):
    rows = (await db.execute(select(RuntimeWorkload).where(RuntimeWorkload.org_id == source.org_id,
                                                           RuntimeWorkload.enabled.is_(True))
                             .order_by(RuntimeWorkload.id))).scalars()
    return {"workloads": [{"id": w.id, "name": w.name, "cgroup_patterns": w.cgroup_patterns,
                           "egress_allow": w.egress_allow, "allow_dns": w.allow_dns, "mode": w.mode}
                          for w in rows],
            "refresh_seconds": 60}


class ViolationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workload_id: int
    action: Literal["observed", "alerted", "blocked"]
    protocol: Literal["tcp", "udp"]
    dst_ip: str
    dst_port: int = Field(ge=0, le=65535)
    comm: Optional[str] = Field(default=None, max_length=64)
    cgroup: Optional[str] = Field(default=None, max_length=500)
    count: int = Field(default=1, ge=1, le=1_000_000_000)

    @field_validator("dst_ip")
    @classmethod
    def _ip(cls, v):
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError:
            raise ValueError(f"not an IP address: {v!r}")


class ViolationBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str = Field(min_length=1, max_length=255)
    events: List[ViolationIn] = Field(min_length=1, max_length=500)


@daemon_router.post("/violations")
async def report_violations(data: ViolationBatch, db: AsyncSession = Depends(get_db),
                            source: IngestionSource = Depends(current_daemon)):
    return await svc.ingest_violations(db, source.org_id, source.id, data.host,
                                       [e.model_dump() for e in data.events])
