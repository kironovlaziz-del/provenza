# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Discovery read side: the devices that report telemetry and the AI agents
found running on them (both written by TelemetryService), plus the review
of a finding: link it to the governed Agent it became, or ignore it.
"""

from datetime import datetime, timezone
from typing import List, Optional, Tuple

from fastapi import status
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import api_error
from app.models.agent import Agent
from app.models.endpoint_device import DiscoveredAgent, EndpointDevice
from app.models.ingestion_source import IngestionSource
from app.services.agent_catalog import describe

FOUND_STATUSES = ("new", "registered", "ignored")


class EndpointInventory:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------ devices
    def _device_query(self, org_id: int):
        counts = (
            select(
                DiscoveredAgent.device_id.label("device_id"),
                func.count().label("total"),
                func.count().filter(DiscoveredAgent.status == "new").label("new"),
            )
            .where(DiscoveredAgent.org_id == org_id)
            .group_by(DiscoveredAgent.device_id)
            .subquery()
        )
        return (
            select(EndpointDevice, IngestionSource, counts.c.total, counts.c.new)
            .join(IngestionSource, IngestionSource.id == EndpointDevice.ingestion_source_id)
            .outerjoin(counts, counts.c.device_id == EndpointDevice.id)
            .where(EndpointDevice.org_id == org_id)
        )

    @staticmethod
    def _device_out(d: EndpointDevice, src: IngestionSource, total, new) -> dict:
        return {
            "id": d.id, "host_id": d.host_id,
            "source": {"id": src.id, "name": src.name, "source_type": src.source_type},
            "last_user": d.last_user, "os": d.os, "agent_version": d.agent_version,
            "first_seen_at": d.first_seen_at, "last_seen_at": d.last_seen_at,
            "event_count": int(d.event_count or 0), "agents_found": int(total or 0), "agents_new": int(new or 0),
        }

    async def list_devices(self, org_id: int, q: Optional[str], skip: int, limit: int) -> Tuple[List[dict], int]:
        query = self._device_query(org_id)
        if q:
            esc = q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            like = f"%{esc}%"
            query = query.where(EndpointDevice.host_id.ilike(like, escape="\\")
                                | EndpointDevice.last_user.ilike(like, escape="\\"))
        total = (await self.db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
        rows = (await self.db.execute(
            query.order_by(EndpointDevice.last_seen_at.desc(), EndpointDevice.id.desc()).offset(skip).limit(limit)
        )).all()
        return [self._device_out(*r) for r in rows], total

    async def device(self, org_id: int, device_id: int) -> dict:
        row = (await self.db.execute(
            self._device_query(org_id).where(EndpointDevice.id == device_id)
        )).one_or_none()
        if row is None:
            raise api_error(status.HTTP_404_NOT_FOUND, "device.not_found")
        out = self._device_out(*row)
        out["agents"], _ = await self.list_found(org_id, None, 0, 500, device_id=device_id)
        return out

    # ------------------------------------------------------------ agents found
    async def list_found(self, org_id: int, status_filter: Optional[str], skip: int, limit: int,
                         device_id: Optional[int] = None) -> Tuple[List[dict], int]:
        query = (
            select(DiscoveredAgent, EndpointDevice.host_id, EndpointDevice.last_user, Agent.id, Agent.name)
            .join(EndpointDevice, EndpointDevice.id == DiscoveredAgent.device_id)
            .outerjoin(Agent, (Agent.id == DiscoveredAgent.registered_agent_id) & (Agent.org_id == org_id))
            .where(DiscoveredAgent.org_id == org_id)
        )
        if status_filter:
            query = query.where(DiscoveredAgent.status == status_filter)
        if device_id is not None:
            query = query.where(DiscoveredAgent.device_id == device_id)
        total = (await self.db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
        # new first, then by how recently they were seen
        order = case((DiscoveredAgent.status == "new", 0), else_=1)
        rows = (await self.db.execute(
            query.order_by(order, DiscoveredAgent.last_seen_at.desc(), DiscoveredAgent.id.desc())
            .offset(skip).limit(limit)
        )).all()
        return [self._found_out(*r) for r in rows], total

    @staticmethod
    def _found_out(f: DiscoveredAgent, host: str, user: Optional[str], agent_id, agent_name) -> dict:
        info = describe(f.product)
        return {
            "id": f.id, "product": f.product, "name": info["name"], "vendor": info["vendor"],
            "category": info["category"], "device_id": f.device_id, "device_host": host, "device_user": user,
            "risk_score": f.risk_score, "evidence": f.evidence, "status": f.status,
            "registered_agent": {"id": agent_id, "name": agent_name} if agent_id else None,
            "decided_at": f.decided_at, "first_seen_at": f.first_seen_at, "last_seen_at": f.last_seen_at,
            "seen_count": f.seen_count,
        }

    async def summary(self, org_id: int) -> dict:
        by = dict((await self.db.execute(
            select(DiscoveredAgent.status, func.count()).where(DiscoveredAgent.org_id == org_id)
            .group_by(DiscoveredAgent.status)
        )).all())
        devices = (await self.db.execute(
            select(func.count()).select_from(EndpointDevice).where(EndpointDevice.org_id == org_id)
        )).scalar_one()
        return {**{s: int(by.get(s, 0)) for s in FOUND_STATUSES}, "devices": int(devices)}

    async def _finding(self, org_id: int, found_id: int) -> DiscoveredAgent:
        f = (await self.db.execute(
            select(DiscoveredAgent).where(DiscoveredAgent.id == found_id, DiscoveredAgent.org_id == org_id)
            .with_for_update()
        )).scalar_one_or_none()
        if f is None:
            raise api_error(status.HTTP_404_NOT_FOUND, "found_agent.not_found")
        return f

    async def link(self, org_id: int, found_id: int, agent_id: int, user_id: int) -> dict:
        """The finding became this governed agent (registered in Agents)."""
        f = await self._finding(org_id, found_id)
        agent = (await self.db.execute(
            select(Agent).where(Agent.id == agent_id, Agent.org_id == org_id)
        )).scalar_one_or_none()
        if agent is None:
            raise api_error(status.HTTP_404_NOT_FOUND, "agent.not_found")
        before = {"status": f.status, "registered_agent_id": f.registered_agent_id}
        f.status, f.registered_agent_id = "registered", agent.id
        f.decided_by, f.decided_at = user_id, datetime.now(timezone.utc)
        await self.db.commit()
        return {"before": before, "after": {"status": f.status, "registered_agent_id": agent.id}}

    async def set_ignored(self, org_id: int, found_id: int, ignored: bool, user_id: int) -> dict:
        f = await self._finding(org_id, found_id)
        before = f.status
        if ignored:
            f.status = "ignored"
        else:
            # back to review; a link to an agent that still exists is kept
            f.status = "registered" if f.registered_agent_id else "new"
        f.decided_by, f.decided_at = user_id, datetime.now(timezone.utc)
        await self.db.commit()
        return {"before": before, "after": f.status}
