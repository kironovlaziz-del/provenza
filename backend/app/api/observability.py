# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Real-time agent observability.

  GET  /stream      SSE: live agent events of the caller's organization,
                    filtered on the server (?agent_id=1,2&event_types=...),
                    sent in batches every 100 ms at most, keepalive every 15 s;
                    ?detail=1 adds the content, PII masked
  GET  /events      the same events from history (agent_events_v), for backfill
  GET  /summary     totals and per-agent figures for a window
  GET  /timeseries  stacked series by type, decision, agent, model, tool, guard...
  GET  /breakdown   totals of one dimension split by another (tools by decision)
  POST /reveal      one event's content WITHOUT masking - admins only, audited
  GET  /health      Redis reachable, open streams

The bus carries metadata only (app.core.obs_hooks). Content is read from the
database per reader and masked by the Prompt Firewall (app.services.obs_content);
unmasked text only through /reveal.
"""

import asyncio
import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Optional, Set, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core import obs_bus
from app.core.database import get_db
from app.core.obs_hooks import EVENT_TYPES, matches
from app.models.user import User, UserRole
from app.services import obs_content
from app.services import observability as obs
from app.services.audit_service import AuditService

router = APIRouter()

MAX_STREAMS_PER_ORG = 20
MAX_AGENT_FILTER = 50
BATCH_SECONDS = 0.1
BATCH_MAX = 500
KEEPALIVE_SECONDS = 15.0
QUEUE_MAX = 5000

_streams: Dict[int, int] = defaultdict(int)


def _roles(*names):
    return [getattr(UserRole, n) for n in names if hasattr(UserRole, n)]


READ = require_role(*_roles("admin", "approver", "auditor", "compliance"))
ADMIN = require_role(*_roles("admin"))


def parse_filters(agent_id: Optional[str], event_types: Optional[str]) -> Tuple[Optional[Set[int]], Optional[Set[str]]]:
    agents = None
    if agent_id:
        try:
            agents = {int(x) for x in agent_id.split(",") if x.strip()}
        except ValueError:
            raise HTTPException(status_code=422, detail="agent_id: comma-separated integers")
        if len(agents) > MAX_AGENT_FILTER:
            raise HTTPException(status_code=422, detail=f"agent_id: at most {MAX_AGENT_FILTER} agents")
    types = None
    if event_types:
        types = {x.strip() for x in event_types.split(",") if x.strip()}
        unknown = types - set(EVENT_TYPES)
        if unknown:
            raise HTTPException(status_code=422, detail=f"event_types: unknown {sorted(unknown)}; use {list(EVENT_TYPES)}")
    return agents or None, types or None


def _frame(event: str, data) -> str:
    return f"event: {event}\ndata: {json.dumps(data, separators=(',', ':'), default=str)}\n\n"


@router.get("/stream")
async def stream(
    request: Request,
    agent_id: Optional[str] = Query(None, description="comma-separated agent ids"),
    event_types: Optional[str] = Query(None, description=f"comma-separated: {', '.join(EVENT_TYPES)}"),
    detail: bool = Query(False, description="attach content, PII masked"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(READ),
):
    agents, types = parse_filters(agent_id, event_types)
    org_id = current_user.org_id
    if _streams[org_id] >= MAX_STREAMS_PER_ORG:
        raise HTTPException(status_code=429, detail="Too many live views open for this organization")

    async def events():
        _streams[org_id] += 1   # counted here, so the finally below always pairs with it
        queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAX)
        end, failed = object(), object()
        dropped = 0

        async def pump():
            nonlocal dropped
            try:
                async for ev in obs_bus.subscribe(org_id):
                    if not matches(ev, agents, types):
                        continue
                    try:
                        queue.put_nowait(ev)
                    except asyncio.QueueFull:
                        dropped += 1
                await queue.put(end)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                await queue.put(failed)

        task = asyncio.create_task(pump())
        loop = asyncio.get_running_loop()
        try:
            yield _frame("hello", {
                "server_time": datetime.now(timezone.utc).isoformat(),
                "batch_ms": int(BATCH_SECONDS * 1000),
                "agent_id": sorted(agents) if agents else None,
                "event_types": sorted(types) if types else None,
                "detail": detail,
            })
            while True:
                try:
                    first = await asyncio.wait_for(queue.get(), timeout=KEEPALIVE_SECONDS)
                except asyncio.TimeoutError:
                    if await request.is_disconnected():
                        break
                    yield ": keepalive\n\n"
                    continue
                if first is failed:
                    yield _frame("error", {"detail": "live events are unavailable; retrying"})
                    break
                if first is end:
                    break
                batch, stop = [first], None
                deadline = loop.time() + BATCH_SECONDS
                while len(batch) < BATCH_MAX:
                    left = deadline - loop.time()
                    if left <= 0:
                        break
                    try:
                        ev = await asyncio.wait_for(queue.get(), timeout=left)
                    except asyncio.TimeoutError:
                        break
                    if ev is end or ev is failed:
                        stop = ev
                        break
                    batch.append(ev)
                if detail:
                    await _attach(db, org_id, batch)
                payload = {"events": batch}
                if dropped:
                    payload["dropped"], dropped = dropped, 0
                yield _frame("batch", payload)
                if stop is failed:
                    yield _frame("error", {"detail": "live events are unavailable; retrying"})
                if stop is not None:
                    break
        finally:
            task.cancel()
            try:
                await task
            except BaseException:  # noqa: BLE001
                pass
            _streams[org_id] = max(0, _streams[org_id] - 1)

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})


async def _attach(db: AsyncSession, org_id: int, batch: list) -> None:
    """Masked content for a batch; the read transaction is ended at once so a
    long-lived stream never holds a pooled connection between batches."""
    try:
        await obs_content.attach(db, org_id, batch)
    except Exception:  # noqa: BLE001 - the live view must keep going
        for ev in batch:
            ev.setdefault("content_error", True)
    finally:
        try:
            await db.rollback()
        except Exception:  # noqa: BLE001
            pass


@router.get("/events")
async def events_history(
    agent_id: Optional[str] = Query(None),
    event_types: Optional[str] = Query(None),
    minutes: int = Query(15, ge=1, le=43200),
    limit: int = Query(500, ge=1, le=2000),
    before: Optional[datetime] = Query(None, description="older than this time (paging)"),
    detail: bool = Query(False, description="attach content, PII masked"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(READ),
):
    agents, types = parse_filters(agent_id, event_types)
    if detail and limit > 500:
        raise HTTPException(status_code=422, detail="limit: at most 500 with detail=1")
    rows = await obs.history(db, current_user.org_id, minutes=minutes, agent_ids=agents, types=types, limit=limit,
                             before_ts=before)
    if detail:
        await obs_content.attach(db, current_user.org_id, rows)
    return rows


def _window(minutes: int) -> int:
    if minutes not in obs.WINDOWS:
        raise HTTPException(status_code=422, detail=f"minutes: one of {sorted(obs.WINDOWS)}")
    return minutes


@router.get("/timeseries")
async def timeseries(
    dim: str = Query("type"),
    metric: str = Query("count"),
    minutes: int = Query(15),
    agent_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(READ),
):
    if dim not in obs.DIMS:
        raise HTTPException(status_code=422, detail=f"dim: one of {sorted(obs.DIMS)}")
    if metric not in obs.METRICS:
        raise HTTPException(status_code=422, detail=f"metric: one of {sorted(obs.METRICS)}")
    agents, _ = parse_filters(agent_id, None)
    return await obs.timeseries(db, current_user.org_id, minutes=_window(minutes), dim=dim, metric=metric,
                                agent_ids=agents)


@router.get("/breakdown")
async def breakdown(
    dim: str = Query("tool"),
    by: str = Query("decision"),
    minutes: int = Query(15),
    agent_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(READ),
):
    if dim not in obs.DIMS or by not in obs.DIMS or "guard" in (dim, by) or dim == by:
        raise HTTPException(status_code=422, detail="dim/by: two different dimensions, guard excluded")
    agents, _ = parse_filters(agent_id, None)
    return await obs.breakdown(db, current_user.org_id, minutes=_window(minutes), dim=dim, by=by, agent_ids=agents)


class RevealIn(BaseModel):
    type: str
    id: int
    reason: Optional[str] = Field(None, max_length=300)


@router.post("/reveal")
async def reveal(data: RevealIn, db: AsyncSession = Depends(get_db), current_user: User = Depends(ADMIN)):
    """Content of one event without PII masking. Every call is audited."""
    if data.type not in EVENT_TYPES:
        raise HTTPException(status_code=422, detail=f"type: one of {list(EVENT_TYPES)}")
    exists = (await db.execute(text(
        f"SELECT 1 FROM {obs.VIEW} WHERE org_id = :org AND event_type = :t AND source_id = :id LIMIT 1"
    ), {"org": current_user.org_id, "t": data.type, "id": data.id})).first()
    if not exists:
        raise HTTPException(status_code=404, detail="Event not found")
    content = await obs_content.reveal(db, current_user.org_id, data.type, data.id) or []
    await AuditService(db).log(current_user.org_id, current_user.id, "agent_event", data.id, "observability.reveal_raw",
                               {"event_type": data.type, "reason": data.reason, "sections": [c["label"] for c in content]})
    await db.commit()
    return {"type": data.type, "id": data.id, "masked": False, "content": content}


@router.get("/summary")
async def summary(
    minutes: int = Query(15),
    agent_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(READ),
):
    agents, _ = parse_filters(agent_id, None)
    return await obs.summary(db, current_user.org_id, minutes=_window(minutes), agent_ids=agents)


@router.get("/health")
async def health(current_user: User = Depends(READ)):
    return {"redis": await obs_bus.ping(), "open_streams": _streams.get(current_user.org_id, 0),
            "max_streams": MAX_STREAMS_PER_ORG}
