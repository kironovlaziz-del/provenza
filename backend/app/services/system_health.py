# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Health of the moving parts behind the API: database, Redis, Celery workers,
Celery beat and the task queue.

The API answering /health says nothing about background work. Workers can be
gone, or Redis can reject every task (a missing REDIS_PASSWORD once kept the
whole pipeline silent for days) while every page still loads. This check
looks at each part directly:

  database   SELECT 1
  redis      PING with the configured password, queue length
  workers    Celery control ping (who answers within the timeout)
  beat       a heartbeat task scheduled by beat every minute and run by a
             worker writes a timestamp to Redis; its age proves the whole
             schedule -> queue -> worker path works
"""

import asyncio
import time
from datetime import datetime, timezone
from typing import List

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings

HEARTBEAT_KEY = "provenza:heartbeat:beat"
HEARTBEAT_EVERY = 60          # seconds, see celery_app.beat_schedule
BEAT_STALE_AFTER = 180        # three missed beats
QUEUE_BACKLOG_WARN = 100
DEFAULT_QUEUE = "celery"


def _redis_client(**kw):
    from redis.asyncio import Redis

    return Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, password=settings.REDIS_PASSWORD or None,
                 decode_responses=True, socket_connect_timeout=2, socket_timeout=2, db=0, **kw)


async def _close(client) -> None:
    try:
        await client.aclose()
    except AttributeError:
        await client.close()
    except Exception:  # noqa: BLE001
        pass


async def _database(db: AsyncSession) -> dict:
    t = time.perf_counter()
    try:
        await db.execute(text("SELECT 1"))
        return {"ok": True, "latency_ms": round((time.perf_counter() - t) * 1000, 1)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": exc.__class__.__name__}


async def _redis() -> dict:
    client = _redis_client()
    t = time.perf_counter()
    try:
        await client.ping()
        latency = round((time.perf_counter() - t) * 1000, 1)
        beat_ts = await client.get(HEARTBEAT_KEY)
        queued = await client.llen(DEFAULT_QUEUE)
        return {"ok": True, "latency_ms": latency, "queued_tasks": queued,
                "heartbeat": float(beat_ts) if beat_ts else None}
    except Exception as exc:  # noqa: BLE001
        name = exc.__class__.__name__
        hint = "wrong or missing REDIS_PASSWORD" if "Auth" in name else "Redis is not reachable"
        return {"ok": False, "error": name, "hint": hint}
    finally:
        await _close(client)


def _ping_workers_sync() -> List[str]:
    from app.core.celery_app import celery_app

    replies = celery_app.control.inspect(timeout=1.5).ping() or {}
    return sorted(replies)


async def _workers() -> dict:
    try:
        names = await asyncio.wait_for(asyncio.to_thread(_ping_workers_sync), timeout=6)
        return {"ok": bool(names), "names": names, "count": len(names)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "names": [], "count": 0, "error": exc.__class__.__name__}


async def check(db: AsyncSession) -> dict:
    now = time.time()
    database, redis_state, workers = await asyncio.gather(_database(db), _redis(), _workers())

    hb = redis_state.get("heartbeat")
    age = round(now - hb, 1) if hb else None
    beat = {"ok": age is not None and age <= BEAT_STALE_AFTER, "last_heartbeat_age_seconds": age,
            "expected_every_seconds": HEARTBEAT_EVERY}

    problems = []
    if not database["ok"]:
        problems.append({"code": "db_down", "severity": "critical",
                         "message": f"The database does not answer ({database.get('error')})."})
    if not redis_state["ok"]:
        problems.append({"code": "redis_down", "severity": "critical",
                         "message": f"Redis: {redis_state.get('hint')} ({redis_state.get('error')}). "
                                    "Background tasks and live events are stopped."})
    else:
        if not workers["ok"]:
            problems.append({"code": "no_workers", "severity": "critical",
                             "message": "No Celery worker answers. Queued requests, sweeps and training jobs "
                                        "are not processed."})
        if not beat["ok"]:
            problems.append({"code": "beat_stale", "severity": "warning",
                             "message": "Scheduled jobs are not running: no heartbeat from Celery beat "
                                        + ("ever." if age is None else f"for {int(age)} s.")})
        if (redis_state.get("queued_tasks") or 0) > QUEUE_BACKLOG_WARN:
            problems.append({"code": "queue_backlog", "severity": "warning",
                             "message": f"{redis_state['queued_tasks']} tasks are waiting in the queue."})

    status = ("down" if any(p["severity"] == "critical" for p in problems)
              else "degraded" if problems else "ok")
    return {"status": status, "checked_at": datetime.now(timezone.utc).isoformat(), "problems": problems,
            "components": {"database": database, "redis": {k: v for k, v in redis_state.items() if k != "heartbeat"},
                           "workers": workers, "beat": beat}}
