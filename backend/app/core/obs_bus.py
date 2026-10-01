# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Observability bus: agent events over the Redis instance Celery already uses.

Publishing side
  publish(org_id, events) never blocks and never raises. Inside an event
  loop the events are buffered for FLUSH_DELAY (100 ms) and sent as one JSON
  array per organization; outside a loop (sync code, Celery prefork) they are
  sent at once. If the loop shuts down before the flush (asyncio.run in a
  Celery task), the buffer is sent synchronously on cancellation, so nothing
  committed is lost on the way out.

  When Redis is unreachable the bus stays quiet for BACKOFF_SECONDS instead
  of stalling every flush on a connect timeout. Events are a live view only;
  the durable record is the database (agent_events_v), so dropping a batch
  while Redis is down loses nothing that history cannot show.

Subscribing side
  subscribe(org_id) yields single events for one organization. One channel
  per organization keeps tenants apart at the transport level; filtering by
  agent and event type happens in the API, on the server.
"""

import asyncio
import json
import logging
import threading
import time
import weakref
from typing import Any, AsyncIterator, Dict, List, Optional

from app.core.config import settings

log = logging.getLogger(__name__)

FLUSH_DELAY = 0.1
MAX_BATCH = 500
BACKOFF_SECONDS = 30.0

_lock = threading.Lock()
_sync_client = None
_down_until = 0.0
_last_warning = 0.0
_loops: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict]" = weakref.WeakKeyDictionary()


def channel(org_id: int) -> str:
    return f"obs:agents:{int(org_id)}"


def _redis_kwargs(read_timeout: Optional[float]) -> Dict[str, Any]:
    return dict(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        password=settings.REDIS_PASSWORD or None,
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=read_timeout,
    )


def _warn(exc: Exception) -> None:
    global _last_warning
    now = time.monotonic()
    if now - _last_warning > 60:
        _last_warning = now
        log.warning("observability bus: publish failed (%s); live view paused for %ss",
                    exc.__class__.__name__, int(BACKOFF_SECONDS))


def _send(pending: Dict[int, List[dict]]) -> None:
    """Blocking send of {org_id: [events]}; swallows every error."""
    global _sync_client, _down_until
    if not pending or time.monotonic() < _down_until:
        return
    try:
        with _lock:
            if _sync_client is None:
                from redis import Redis
                _sync_client = Redis(**_redis_kwargs(2))
            client = _sync_client
        pipe = client.pipeline(transaction=False)
        for org_id, events in pending.items():
            for i in range(0, len(events), MAX_BATCH):
                pipe.publish(channel(org_id), json.dumps(events[i:i + MAX_BATCH], separators=(",", ":"), default=str))
        pipe.execute()
    except Exception as exc:  # noqa: BLE001
        with _lock:
            _sync_client = None
        _down_until = time.monotonic() + BACKOFF_SECONDS
        _warn(exc)


async def _flush_later(state: dict) -> None:
    try:
        await asyncio.sleep(FLUSH_DELAY)
    except asyncio.CancelledError:
        pending, state["pending"] = state["pending"], {}
        _send(pending)  # the loop is going away: last chance, synchronously
        raise
    pending, state["pending"] = state["pending"], {}
    if not pending:
        return
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, _send, pending)
    except RuntimeError:  # executor already shut down
        _send(pending)


def publish(org_id: int, events: List[dict]) -> None:
    """Queue events of one organization for the live view. Never raises."""
    if not events:
        return
    try:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is None or loop.is_closed():
            _send({org_id: list(events)})
            return
        state = _loops.get(loop)
        if state is None:
            state = _loops[loop] = {"pending": {}, "task": None}
        state["pending"].setdefault(org_id, []).extend(events)
        task = state["task"]
        if task is None or task.done():
            state["task"] = loop.create_task(_flush_later(state))
    except Exception as exc:  # noqa: BLE001
        _warn(exc)


async def subscribe(org_id: int) -> AsyncIterator[dict]:
    """Yield the events of one organization as they are published.
    Errors connecting to Redis propagate, so the caller can tell the browser."""
    from redis.asyncio import Redis

    client = Redis(**_redis_kwargs(None))
    pubsub = client.pubsub()
    await pubsub.subscribe(channel(org_id))
    try:
        while True:
            msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if msg is None or msg.get("type") != "message":
                continue
            try:
                data = json.loads(msg["data"])
            except (TypeError, ValueError):
                continue
            for ev in data if isinstance(data, list) else [data]:
                if isinstance(ev, dict):
                    yield ev
    finally:
        try:
            await pubsub.unsubscribe(channel(org_id))
        except Exception:  # noqa: BLE001
            pass
        try:
            await pubsub.aclose()
        except AttributeError:
            await pubsub.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            await client.aclose()
        except AttributeError:
            await client.close()
        except Exception:  # noqa: BLE001
            pass


async def ping() -> bool:
    from redis.asyncio import Redis

    client = Redis(**_redis_kwargs(2))
    try:
        return bool(await client.ping())
    except Exception:  # noqa: BLE001
        return False
    finally:
        try:
            await client.aclose()
        except AttributeError:
            await client.close()
        except Exception:  # noqa: BLE001
            pass
