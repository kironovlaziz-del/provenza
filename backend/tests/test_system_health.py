"""
System health: every component reported, status derived from them, and the
problems a person must act on (no worker, stale beat, Redis auth) named.
"""

import time

import pytest

from app.services import system_health
from tests.conftest import auth_headers

H = "/api/v1/system/health"


def _fake(monkeypatch, *, redis_ok=True, workers=("celery@w1",), beat_age=30.0, queued=0):
    async def redis():
        if not redis_ok:
            return {"ok": False, "error": "AuthenticationError", "hint": "wrong or missing REDIS_PASSWORD"}
        return {"ok": True, "latency_ms": 1.0, "queued_tasks": queued,
                "heartbeat": None if beat_age is None else time.time() - beat_age}

    async def ws():
        return {"ok": bool(workers), "names": list(workers), "count": len(workers)}

    monkeypatch.setattr(system_health, "_redis", redis)
    monkeypatch.setattr(system_health, "_workers", ws)


@pytest.mark.asyncio
async def test_all_good(client, admin_token, monkeypatch):
    _fake(monkeypatch)
    r = await client.get(H, headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok" and body["problems"] == []
    assert set(body["components"]) == {"database", "redis", "workers", "beat"}
    assert body["components"]["database"]["ok"] is True and body["components"]["workers"]["count"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("kw,code,status", [
    ({"workers": ()}, "no_workers", "down"),
    ({"beat_age": 900.0}, "beat_stale", "degraded"),
    ({"beat_age": None}, "beat_stale", "degraded"),
    ({"queued": 500}, "queue_backlog", "degraded"),
    ({"redis_ok": False}, "redis_down", "down"),
])
async def test_problems(client, admin_token, monkeypatch, kw, code, status):
    _fake(monkeypatch, **kw)
    body = (await client.get(H, headers=auth_headers(admin_token))).json()
    assert body["status"] == status
    assert code in {p["code"] for p in body["problems"]}


@pytest.mark.asyncio
async def test_access(client, approver_token, monkeypatch):
    _fake(monkeypatch)
    assert (await client.get(H, headers=auth_headers(approver_token))).status_code == 200
    assert (await client.get(H)).status_code in (401, 403)
