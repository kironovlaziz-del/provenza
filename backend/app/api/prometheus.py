# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Prometheus proxy.

Registered under /api/v1/metrics (distinct from /api/v1/observability,
which is the agent-observability event stream — different data source,
different shape). Thin pass-through to Prometheus on loopback: the browser
cannot reach 127.0.0.1:9090 directly, and we do not want to expose the
Prometheus port. Auth reuses the same JWT as the rest of the admin API
and requires admin.

If Prometheus is down, both handlers return 503 with a short message.
"""

import asyncio
import json
import urllib.error
import urllib.parse
import urllib.request

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import require_role
from app.core.config import settings
from app.models.user import User, UserRole

router = APIRouter()


def _fetch_json(url: str, timeout: float = 5.0) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


async def _proxy(path: str, params: dict[str, str]) -> dict:
    url = f"{settings.PROMETHEUS_URL.rstrip('/')}{path}?{urllib.parse.urlencode(params)}"
    try:
        return await asyncio.to_thread(_fetch_json, url)
    except urllib.error.HTTPError as e:
        raise HTTPException(status_code=e.code, detail=f"Prometheus: {e.reason}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise HTTPException(
            status_code=503,
            detail=f"Prometheus unavailable at {settings.PROMETHEUS_URL}: {e}",
        )


@router.get("/query", summary="Instant query against Prometheus")
async def query(
    query: str = Query(..., description="PromQL expression"),
    time: str | None = Query(default=None, description="RFC3339 or unix timestamp"),
    _: User = Depends(require_role(UserRole.admin)),
) -> dict:
    params = {"query": query}
    if time:
        params["time"] = time
    return await _proxy("/api/v1/query", params)


@router.get("/query_range", summary="Range query against Prometheus")
async def query_range(
    query: str = Query(..., description="PromQL expression"),
    start: float = Query(..., description="Start timestamp (unix seconds)"),
    end: float = Query(..., description="End timestamp (unix seconds)"),
    step: str = Query(default="15s", description="Resolution, e.g. 15s, 1m"),
    _: User = Depends(require_role(UserRole.admin)),
) -> dict:
    return await _proxy(
        "/api/v1/query_range",
        {"query": query, "start": str(start), "end": str(end), "step": step},
    )
