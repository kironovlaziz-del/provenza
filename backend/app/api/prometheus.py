# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Prometheus proxy.

Registered under /api/v1/metrics (distinct from /api/v1/observability,
which is the agent-observability event stream — different data source,
different shape). Thin pass-through to Prometheus on loopback: the browser
cannot reach 127.0.0.1:9090 directly, and we do not want to expose the
Prometheus port. Auth reuses the same JWT as the rest of the admin API.

The metrics describe the installation, not one organization: HTTP traffic
of the whole API, and every organization's sensors, tables and audit log
(labelled org_id). So the proxy answers only the installation's operator -
an administrator of the first organization (deps.require_operator).
Administrators of organizations created later by public sign-up get 403:
they are tenants and must not see each other's data.

If Prometheus is down, both handlers return 503 with a short message.
"""

import asyncio
import json
import urllib.error
import urllib.parse
import urllib.request

from fastapi import APIRouter, Depends, Header, HTTPException, Query

from app.api.deps import require_operator
from app.core.database import get_db
from app.services import notification_service
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.models.user import User

router = APIRouter()

# Functions that can rewrite labels and forge a metric out of thin air.
# The endpoint is admin-only, but a typo in a dashboard query that hits
# label_replace quietly changes what the operator is looking at. Cheap
# guardrail; no need for a full PromQL parser.
_FORBIDDEN_FUNCS = ("label_replace", "label_join")


def _fetch_json(url: str, timeout: float = 5.0) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    # Bandit B310 flags urlopen because it accepts file:// and other schemes.
    # Here the URL is fully controlled by us: the host comes from
    # settings.PROMETHEUS_URL (operator-set, loopback by default), the path
    # is a literal /api/v1/query[_range], and the query string is built by
    # urllib.parse.urlencode. No user input reaches the scheme or host.
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
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


def _validate_query(q: str) -> None:
    """Reject only the patterns that quietly change what a query means.

    /api/v1/metrics/query{,_range} answers the operator only, who sees the
    whole installation (require_operator). label_replace / label_join are
    the only refusals: they rewrite labels and can make a per-org series
    look like a different org's series without warning.
    """
    for fn in _FORBIDDEN_FUNCS:
        if fn in q:
            raise HTTPException(
                status_code=400,
                detail=f"{fn} is not allowed",
            )


@router.get("/query", summary="Instant query against Prometheus")
async def query(
    query: str = Query(..., description="PromQL expression"),
    time: str | None = Query(default=None, description="RFC3339 or unix timestamp"),
    _: User = Depends(require_operator),
) -> dict:
    _validate_query(query)
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
    _: User = Depends(require_operator),
) -> dict:
    _validate_query(query)
    return await _proxy(
        "/api/v1/query_range",
        {"query": query, "start": str(start), "end": str(end), "step": step},
    )


# ---------------------------------------------------------------- alerts
# Alertmanager posts here on firing / resolved. The endpoint is NOT
# authenticated by JWT (Alertmanager does not speak it); it checks a
# shared Bearer secret from settings.ALERTMANAGER_SECRET, which the
# operator puts in .env and in deploy/observability/alertmanager-secret.
# Empty secret disables the endpoint entirely — 503, not 401, so a
# mis-configured install fails loudly.

# Map the Prometheus "severity" label to the human-readable prefix used
# in the notification subject. Missing or unknown severity is treated as
# "warning" so nothing is dropped silently.
_SEVERITY_PREFIX = {
    "info": "INFO",
    "warning": "WARNING",
    "critical": "CRITICAL",
}


def _check_alertmanager_secret(authorization: str | None) -> None:
    import hmac
    expected = settings.ALERTMANAGER_SECRET
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="alert ingestion is disabled (ALERTMANAGER_SECRET is empty)",
        )
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization[len("Bearer "):]
    if not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid token")


@router.post(
    "/alerts",
    summary="Alertmanager webhook receiver (fires notifications)",
    include_in_schema=False,
)
async def receive_alerts(
    payload: dict,
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Fan alerts out to each organization's notification channels.

    Alertmanager sends every grouped alert here; the shape is stable
    (v4): {"version":"4","status":"firing|resolved",
    "alerts":[{"status":"firing","labels":{...},"annotations":{...},
    "startsAt":"...","endsAt":"..."}, ...], ...}.

    For each alert with status=firing we look for labels.org_id and call
    notify() with event_type="alert". Resolved alerts are acknowledged
    but not pushed (this is not an incident tracker; it is a notifier).
    Alerts without org_id are counted as skipped.
    """
    _check_alertmanager_secret(authorization)

    alerts = payload.get("alerts") or []
    processed = 0
    skipped = 0

    for a in alerts:
        if a.get("status") != "firing":
            continue
        labels = a.get("labels") or {}
        annotations = a.get("annotations") or {}
        org_id_raw = labels.get("org_id")
        if not org_id_raw:
            skipped += 1
            continue
        try:
            org_id = int(org_id_raw)
        except (TypeError, ValueError):
            skipped += 1
            continue

        alertname = labels.get("alertname", "unknown")
        severity = labels.get("severity", "warning")
        prefix = _SEVERITY_PREFIX.get(severity, severity.upper())

        summary = annotations.get("summary") or alertname
        description = annotations.get("description") or ""
        subject = f"[{prefix}] {alertname}"
        message = f"{summary}\n\n{description}".strip()

        # metadata is JSON-serialisable: labels + annotations + startsAt.
        metadata = {
            "source": "prometheus",
            "alertname": alertname,
            "severity": severity,
            "startsAt": a.get("startsAt"),
            "labels": labels,
            "annotations": annotations,
        }
        await notification_service.notify(
            db,
            org_id=org_id,
            event_type="alert",
            subject=subject,
            message=message,
            metadata=metadata,
        )
        processed += 1

    return {"processed": processed, "skipped": skipped}
