"""
Aggregate metrics for the dashboard.

All queries are scoped to a single organization and (where it makes
sense) to a rolling time window in days. Counts are intentionally
returned as plain dicts and lists so the frontend can pass them
straight into charting libraries.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_request import AIRequest
from app.models.ai_incident import AIIncident
from app.models.ai_approval import AIApproval
from app.models.ai_policy import AIPolicy


async def _grouped_counts(
    db: AsyncSession, column, base_filter
) -> Dict[str, int]:
    rows = await db.execute(
        select(column, func.count()).where(base_filter).group_by(column)
    )
    return {(str(k) if k is not None else "unknown"): int(v) for k, v in rows.all()}


async def build_stats(
    db: AsyncSession, org_id: int, window_days: int = 7
) -> Dict[str, Any]:
    since = datetime.now(timezone.utc) - timedelta(days=window_days)

    # --- time series: requests per day, split by coarse status ---
    bucket_day = func.date_trunc("day", AIRequest.created_at).label("day")
    rows = await db.execute(
        select(
            bucket_day,
            AIRequest.status,
            func.count().label("c"),
        )
        .where(
            AIRequest.org_id == org_id,
            AIRequest.created_at >= since,
        )
        .group_by(bucket_day, AIRequest.status)
        .order_by(bucket_day)
    )

    # Assemble the daily series, filling gaps with zeros so the chart
    # does not show holes on quiet days.
    by_day: Dict[str, Dict[str, int]] = {}
    for i in range(window_days):
        d = (datetime.now(timezone.utc) - timedelta(days=window_days - 1 - i)).date()
        by_day[d.isoformat()] = {
            "date": d.isoformat(),
            "total": 0,
            "completed": 0,
            "blocked": 0,
            "failed": 0,
        }

    for day, status, count in rows.all():
        key = day.date().isoformat()
        if key not in by_day:
            continue
        by_day[key]["total"] += int(count)
        if status == "completed":
            by_day[key]["completed"] += int(count)
        elif status == "blocked":
            by_day[key]["blocked"] += int(count)
        elif status == "failed":
            by_day[key]["failed"] += int(count)

    requests_by_day = [by_day[k] for k in sorted(by_day.keys())]

    # --- distributions ---
    requests_by_status = await _grouped_counts(
        db, AIRequest.status, AIRequest.org_id == org_id
    )
    incidents_by_severity = await _grouped_counts(
        db, AIIncident.severity, AIIncident.org_id == org_id
    )

    # --- scalar counters ---
    total_requests = sum(requests_by_status.values())
    total_incidents = await db.scalar(
        select(func.count()).select_from(AIIncident).where(AIIncident.org_id == org_id)
    )

    pending_approvals = await db.scalar(
        select(func.count())
        .select_from(AIApproval)
        .join(AIRequest, AIRequest.id == AIApproval.request_id)
        .where(
            AIRequest.org_id == org_id,
            AIApproval.decision.is_(None),
        )
    )
    total_policies = await db.scalar(
        select(func.count()).select_from(AIPolicy).where(AIPolicy.org_id == org_id)
    )

    return {
        "window_days": window_days,
        "requests_by_day": requests_by_day,
        "requests_by_status": requests_by_status,
        "incidents_by_severity": incidents_by_severity,
        "total_requests": total_requests,
        "total_incidents": int(total_incidents or 0),
        "pending_approvals": int(pending_approvals or 0),
        "total_policies": int(total_policies or 0),
    }
