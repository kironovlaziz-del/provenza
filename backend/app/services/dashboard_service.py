"""
Aggregate metrics for the dashboard.

All queries are scoped to a single organization and (where it makes
sense) to a rolling time window in days. Counts are intentionally
returned as plain dicts and lists so the frontend can pass them
straight into charting libraries.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent_action import AgentAction
from app.models.ai_incident import AIIncident
from app.models.gateway import GatewayCall
from app.models.policy_layer import PolicyLayer


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

    # --- time series: LLM calls through the gateway per day, by outcome ---
    bucket_day = func.date_trunc("day", GatewayCall.created_at).label("day")
    rows = await db.execute(
        select(
            bucket_day,
            GatewayCall.status,
            func.count().label("c"),
        )
        .where(
            GatewayCall.org_id == org_id,
            GatewayCall.created_at >= since,
        )
        .group_by(bucket_day, GatewayCall.status)
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
            "denied": 0,
            "failed": 0,
        }

    for day, status, count in rows.all():
        key = day.date().isoformat()
        if key not in by_day:
            continue
        by_day[key]["total"] += int(count)
        if status == "completed":
            by_day[key]["completed"] += int(count)
        elif status in ("denied", "rate_limited", "blocked", "filtered"):
            by_day[key]["denied"] += int(count)
        elif status == "failed":
            by_day[key]["failed"] += int(count)

    calls_by_day = [by_day[k] for k in sorted(by_day.keys())]

    # --- distributions ---
    calls_by_status = await _grouped_counts(
        db, GatewayCall.status, (GatewayCall.org_id == org_id) & (GatewayCall.created_at >= since)
    )
    incidents_by_severity = await _grouped_counts(
        db, AIIncident.severity, AIIncident.org_id == org_id
    )

    # --- scalar counters ---
    total_incidents = await db.scalar(
        select(func.count()).select_from(AIIncident).where(AIIncident.org_id == org_id)
    )
    # agent actions waiting for a person (Approvals)
    pending_approvals = await db.scalar(
        select(func.count()).select_from(AgentAction).where(
            AgentAction.org_id == org_id, AgentAction.policy_check_result == "pending_approval")
    )
    # levels of the policy hierarchy that carry rules
    total_policies = await db.scalar(
        select(func.count()).select_from(PolicyLayer).where(
            PolicyLayer.org_id == org_id, PolicyLayer.document != text("'{}'::jsonb"))
    )

    return {
        "window_days": window_days,
        "calls_by_day": calls_by_day,
        "calls_by_status": calls_by_status,
        "incidents_by_severity": incidents_by_severity,
        "total_calls": sum(calls_by_status.values()),
        "total_incidents": int(total_incidents or 0),
        "pending_approvals": int(pending_approvals or 0),
        "total_policies": int(total_policies or 0),
    }
