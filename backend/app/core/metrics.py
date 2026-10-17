# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza - https://github.com/kironovlaziz-del/provenza

"""Prometheus metrics for the backend.

Single source of truth: every metric name and label set lives here so
dashboards and alerts do not drift from the code. The module is imported
by main.py (HTTP middleware and /metrics endpoint) and by the egress
service (event counters).

Cardinality: HTTP path labels use the FastAPI route template, not the raw
URL, so /sensors/3/violations and /sensors/4/violations collapse into one
series. Unmatched requests collapse into "__unmatched__". Sensor gauges
are labelled by sensor_id — one series per sensor, which scales to
hundreds without issue.
"""

from datetime import datetime, timedelta, timezone

from prometheus_client import Counter, Gauge, Histogram
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.egress_sensor import EgressSensor


# ------------------------------------------------------------------ HTTP

http_requests_total = Counter(
    "http_requests_total",
    "HTTP requests handled by the API, by route template and status.",
    ["method", "path", "status"],
)

http_request_duration_seconds = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds, by route template.",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)


# ---------------------------------------------------------------- sensor

sensor_violations_inserted_total = Counter(
    "sensor_violations_inserted_total",
    "Violation events accepted from sensors and written to egress_violations.",
)

sensor_violations_dropped_total = Counter(
    "sensor_violations_dropped_total",
    "Violation events dropped because their workload_id was not this org's.",
)

sensor_activity_inserted_total = Counter(
    "sensor_activity_inserted_total",
    "Sampled allowed connects accepted from sensors and written to sensor_activity.",
)

sensor_activity_dropped_total = Counter(
    "sensor_activity_dropped_total",
    "Sampled allowed connects dropped because their workload_id was not this org's.",
)




# State gauges, refreshed on each /metrics scrape. Cheap — one SELECT over
# egress_sensors, which is small (one row per sensor in the org).
sensor_last_heartbeat_age_seconds = Gauge(
    "sensor_last_heartbeat_age_seconds",
    "Seconds since each active sensor's last heartbeat.",
    ["sensor_id"],
)

sensors_offline = Gauge(
    "sensors_offline",
    "Active sensors whose last heartbeat is older than the offline threshold.",
)

# Row counts, refreshed on scrape from the DB. Counters on the Celery
# workers never reach /metrics (separate process); these gauges read the
# tables directly, so retention actually shows up here. Indexed on
# (org_id, created_at) makes COUNT cheap even at millions of rows.
sensor_activity_rows = Gauge(
    "sensor_activity_rows",
    "Total rows in sensor_activity, per organization.",
    ["org_id"],
)

sensor_violations_rows = Gauge(
    "sensor_violations_rows",
    "Total rows in egress_violations, per organization.",
    ["org_id"],
)

# Retention health gauges. The two oldest-age series tell you whether the
# prune is keeping up (age should hover just below the configured
# retention * 86400); the three status series tell you whether the prune
# ran at all and what it did the last time. Both tables are covered.
sensor_activity_oldest_age_seconds = Gauge(
    "sensor_activity_oldest_age_seconds",
    "Age in seconds of the oldest sensor_activity row, per organization.",
    ["org_id"],
)

sensor_violations_oldest_age_seconds = Gauge(
    "sensor_violations_oldest_age_seconds",
    "Age in seconds of the oldest egress_violations row, per organization.",
    ["org_id"],
)

retention_last_pruned_at_seconds_ago = Gauge(
    "retention_last_pruned_at_seconds_ago",
    "Seconds since the last successful prune, per table and organization.",
    ["table", "org_id"],
)

retention_last_prune_failed = Gauge(
    "retention_last_prune_failed",
    "1 if the last prune failed for this table/organization, else 0.",
    ["table", "org_id"],
)

retention_last_prune_rows = Gauge(
    "retention_last_prune_rows",
    "Rows deleted by the last prune, per table and organization.",
    ["table", "org_id"],
)

# Matches egress_sensor.warn_offline's own threshold. Kept separate on
# purpose: the metric is a monitoring signal, the warn task sends notices.
OFFLINE_AFTER = timedelta(minutes=5)


async def update_db_gauges(db: AsyncSession) -> None:
    """Refresh the DB-derived gauges. Called from GET /metrics.

    Revoked sensors are excluded: they are not expected to heartbeat, so
    including them would inflate both series.
    """
    now = datetime.now(timezone.utc)
    rows = (
        await db.execute(
            select(EgressSensor.id, EgressSensor.last_seen_at).where(
                EgressSensor.revoked_at.is_(None)
            )
        )
    ).all()

    offline = 0
    for sensor_id, last_seen in rows:
        if last_seen is None:
            continue
        age = (now - last_seen).total_seconds()
        sensor_last_heartbeat_age_seconds.labels(sensor_id=str(sensor_id)).set(age)
        if now - last_seen > OFFLINE_AFTER:
            offline += 1
    sensors_offline.set(offline)

    # Row counts for retention monitoring. COUNT(*) on indexed column is
    # cheap; if it ever becomes slow, switch to pg_class.reltuples.
    from sqlalchemy import func
    from app.models.egress_sensor import SensorActivity, EgressViolation

    act_rows = (
        await db.execute(
            select(SensorActivity.org_id, func.count()).group_by(SensorActivity.org_id)
        )
    ).all()
    for org_id, n in act_rows:
        sensor_activity_rows.labels(org_id=str(org_id)).set(n)

    vio_rows = (
        await db.execute(
            select(EgressViolation.org_id, func.count()).group_by(EgressViolation.org_id)
        )
    ).all()
    for org_id, n in vio_rows:
        sensor_violations_rows.labels(org_id=str(org_id)).set(n)

    # Oldest row age, per table and org. MIN(created_at) is a single index
    # lookup on ix_*_org_time; even at millions of rows this is cheap.
    from app.models.egress_sensor import EgressPolicySettings

    act_oldest = (
        await db.execute(
            select(
                SensorActivity.org_id,
                func.min(SensorActivity.created_at),
            ).group_by(SensorActivity.org_id)
        )
    ).all()
    for org_id, oldest in act_oldest:
        if oldest is not None:
            age = (now - oldest).total_seconds()
            sensor_activity_oldest_age_seconds.labels(org_id=str(org_id)).set(age)

    vio_oldest = (
        await db.execute(
            select(
                EgressViolation.org_id,
                func.min(EgressViolation.created_at),
            ).group_by(EgressViolation.org_id)
        )
    ).all()
    for org_id, oldest in vio_oldest:
        if oldest is not None:
            age = (now - oldest).total_seconds()
            sensor_violations_oldest_age_seconds.labels(org_id=str(org_id)).set(age)

    # Last-prune status, read from the persisted EgressPolicySettings row.
    settings_rows = (
        await db.execute(
            select(
                EgressPolicySettings.org_id,
                EgressPolicySettings.activity_last_pruned_at,
                EgressPolicySettings.activity_last_prune_rows,
                EgressPolicySettings.activity_last_prune_error,
                EgressPolicySettings.violation_last_pruned_at,
                EgressPolicySettings.violation_last_prune_rows,
                EgressPolicySettings.violation_last_prune_error,
            )
        )
    ).all()

    for row in settings_rows:
        org = str(row.org_id)
        for table, at, rows, err in (
            ("activity",   row.activity_last_pruned_at,   row.activity_last_prune_rows,   row.activity_last_prune_error),
            ("violations", row.violation_last_pruned_at,  row.violation_last_prune_rows,  row.violation_last_prune_error),
        ):
            if at is not None:
                age = (now - at).total_seconds()
                retention_last_pruned_at_seconds_ago.labels(table=table, org_id=org).set(age)
            retention_last_prune_failed.labels(table=table, org_id=org).set(1 if err else 0)
            retention_last_prune_rows.labels(table=table, org_id=org).set(rows or 0)
