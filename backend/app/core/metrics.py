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

sensor_activity_pruned_total = Counter(
    "sensor_activity_pruned_total",
    "Sampled allowed connects removed by the hourly retention task.",
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
