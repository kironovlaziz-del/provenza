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

Several API processes: uvicorn runs API_WORKERS processes, and a scrape
reaches one of them. The counters and the histogram are therefore kept in
prometheus_client's multiprocess mode when PROMETHEUS_MULTIPROC_DIR is set
(the entrypoint sets it for the API): every process writes its own file and
/metrics adds them up. Without it each scrape saw one process's numbers, the
series jumped between them and rate() was meaningless.

The gauges below describe the database, not a process: they are computed
afresh on every scrape (ScrapeGauge) and only what that scrape found is
exported - a deleted sensor or organization disappears instead of keeping
its last value forever.
"""

import os
from datetime import datetime, timedelta, timezone

from prometheus_client import REGISTRY, CollectorRegistry, Counter, Histogram, generate_latest
from prometheus_client.core import GaugeMetricFamily
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


# ------------------------------------------------------- scrape gauges

class ScrapeGauge:
    """A gauge filled by update_db_gauges on each scrape: the same
    .labels(...).set(v) calls as prometheus_client's Gauge, but the values
    live only until the next scrape and never go through multiprocess files."""

    def __init__(self, name: str, documentation: str, labelnames=()):
        self.name, self.documentation, self.labelnames = name, documentation, tuple(labelnames)
        self._values: dict[tuple, float] = {}
        _SCRAPE_GAUGES.append(self)

    def labels(self, **labels) -> "_Child":
        return _Child(self, tuple(str(labels[n]) for n in self.labelnames))

    def set(self, value: float) -> None:  # an unlabelled gauge
        self._values[()] = float(value)

    def clear(self) -> None:
        self._values = {}

    def family(self) -> GaugeMetricFamily:
        fam = GaugeMetricFamily(self.name, self.documentation, labels=self.labelnames)
        for key, value in sorted(self._values.items()):
            fam.add_metric(list(key), value)
        return fam


class _Child:
    def __init__(self, gauge: ScrapeGauge, key: tuple):
        self._gauge, self._key = gauge, key

    def set(self, value: float) -> None:
        self._gauge._values[self._key] = float(value)


_SCRAPE_GAUGES: list[ScrapeGauge] = []


class _ScrapeCollector:
    def collect(self):
        for g in _SCRAPE_GAUGES:
            yield g.family()


_scrape_collector = _ScrapeCollector()
_MULTIPROC_DIR = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
if not _MULTIPROC_DIR:
    REGISTRY.register(_scrape_collector)


def render() -> bytes:
    """The /metrics payload: every process's counters, and the gauges this
    scrape computed."""
    if _MULTIPROC_DIR:
        from prometheus_client import multiprocess

        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        registry.register(_scrape_collector)
        return generate_latest(registry)
    return generate_latest(REGISTRY)


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

sensor_event_time_rejected_total = Counter(
    "sensor_event_time_rejected_total",
    "Sensor events whose own time was too far from the server's; stored with the server's time.",
)

sensor_activity_dropped_total = Counter(
    "sensor_activity_dropped_total",
    "Sampled allowed connects dropped because their workload_id was not this org's.",
)




# State gauges, refreshed on each /metrics scrape. Cheap — one SELECT over
# egress_sensors, which is small (one row per sensor in the org).
sensor_last_heartbeat_age_seconds = ScrapeGauge(
    "sensor_last_heartbeat_age_seconds",
    "Seconds since each active sensor's last heartbeat.",
    ["sensor_id", "org_id"],
)

sensors_offline = ScrapeGauge(
    "sensors_offline",
    "Active sensors whose last heartbeat is older than the offline threshold.",
    ["org_id"],
)

# Row counts, refreshed on scrape from the DB. Counters on the Celery
# workers never reach /metrics (separate process); these gauges read the
# tables directly, so retention actually shows up here. Indexed on
# (org_id, created_at) makes COUNT cheap even at millions of rows.
sensor_activity_rows = ScrapeGauge(
    "sensor_activity_rows",
    "Total rows in sensor_activity, per organization.",
    ["org_id"],
)

sensor_violations_rows = ScrapeGauge(
    "sensor_violations_rows",
    "Total rows in egress_violations, per organization.",
    ["org_id"],
)

# Retention health gauges. The two oldest-age series tell you whether the
# prune is keeping up (age should hover just below the configured
# retention * 86400); the three status series tell you whether the prune
# ran at all and what it did the last time. Both tables are covered.
sensor_activity_oldest_age_seconds = ScrapeGauge(
    "sensor_activity_oldest_age_seconds",
    "Age in seconds of the oldest sensor_activity row, per organization.",
    ["org_id"],
)

sensor_violations_oldest_age_seconds = ScrapeGauge(
    "sensor_violations_oldest_age_seconds",
    "Age in seconds of the oldest egress_violations row, per organization.",
    ["org_id"],
)

retention_last_pruned_at_seconds_ago = ScrapeGauge(
    "retention_last_pruned_at_seconds_ago",
    "Seconds since the last successful prune, per table and organization.",
    ["table", "org_id"],
)

retention_last_prune_failed = ScrapeGauge(
    "retention_last_prune_failed",
    "1 if the last prune failed for this table/organization, else 0.",
    ["table", "org_id"],
)

retention_last_prune_rows = ScrapeGauge(
    "retention_last_prune_rows",
    "Rows deleted by the last prune, per table and organization.",
    ["table", "org_id"],
)

# Audit log health. The audit log is append-only and tamper-evident (hash
# chain + signed Merkle checkpoints, see app/core/audit_chain.py): rows
# are never deleted, by design. These gauges tell you the log is growing
# at a sane rate and the checkpoint worker is still sealing it. A rising
# oldest_age is expected (the first record never goes away); a rising
# latest_age means the checkpoint worker stopped.
audit_logs_rows = ScrapeGauge(
    "audit_logs_rows",
    "Total rows in ai_audit_logs, per organization.",
    ["org_id"],
)

audit_logs_oldest_age_seconds = ScrapeGauge(
    "audit_logs_oldest_age_seconds",
    "Age in seconds of the oldest ai_audit_logs row, per organization.",
    ["org_id"],
)

audit_checkpoints_rows = ScrapeGauge(
    "audit_checkpoints_rows",
    "Total signed checkpoints per organization.",
    ["org_id"],
)

audit_checkpoints_latest_age_seconds = ScrapeGauge(
    "audit_checkpoints_latest_age_seconds",
    "Seconds since the newest audit checkpoint was issued, per organization.",
    ["org_id"],
)

# The actionable metric: how many records exist that no signed Merkle
# root covers yet. Zero means every record is provable against a
# checkpoint. A non-zero value stuck for more than a few minutes means
# the audit.checkpoint task is not keeping up (worker down, task failing,
# or no signing key). The age of the last checkpoint alone is misleading
# — an inactive organization legitimately has no new checkpoints, so its
# "age" grows without anything being wrong.
audit_unsealed_records = ScrapeGauge(
    "audit_unsealed_records",
    "Audit rows not yet covered by a signed checkpoint, per organization.",
    ["org_id"],
)

# A sensor is offline when it has missed three heartbeats in a row, and never
# sooner than five minutes: a fixed five minutes would call a sensor with a
# 120 s heartbeat offline after two late beats. The same rule drives this
# gauge and the warning egress_sensor.warn_offline_sensors sends.
OFFLINE_FLOOR = timedelta(minutes=5)
OFFLINE_MISSED_BEATS = 3
DEFAULT_HEARTBEAT_SECONDS = 30


def offline_after(heartbeat_seconds: int | None) -> timedelta:
    beat = heartbeat_seconds or DEFAULT_HEARTBEAT_SECONDS
    return max(OFFLINE_FLOOR, timedelta(seconds=OFFLINE_MISSED_BEATS * beat))


async def heartbeat_by_org(db: AsyncSession) -> dict[int, int]:
    """Each organization's configured heartbeat; an organization without a
    settings row uses the default."""
    from app.models.egress_sensor import EgressPolicySettings

    rows = await db.execute(select(EgressPolicySettings.org_id, EgressPolicySettings.heartbeat_seconds))
    return {org_id: beat for org_id, beat in rows.all()}


async def update_db_gauges(db: AsyncSession) -> None:
    """Refresh the DB-derived gauges. Called from GET /metrics.

    Revoked sensors are excluded: they are not expected to heartbeat, so
    including them would inflate both series.
    """
    for g in _SCRAPE_GAUGES:
        g.clear()
    now = datetime.now(timezone.utc)
    rows = (
        await db.execute(
            select(
                EgressSensor.id,
                EgressSensor.org_id,
                EgressSensor.last_seen_at,
            ).where(EgressSensor.revoked_at.is_(None))
        )
    ).all()

    # Pre-seed per-org offline counters with 0 so an organization whose
    # sensors are all healthy shows "0 offline", not "no series".
    org_ids = {org_id for _, org_id, _ in rows}
    offline_by_org: dict[int, int] = {oid: 0 for oid in org_ids}
    beats = await heartbeat_by_org(db) if rows else {}
    for sensor_id, org_id, last_seen in rows:
        if last_seen is None:
            continue
        age = (now - last_seen).total_seconds()
        sensor_last_heartbeat_age_seconds.labels(
            sensor_id=str(sensor_id), org_id=str(org_id)
        ).set(age)
        if now - last_seen > offline_after(beats.get(org_id)):
            offline_by_org[org_id] += 1
    for org_id, n in offline_by_org.items():
        sensors_offline.labels(org_id=str(org_id)).set(n)

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

    # Audit log health. Rows are never deleted (append-only proof), so a
    # rising count is expected; what matters is that the checkpoint worker
    # keeps sealing. audit_checkpoints_latest_age_seconds > 2h is the
    # actionable alert.
    from app.models.audit_log import AIAuditLog, AuditCheckpoint

    audit_stats = (
        await db.execute(
            select(
                AIAuditLog.org_id,
                func.count().label("rows"),
                func.min(AIAuditLog.created_at).label("oldest"),
            ).group_by(AIAuditLog.org_id)
        )
    ).all()
    for org_id, rows, oldest in audit_stats:
        org = str(org_id)
        audit_logs_rows.labels(org_id=org).set(rows or 0)
        if oldest is not None:
            audit_logs_oldest_age_seconds.labels(org_id=org).set(
                (now - oldest).total_seconds()
            )

    cp_stats = (
        await db.execute(
            select(
                AuditCheckpoint.org_id,
                func.count().label("rows"),
                func.max(AuditCheckpoint.issued_at).label("latest"),
            ).group_by(AuditCheckpoint.org_id)
        )
    ).all()
    for org_id, rows, latest in cp_stats:
        org = str(org_id)
        audit_checkpoints_rows.labels(org_id=org).set(rows or 0)
        if latest is not None:
            audit_checkpoints_latest_age_seconds.labels(org_id=org).set(
                (now - latest).total_seconds()
            )

    # Unsealed = audit head (max seq) minus the largest sealed tree_size.
    # One query per table, aggregated; both are small (one row per org).
    unsealed = (
        await db.execute(
            select(
                AIAuditLog.org_id,
                func.max(AIAuditLog.seq).label("head"),
            ).group_by(AIAuditLog.org_id)
        )
    ).all()
    sealed = {
        org_id: (size or 0)
        for org_id, size in (
            await db.execute(
                select(
                    AuditCheckpoint.org_id,
                    func.max(AuditCheckpoint.tree_size),
                ).group_by(AuditCheckpoint.org_id)
            )
        ).all()
    }
    for org_id, head in unsealed:
        org = str(org_id)
        sealed_upto = sealed.get(org_id, 0)
        audit_unsealed_records.labels(org_id=org).set(max(0, (head or 0) - sealed_upto))
