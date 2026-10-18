# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza - https://github.com/kironovlaziz-del/provenza

"""
Business logic for the egress sensor API.

Nothing here touches the request/response cycle: it takes a session and
returns plain data, so it can be reused from background jobs (the offline
checker) without dragging FastAPI into it.
"""

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Tuple

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_api_key
from app.models.egress_sensor import (
    EgressPolicyRevision,
    EgressPolicySettings,
    EgressSensor,
    EgressSensorWorkload,
    EgressViolation,
    EgressWorkload,
    SensorActivity,)
from app.core.metrics import (
    sensor_activity_dropped_total,
    sensor_activity_inserted_total,
    sensor_event_time_rejected_total,
    sensor_violations_dropped_total,
    sensor_violations_inserted_total,
)
from app.schemas.egress_sensor import (HeartbeatIn, PolicyAllow, PolicyOut, PolicySettingsOut,
                                    PolicySettingsUpdate, PolicyWorkload, SensorWorkloadOut,
                                    ViolationIn)

logger = logging.getLogger(__name__)

SENSOR_KEY_PREFIX = "pvz_sensor_"
# How much of the key is shown in the UI so two keys can be told apart.
# The full key is 11 + 32 = 43 chars; the prefix we keep is 11 + 8 = 19.
KEY_DISPLAY_LEN = 19

# What the UI shows in the incident card; distinguishes this kind of incident
# from others.
INCIDENT_TYPE = "egress_violation"
# Only these actions produce an incident or a notification: observe mode is a
# record, not a signal.
_LOUD = ("alerted", "blocked")

# How long a sensor may be silent before we warn the organization.
OFFLINE_AFTER = timedelta(minutes=5)


def new_sensor_key() -> Tuple[str, str, str]:
    """Returns (plaintext, hash, display_prefix) for a new sensor key."""
    raw = SENSOR_KEY_PREFIX + secrets.token_hex(16)
    return raw, hash_api_key(raw), raw[:KEY_DISPLAY_LEN]


async def find_sensor_by_key(db: AsyncSession, raw_key: str) -> Optional[EgressSensor]:
    if not raw_key:
        return None
    result = await db.execute(
        select(EgressSensor).where(EgressSensor.key_hash == hash_api_key(raw_key))
    )
    return result.scalar_one_or_none()


# ---------------------------------------------------------------- revisions

async def revision_for(db: AsyncSession, org_id: int) -> int:
    """Read the current revision (0 if the org has never had a workload)."""
    result = await db.execute(
        select(EgressPolicyRevision).where(EgressPolicyRevision.org_id == org_id)
    )
    row = result.scalar_one_or_none()
    return row.revision if row else 0


async def bump_revision(db: AsyncSession, org_id: int) -> int:
    """Increment the organization's revision. Creates the row on first use.
    Callers are expected to commit; this only stages the change."""
    result = await db.execute(
        select(EgressPolicyRevision).where(EgressPolicyRevision.org_id == org_id)
    )
    row = result.scalar_one_or_none()
    if row is None:
        row = EgressPolicyRevision(org_id=org_id, revision=1)
        db.add(row)
        await db.flush()
        return row.revision
    row.revision = (row.revision or 0) + 1
    await db.flush()
    return row.revision


# ---------------------------------------------------------------- settings

# Values that used to be hardcoded in build_policy. Kept here so a fresh
# organization and an explicit settings row agree.
SETTINGS_DEFAULTS = {
    "refresh_seconds": 30,
    "heartbeat_seconds": 30,
    "default_mode": "observe",
    "default_dns": "off",
}


async def settings_for(db: AsyncSession, org_id: int) -> EgressPolicySettings:
    """Return the organization's policy settings, creating the row with
    defaults on first call. Callers commit; this only stages a new row."""
    row = (await db.execute(
        select(EgressPolicySettings).where(EgressPolicySettings.org_id == org_id)
    )).scalar_one_or_none()
    if row is not None:
        return row
    row = EgressPolicySettings(org_id=org_id, **SETTINGS_DEFAULTS)
    db.add(row)
    await db.flush()
    return row


async def update_settings(
    db: AsyncSession, org_id: int, actor_user_id: int, data: PolicySettingsUpdate
) -> EgressPolicySettings:
    """Apply an update to the organization's policy settings. Because the
    settings row may not exist yet, this reads through settings_for first,
    then applies only the fields the caller sent."""
    row = await settings_for(db, org_id)
    fields = data.model_dump(exclude_unset=True)
    for k, v in fields.items():
        setattr(row, k, v)
    row.updated_by = actor_user_id
    await db.flush()
    return row


# ---------------------------------------------------------------- policy

def _allow_rules(raw: Any) -> list[PolicyAllow]:
    """Turn the JSONB stored on the workload into PolicyAllow objects.

    The stored shape is what WorkloadIn validated: {dest|source, ports,
    protocols}. Unknown keys are dropped so a hand-edited row cannot leak
    something the sensor does not expect.
    """
    if not isinstance(raw, list):
        return []
    out: list[PolicyAllow] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        dest = item.get("dest")
        source = item.get("source")
        ports = item.get("ports") or []
        protocols = item.get("protocols") or []
        out.append(PolicyAllow(
            dest=dest if dest else None,
            source=source if source else None,
            ports=[int(p) for p in ports],
            protocols=[str(p) for p in protocols],
        ))
    return out


async def forced_isolation(db: AsyncSession, org_id: int, workloads) -> dict:
    """Workloads that must have no network now, whatever their own setting:
    every one while the organization's AI traffic is stopped (kill switch),
    and those linked to an agent that is not active (stopped, quarantined,
    suspended, retired or gone). workload id -> reason."""
    from app.models.agent import Agent
    from app.services.kill_switch import traffic_stop

    if not workloads:
        return {}
    if await traffic_stop(db, org_id) is not None:
        return {w.id: "org_traffic_stopped" for w in workloads}
    agent_ids = {w.agent_id for w in workloads if w.agent_id is not None}
    if not agent_ids:
        return {}
    statuses = dict((await db.execute(
        select(Agent.id, Agent.status).where(Agent.org_id == org_id, Agent.id.in_(agent_ids))
    )).all())
    return {w.id: f"agent_{statuses.get(w.agent_id) or 'missing'}" for w in workloads
            if w.agent_id is not None and statuses.get(w.agent_id) != "active"}


async def _policy_workloads(db: AsyncSession, org_id: int):
    return (await db.execute(
        select(EgressWorkload)
        .where(
            EgressWorkload.org_id == org_id,
            EgressWorkload.enabled.is_(True),
            EgressWorkload.deleted_at.is_(None),
        )
        .order_by(EgressWorkload.id.asc())
    )).scalars().all()


async def policy_version(db: AsyncSession, org_id: int) -> str:
    """The policy's version (and ETag): the revision, plus a digest of what the
    kill switch and agent statuses isolate - those change without a workload
    edit, and the sensors must notice at their next poll."""
    import hashlib
    import json

    rev = await revision_for(db, org_id)
    forced = await forced_isolation(db, org_id, await _policy_workloads(db, org_id))
    if not forced:
        return str(rev)
    digest = hashlib.sha256(json.dumps(sorted(forced.items())).encode()).hexdigest()[:12]
    return f"{rev}-{digest}"


async def build_policy(db: AsyncSession, org_id: int) -> PolicyOut:
    """Assemble the policy document for the sensor.

    Only workloads that are enabled and not soft-deleted are included.
    Their order is the id order: the sensor assigns each workload an index
    that positions its per-workload DNS proxy port, so a stable order keeps
    a sensor's ports stable across polls.
    """
    rev = await revision_for(db, org_id)

    result = await db.execute(
        select(EgressWorkload)
        .where(
            EgressWorkload.org_id == org_id,
            EgressWorkload.enabled.is_(True),
            EgressWorkload.deleted_at.is_(None),
        )
        .order_by(EgressWorkload.id.asc())
    )
    workloads = result.scalars().all()
    forced = await forced_isolation(db, org_id, workloads)

    out_workloads: list[PolicyWorkload] = []
    for w in workloads:
        out_workloads.append(PolicyWorkload(
            id=w.id,
            name=w.name,
            agent_id=w.agent_id,
            cgroup_patterns=list(w.cgroup_patterns or []),
            run_as_users=list(w.run_as_users or []),
            egress_allow=_allow_rules(w.egress_allow),
            ingress_allow=_allow_rules(w.ingress_allow),
            dns=w.dns or "off",
            mode=w.mode or "observe",
            isolated=bool(w.isolated) or w.id in forced,
            isolated_reason=w.isolated_reason if w.isolated else forced.get(w.id),
        ))

    settings = await settings_for(db, org_id)

    return PolicyOut(
        schema=1,
        version=await policy_version(db, org_id),
        refresh_seconds=settings.refresh_seconds,
        heartbeat_seconds=settings.heartbeat_seconds,
        workloads=out_workloads,
    )


async def _record_prune_status(
    db: AsyncSession, *, table: str, rows: int, error: str | None,
) -> None:
    """Persist the outcome of the last prune so /metrics can surface it.

    The Celery worker runs in its own process; a counter incremented there
    would never reach the uvicorn /metrics endpoint. Writing to the
    EgressPolicySettings row keeps the status visible to update_db_gauges,
    which reads it on each scrape.

    table is "activity" or "violations". Missing settings rows are created
    with defaults so a first prune on a fresh org still records status.
    """
    from datetime import datetime, timezone

    # Determine which orgs to update: those whose settings row already
    # exists are updated; those without a row are created with defaults.
    existing = {
        s.org_id: s
        for s in (
            await db.execute(select(EgressPolicySettings))
        ).scalars().all()
    }

    now = datetime.now(timezone.utc)

    # For every org that had rows touched in this run (or every org with a
    # settings row), write the status. Practically: upsert on all orgs
    # that have a settings row AND insert for any org without one, so the
    # next prune on that org has a place to write.
    all_org_ids = set(existing.keys())
    # Also include orgs known from tables we just pruned.
    from app.models.egress_sensor import SensorActivity, EgressViolation
    if table == "activity":
        all_org_ids.update(
            (await db.execute(select(SensorActivity.org_id).distinct())).scalars().all()
        )
    else:
        all_org_ids.update(
            (await db.execute(select(EgressViolation.org_id).distinct())).scalars().all()
        )

    for org_id in all_org_ids:
        s = existing.get(org_id)
        if s is None:
            s = EgressPolicySettings(org_id=org_id)
            db.add(s)
        if table == "activity":
            s.activity_last_pruned_at = now
            s.activity_last_prune_rows = rows
            s.activity_last_prune_error = (error or "")[:500] if error else None
        else:
            s.violation_last_pruned_at = now
            s.violation_last_prune_rows = rows
            s.violation_last_prune_error = (error or "")[:500] if error else None

    await db.flush()


async def prune_sensor_activity(db: AsyncSession, default_days: int = 30) -> int:
    """Delete sensor_activity rows older than each organization's retention.

    Retention is per-org (EgressPolicySettings.activity_retention_days); an
    organization without a settings row falls back to default_days. A value
    of 0 disables pruning for that organization entirely.

    Deletion is chunked so a large backlog does not hold a long lock on the
    table. Called hourly by the egress_sensor.prune_activity task.
    """
    retentions = {
        row.org_id: row.activity_retention_days
        for row in (
            await db.execute(
                select(EgressPolicySettings.org_id, EgressPolicySettings.activity_retention_days)
            )
        ).all()
    }
    org_ids = (
        await db.execute(select(SensorActivity.org_id).distinct())
    ).scalars().all()

    total = 0
    chunk = 5000
    for org_id in org_ids:
        days = retentions.get(org_id, default_days)
        if days <= 0:
            continue
        cutoff = now_utc() - timedelta(days=days)
        while True:
            ids = (
                await db.execute(
                    select(SensorActivity.id)
                    .where(
                        SensorActivity.org_id == org_id,
                        SensorActivity.created_at < cutoff,
                    )
                    .limit(chunk)
                )
            ).scalars().all()
            if not ids:
                break
            await db.execute(delete(SensorActivity).where(SensorActivity.id.in_(ids)))
            total += len(ids)
            if len(ids) < chunk:
                break
    await _record_prune_status(
        db, table="activity", rows=total, error=None,
    )
    if total:
        logger.info("pruned sensor_activity", extra={"rows": total})
    return total



async def prune_violations(db: AsyncSession, default_days: int = 30) -> int:
    """Delete egress_violations rows older than each organization's retention.

    Same shape as prune_sensor_activity: retention is per-org, an org without
    a settings row falls back to default_days, 0 disables pruning. Chunked
    to avoid a long table lock. Called hourly by
    egress_sensor.prune_violations.
    """
    retentions = {
        row.org_id: row.violation_retention_days
        for row in (
            await db.execute(
                select(EgressPolicySettings.org_id, EgressPolicySettings.violation_retention_days)
            )
        ).all()
    }
    org_ids = (
        await db.execute(select(EgressViolation.org_id).distinct())
    ).scalars().all()

    total = 0
    chunk = 5000
    for org_id in org_ids:
        days = retentions.get(org_id, default_days)
        if days <= 0:
            continue
        cutoff = now_utc() - timedelta(days=days)
        while True:
            ids = (
                await db.execute(
                    select(EgressViolation.id)
                    .where(
                        EgressViolation.org_id == org_id,
                        EgressViolation.created_at < cutoff,
                    )
                    .limit(chunk)
                )
            ).scalars().all()
            if not ids:
                break
            await db.execute(delete(EgressViolation).where(EgressViolation.id.in_(ids)))
            total += len(ids)
            if len(ids) < chunk:
                break
    await _record_prune_status(
        db, table="violations", rows=total, error=None,
    )
    if total:
        logger.info("pruned egress_violations", extra={"rows": total})
    return total

async def ingest_heartbeat(
    db: AsyncSession, sensor: EgressSensor, data: HeartbeatIn
) -> None:
    """Apply a heartbeat to a sensor.

    Two writes happen here, both under the caller's transaction:

      * the sensor row - version, hostname, hooks, warnings, errors, the
        dropped-event counter, last_seen_at;
      * the per-workload snapshot rows - cgroups and DNS counters for every
        workload the sensor says it governs.

    A workload the sensor reports but this organization does not have is
    dropped (with a log line): that is a deleted workload, and the sensor
    picks up the new policy on its next poll. A snapshot row this sensor
    had before, and no longer reports, is deleted: the workload either
    left the policy or the sensor's view of it changed.
    """
    # -------- sensor row
    sensor.hostname = data.hostname
    sensor.version = data.version
    sensor.kernel = data.kernel
    sensor.enforcing = data.enforcing
    sensor.hooks = list(data.hooks or [])
    sensor.warnings = list(data.warnings or [])
    sensor.errors = list(data.errors or [])
    sensor.dropped_events = data.dropped_events
    sensor.config_version = data.config_version
    sensor.last_seen_at = now_utc()
    if data.allowed_total is not None:
        sensor.allowed_total = data.allowed_total
    if data.denied_total is not None:
        sensor.denied_total = data.denied_total
    if data.observed_total is not None:
        sensor.observed_total = data.observed_total
    if data.allowed_per_min is not None:
        sensor.allowed_per_min = data.allowed_per_min
    if data.denied_per_min is not None:
        sensor.denied_per_min = data.denied_per_min
    if data.observed_per_min is not None:
        sensor.observed_per_min = data.observed_per_min

    # -------- per-workload snapshot
    reported = data.workloads or []
    if not reported:
        # No workloads in the payload: nothing to upsert, and any rows this
        # sensor had are stale. Clean them so the UI does not show ghost
        # cgroups after a policy narrowed down to zero workloads.
        await db.execute(
            delete(EgressSensorWorkload).where(EgressSensorWorkload.sensor_id == sensor.id)
        )
        return

    wids = {w.id for w in reported}
    known = set((await db.execute(
        select(EgressWorkload.id).where(
            EgressWorkload.org_id == sensor.org_id,
            EgressWorkload.id.in_(wids),
        )
    )).scalars())

    # Existing rows for this sensor: what we have to update, and what we
    # have to delete because the sensor no longer reports it.
    existing = {row.workload_id: row for row in (await db.execute(
        select(EgressSensorWorkload).where(EgressSensorWorkload.sensor_id == sensor.id)
    )).scalars()}

    seen: set[int] = set()
    for w in reported:
        if w.id not in known:
            logger.warning(
                "egress_sensor %s: heartbeat reports unknown workload %d, dropped",
                sensor.id, w.id,
            )
            continue
        seen.add(w.id)
        privileged = list(w.privileged or [])
        port = w.dns_port
        if w.id in existing:
            row = existing[w.id]
            row.cgroups = w.cgroups
            row.processes = w.processes
            row.privileged = privileged
            row.dns_port = port
            row.dns_total = w.dns_total
            row.dns_allowed = w.dns_allowed
            row.dns_denied = w.dns_denied
            # updated_at is onupdate=func.now(); flush will bump it.
        else:
            db.add(EgressSensorWorkload(
                org_id=sensor.org_id,
                sensor_id=sensor.id,
                workload_id=w.id,
                cgroups=w.cgroups,
                processes=w.processes,
                privileged=privileged,
                dns_port=port,
                dns_total=w.dns_total,
                dns_allowed=w.dns_allowed,
                dns_denied=w.dns_denied,
            ))

    for wid, row in existing.items():
        if wid not in seen:
            await db.delete(row)

    await db.flush()


async def workloads_for_sensor(
    db: AsyncSession, sensor_id: int
) -> list[SensorWorkloadOut]:
    """The sensor's latest per-workload snapshot, joined with names, sorted
    by workload id. Only workloads of the sensor's organization are shown,
    so a workload that left the policy drops out even before the sensor's
    next heartbeat."""
    rows = (await db.execute(
        select(EgressSensorWorkload, EgressWorkload.name)
        .join(EgressWorkload, EgressWorkload.id == EgressSensorWorkload.workload_id)
        .where(EgressSensorWorkload.sensor_id == sensor_id)
        .order_by(EgressSensorWorkload.workload_id.asc())
    )).all()

    out: list[SensorWorkloadOut] = []
    for snap, name in rows:
        out.append(SensorWorkloadOut(
            workload_id=snap.workload_id,
            workload_name=name,
            cgroups=snap.cgroups,
            processes=snap.processes,
            privileged=list(snap.privileged or []),
            dns_port=snap.dns_port,
            dns_total=snap.dns_total,
            dns_allowed=snap.dns_allowed,
            dns_denied=snap.dns_denied,
            updated_at=snap.updated_at,
        ))
    return out


def policy_etag(version: str) -> str:
    """The value of the ETag header; the sensor compares it to If-None-Match
    and echoes it back verbatim. It carries the quotes around the version,
    matching what sensor/internal/client/client.go sends."""
    return f'"{version}"'


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


# Event times come from the sensor's clock (the kernel's, converted on the
# host). Inside this window they are kept: a sensor posts what it buffered
# while the control plane was unreachable. Outside it - a host with a wrong
# clock, or a sensor key used to date events into the past (so retention
# deletes them at once) or into the future (so they never age out and stay
# at the top of every feed) - the server's own time is used instead.
EVENT_TIME_PAST = timedelta(days=7)
EVENT_TIME_FUTURE = timedelta(minutes=5)


def event_time(ts: Optional[datetime], now: datetime) -> Optional[datetime]:
    """The time to store for an event, or None for "now" (the column
    default). A time without a zone is taken as UTC."""
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    if now - EVENT_TIME_PAST <= ts <= now + EVENT_TIME_FUTURE:
        return ts
    return None


def _note_rejected_times(sensor: EgressSensor, n: int, stream: str) -> None:
    if n:
        sensor_event_time_rejected_total.inc(n)
        logger.warning(
            "egress_sensor %s: %d %s events dated outside [-%s, +%s] of the server's "
            "clock; stored with the server's time (is the host's clock right?)",
            sensor.id, n, stream, EVENT_TIME_PAST, EVENT_TIME_FUTURE,
        )


# ---------------------------------------------------------------- violations

async def ingest_violations(
    db: AsyncSession, sensor: EgressSensor, events: list[ViolationIn]
) -> int:
    """Validate, insert, create incidents for agent-linked workloads, and
    send one notification per batch. Returns the number of events dropped
    because their workload_id is not this organization's.

    An event is dropped (and logged) when its workload_id is not in the
    organization: that happens when a sensor reports for a workload that was
    deleted between its last config fetch and now. The sensor gets the new
    config on its next poll and stops reporting for it.

    Every event in the batch is inserted first: an alert mode violation is a
    record, not a signal, so a broken notification channel cannot lose it.
    """
    if not events:
        return 0

    wids = {e.workload_id for e in events}
    rows = (await db.execute(
        select(EgressWorkload.id, EgressWorkload.agent_id).where(
            EgressWorkload.org_id == sensor.org_id,
            EgressWorkload.id.in_(wids),
        )
    )).all()
    by_id = {wid: agent_id for wid, agent_id in rows}

    accepted: list[ViolationIn] = []
    dropped = 0
    bad_times = 0
    now = now_utc()
    for e in events:
        if e.workload_id not in by_id:
            dropped += 1
            continue
        accepted.append(e)
        kwargs = dict(
            org_id=sensor.org_id,
            sensor_id=sensor.id,
            workload_id=e.workload_id,
            action=e.action,
            kind=e.kind,
            protocol=e.protocol,
            dst_ip=e.dst_ip,
            dst_port=e.dst_port,
            dst_name=e.dst_name,
            comm=e.comm,
            cgroup=e.cgroup,
            isolated=e.isolated,
            count=e.count,
        )
        when = event_time(e.ts, now)
        if when is not None:
            kwargs["created_at"] = when
        elif e.ts is not None:
            bad_times += 1
        db.add(EgressViolation(**kwargs))
    _note_rejected_times(sensor, bad_times, "violation")

    if dropped:
        logger.warning(
            "egress_sensor %s: dropped %d events for unknown workload ids %s",
            sensor.id, dropped, sorted(wids - by_id.keys()),
        )

    # One incident per (workload, action, kind, destination) for loud events
    # on agent-linked workloads. Observe mode stays silent.
    from app.models.agent_action import AgentIncident
    seen: set[tuple] = set()
    for e in accepted:
        agent_id = by_id[e.workload_id]
        if e.action not in _LOUD or agent_id is None:
            continue
        key = (e.workload_id, e.action, e.kind, e.dst_ip, e.dst_port, e.dst_name)
        if key in seen:
            continue
        seen.add(key)
        db.add(AgentIncident(
            org_id=sensor.org_id,
            agent_id=agent_id,
            incident_type=INCIDENT_TYPE,
            severity="high" if e.action == "blocked" else "medium",
            details={
                "sensor_id": sensor.id,
                "sensor_name": sensor.name,
                "workload_id": e.workload_id,
                "kind": e.kind,
                "protocol": e.protocol,
                "dst_ip": e.dst_ip,
                "dst_port": e.dst_port,
                "dst_name": e.dst_name,
                "comm": e.comm,
                "count": e.count,
            },
            resolved=False,
        ))

    await db.flush()

    loud = [e for e in accepted if e.action in _LOUD]
    if loud:
        blocked = sum(1 for e in loud if e.action == "blocked")
        alerted = len(loud) - blocked
        try:
            from app.services import notification_service
            await notification_service.notify(
                db, sensor.org_id,
                event_type="egress_violation",
                subject=f"Egress violations on {sensor.name}",
                message=f"{blocked} blocked, {alerted} alerted ({len(accepted)} events in batch)",
                metadata={
                    "sensor_id": sensor.id,
                    "sensor_name": sensor.name,
                    "blocked": blocked,
                    "alerted": alerted,
                    "severity": "high" if blocked else "medium",
                },
            )
        except Exception as exc:  # best-effort, must not lose the record
            logger.warning("egress_sensor %s: notification failed: %s", sensor.id, exc)

    if dropped:
        sensor_violations_dropped_total.inc(dropped)
    accepted = len(events) - dropped
    if accepted:
        sensor_violations_inserted_total.inc(accepted)
    return dropped


# ---------------------------------------------------------------- offline

async def ingest_activities(db, sensor, events):
    """Store a batch of sampled allowed connections.

    Mirrors ingest_violations: events whose workload_id is not this
    organization's are dropped and counted. No incidents, no notifications,
    no counter bumps -- activity is read-only telemetry.
    """
    if not events:
        return 0

    wids = {e.workload_id for e in events}
    q = select(EgressWorkload.id).where(
        EgressWorkload.id.in_(wids),
        EgressWorkload.org_id == sensor.org_id,
    )
    valid = {row[0] for row in (await db.execute(q)).all()}

    dropped = 0
    bad_times = 0
    now = now_utc()
    rows = []
    for e in events:
        if e.workload_id not in valid:
            dropped += 1
            continue
        kwargs = dict(
            org_id=sensor.org_id,
            sensor_id=sensor.id,
            workload_id=e.workload_id,
            action=e.action,
            kind=e.kind,
            protocol=e.protocol or None,
            dst_ip=e.dst_ip,
            dst_port=e.dst_port,
            dst_name=e.dst_name,
            comm=e.comm,
            cgroup=e.cgroup,
            isolated=e.isolated,
            count=e.count,
        )
        when = event_time(e.ts, now)
        if when is not None:
            kwargs["created_at"] = when
        elif e.ts is not None:
            bad_times += 1
        rows.append(SensorActivity(**kwargs))
    _note_rejected_times(sensor, bad_times, "activity")

    if rows:
        db.add_all(rows)
    if dropped:
        sensor_activity_dropped_total.inc(dropped)
    accepted = len(events) - dropped
    if accepted:
        sensor_activity_inserted_total.inc(accepted)
    return dropped

async def warn_offline_sensors(db: AsyncSession) -> int:
    """Warn once per silent sensor. A sensor counts as silent when it has
    sent at least one heartbeat and the last one is older than OFFLINE_AFTER.
    We warn when offline_notified_at is null or older than the last heartbeat
    (meaning: it came back after we warned, then went silent again).

    Returns the number of sensors warned.
    """
    threshold = now_utc() - OFFLINE_AFTER
    rows = (await db.execute(
        select(EgressSensor).where(
            EgressSensor.enabled.is_(True),
            EgressSensor.revoked_at.is_(None),
            EgressSensor.last_seen_at.isnot(None),
            EgressSensor.last_seen_at < threshold,
            or_(
                EgressSensor.offline_notified_at.is_(None),
                EgressSensor.offline_notified_at < EgressSensor.last_seen_at,
            ),
        )
    )).scalars().all()

    now = now_utc()
    warned = 0
    for s in rows:
        try:
            from app.services import notification_service
            await notification_service.notify(
                db, s.org_id,
                event_type="egress_sensor_offline",
                subject=f"Sensor {s.name} is not reporting",
                message=f"Last heartbeat {s.last_seen_at.isoformat()} (host {s.hostname or 'unknown'}).",
                metadata={
                    "sensor_id": s.id,
                    "sensor_name": s.name,
                    "hostname": s.hostname,
                    "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None,
                    "severity": "high",
                },
            )
        except Exception as exc:
            logger.warning("offline notification for sensor %s failed: %s", s.id, exc)
            continue
        s.offline_notified_at = now
        warned += 1
    await db.flush()
    return warned
