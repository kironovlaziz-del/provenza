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
    for e in events:
        if e.workload_id not in by_id:
            dropped += 1
            continue
        accepted.append(e)
        db.add(EgressViolation(
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
        ))

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
    rows = []
    for e in events:
        if e.workload_id not in valid:
            dropped += 1
            continue
        rows.append(SensorActivity(
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
        ))

    if rows:
        db.add_all(rows)
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
