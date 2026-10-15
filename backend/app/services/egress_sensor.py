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

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_api_key
from app.models.egress_sensor import (
    EgressPolicyRevision,
    EgressSensor,
    EgressViolation,
    EgressWorkload,
)
from app.schemas.egress_sensor import PolicyAllow, PolicyOut, PolicyWorkload, ViolationIn

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
            isolated=bool(w.isolated),
            isolated_reason=w.isolated_reason,
        ))

    return PolicyOut(
        schema=1,
        version=str(rev),
        refresh_seconds=30,
        heartbeat_seconds=30,
        workloads=out_workloads,
    )


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
