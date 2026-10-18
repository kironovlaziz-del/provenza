# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Egress sensor API.

Two routers, one prefix (/api/v1/egress-sensor):

  admin_router   — used by the UI. Authenticates the human admin (JWT)
                   and scopes every operation to the admin's org.
  sensor_router  — used by the sensor daemon itself. Authenticates with
                   X-Sensor-Key (pvz_sensor_...) and answers the three
                   calls the sensor makes: fetch the config, post a
                   heartbeat, post a batch of violations.

The sensor side is deliberately narrow: /config, /heartbeat, /violations.
Anything else the sensor might need is added there, not on the admin
router, so an admin key cannot accidentally be used from a host.
"""

from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.api.export_keys import export_reader
from app.core.database import get_db
from app.core.errors import api_error
from app.models.egress_sensor import (
    EgressSensor,
    EgressSensorCommand,
    EgressViolation,
    EgressWorkload,
    SensorActivity,
)
from app.models.user import User, UserRole
from app.schemas.egress_sensor import (
    CommandAckIn,
    CommandForSensor,
    CommandIn,
    CommandOut,
    HeartbeatIn,
    HeartbeatResponseOut,
    PolicySettingsOut,
    PolicySettingsUpdate,
    SensorCreated,
    SensorOut,
    SensorWorkloadOut,
    SigningKeyOut,
    SigningKeyRotationOut,
    SensorRegister,
    SensorUpdate,
    ViolationOut,
    ViolationsBatch,
    WorkloadIn,
    WorkloadOut,
    WorkloadUpdate,
    ActivityBatch,
    ActivityOut,
    EventOut,
    EventList,)
from app.services import egress_sensor as svc
from app.services import egress_sensor_commands as cmd_svc
from app.services.audit_service import AuditService

# ---------------------------------------------------------------- admin

admin_router = APIRouter()


async def _get_org_sensor(
    db: AsyncSession, sensor_id: int, org_id: int, include_revoked: bool = False
) -> EgressSensor:
    result = await db.execute(
        select(EgressSensor).where(EgressSensor.id == sensor_id, EgressSensor.org_id == org_id)
    )
    sensor = result.scalar_one_or_none()
    if sensor is None or (sensor.revoked_at is not None and not include_revoked):
        raise api_error(status.HTTP_404_NOT_FOUND, "egress_sensor.not_found", id=sensor_id)
    return sensor


async def _get_org_workload(db: AsyncSession, workload_id: int, org_id: int) -> EgressWorkload:
    result = await db.execute(
        select(EgressWorkload).where(
            EgressWorkload.id == workload_id,
            EgressWorkload.org_id == org_id,
            EgressWorkload.deleted_at.is_(None),
        )
    )
    w = result.scalar_one_or_none()
    if w is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "egress_workload.not_found", id=workload_id)
    return w


# ---- sensors

@admin_router.post(
    "/sensors",
    response_model=SensorCreated,
    status_code=status.HTTP_201_CREATED,
    summary="Register a sensor and return its key once",
)
async def register_sensor(
    data: SensorRegister,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    exists = await db.execute(
        select(EgressSensor.id).where(
            EgressSensor.org_id == current_user.org_id,
            EgressSensor.name == data.name,
            EgressSensor.revoked_at.is_(None),
        )
    )
    if exists.scalar_one_or_none() is not None:
        raise api_error(status.HTTP_409_CONFLICT, "egress_sensor.name_taken", name=data.name)

    raw, h, prefix = svc.new_sensor_key()
    sensor = EgressSensor(
        org_id=current_user.org_id,
        name=data.name,
        key_hash=h,
        key_prefix=prefix,
        enabled=True,
        created_by=current_user.id,
    )
    db.add(sensor)
    await db.flush()

    await AuditService(db).log(
        current_user.org_id, current_user.id, "egress_sensor", sensor.id, "created",
        {"name": data.name, "key_prefix": sensor.key_prefix},
    )

    out = SensorOut.model_validate(sensor, from_attributes=True)
    return SensorCreated(**out.model_dump(), api_key=raw)


@admin_router.get("/sensors", response_model=list[SensorOut])
async def list_sensors(
    include_revoked: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    q = select(EgressSensor).where(EgressSensor.org_id == current_user.org_id)
    if not include_revoked:
        q = q.where(EgressSensor.revoked_at.is_(None))
    q = q.order_by(EgressSensor.id.desc())
    result = await db.execute(q)
    return list(result.scalars().all())


@admin_router.get("/sensors/{sensor_id}", response_model=SensorOut)
async def get_sensor(
    sensor_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    return await _get_org_sensor(db, sensor_id, current_user.org_id, include_revoked=True)


@admin_router.patch("/sensors/{sensor_id}", response_model=SensorOut)
async def update_sensor(
    sensor_id: int,
    data: SensorUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    sensor = await _get_org_sensor(db, sensor_id, current_user.org_id, include_revoked=True)
    fields = data.model_dump(exclude_unset=True)
    if "name" in fields and fields["name"] != sensor.name:
        clash = await db.execute(
            select(EgressSensor.id).where(
                EgressSensor.org_id == current_user.org_id,
                EgressSensor.name == fields["name"],
                EgressSensor.id != sensor.id,
                EgressSensor.revoked_at.is_(None),
            )
        )
        if clash.scalar_one_or_none() is not None:
            raise api_error(status.HTTP_409_CONFLICT, "egress_sensor.name_taken", name=fields["name"])
    changes: dict = {}
    for k, v in fields.items():
        changes[k] = {"from": getattr(sensor, k), "to": v}
    for k, v in fields.items():
        setattr(sensor, k, v)
    await db.flush()

    await AuditService(db).log(
        current_user.org_id, current_user.id, "egress_sensor", sensor.id, "updated",
        {"changes": changes},
    )
    await db.refresh(sensor)
    return sensor


@admin_router.delete("/sensors/{sensor_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_sensor(
    sensor_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    sensor = await _get_org_sensor(db, sensor_id, current_user.org_id)
    sensor.enabled = False
    sensor.revoked_at = svc.now_utc()
    await db.flush()

    await AuditService(db).log(
        current_user.org_id, current_user.id, "egress_sensor", sensor.id, "revoked",
        {"name": sensor.name, "key_prefix": sensor.key_prefix},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@admin_router.post(
    "/sensors/{sensor_id}/refresh",
    summary="Bump the org's policy revision so sensors pick it up at their next poll",
)
async def refresh_sensor(
    sensor_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """Bump the organization's policy revision. Sensors notice the change on
    their next poll (within refresh_seconds, ~30s) and fetch the new policy.
    Nothing is sent to the sensor directly: the control plane is not a
    command channel."""
    sensor = await _get_org_sensor(db, sensor_id, current_user.org_id, include_revoked=True)
    new_rev = await svc.bump_revision(db, current_user.org_id)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "egress_sensor", sensor.id, "refreshed",
        {"name": sensor.name, "new_revision": new_rev},
    )
    return {"bumped": True, "new_revision": new_rev}


@admin_router.get("/sensors/{sensor_id}/violations", response_model=list[ViolationOut])
async def list_sensor_violations(
    sensor_id: int,
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    await _get_org_sensor(db, sensor_id, current_user.org_id, include_revoked=True)
    result = await db.execute(
        select(EgressViolation)
        .where(EgressViolation.sensor_id == sensor_id, EgressViolation.org_id == current_user.org_id)
        .order_by(EgressViolation.id.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


# ---- workloads

@admin_router.get(
    "/sensors/{sensor_id}/workloads",
    response_model=list[SensorWorkloadOut],
    summary="Per-workload snapshot from the sensor's latest heartbeat",
)
async def list_sensor_workloads(
    sensor_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    await _get_org_sensor(db, sensor_id, current_user.org_id, include_revoked=True)
    return await svc.workloads_for_sensor(db, sensor_id)


@admin_router.get("/sensors/{sensor_id}/activity", response_model=list[ActivityOut])
async def list_sensor_activity(
    sensor_id: int,
    limit: int = 200,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Sampled allowed connections from this sensor, newest first. The UI's
    Activity window polls this alongside /violations."""
    q = (
        select(SensorActivity)
        .where(
            SensorActivity.sensor_id == sensor_id,
            SensorActivity.org_id == current_user.org_id,
        )
        .order_by(SensorActivity.id.desc())
        .limit(limit)
    )
    rows = (await db.execute(q)).scalars().all()
    return rows



# ---------------------------------------------------------------- events
# Unified stream for SIEM/SOAR integrations. Merges violations and
# sampled activity into one paginated feed sorted by created_at DESC.
# The existing per-table endpoints stay as-is for the UI; this is the
# machine-facing view.

import base64
import json as _json
from datetime import datetime, timezone


def _encode_cursor(event_type: str, event_id: int, created_at: datetime) -> str:
    # The cursor packs (event_type, id, created_at) because two rows can
    # share created_at to the second and the ids are not comparable across
    # tables. Opaque to the caller, base64-encoded so nothing in it can be
    # re-ordered or dropped by a client that assumes integer ids.
    payload = {
        "t": event_type,
        "i": event_id,
        "c": created_at.astimezone(timezone.utc).isoformat(),
    }
    return base64.urlsafe_b64encode(
        _json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")


# Ties on created_at are broken by table, then id: ids of the two tables
# are not comparable, the rank makes the order total.
_EVENT_RANK = {"violation": 1, "activity": 0}


def _decode_cursor(cursor: str) -> tuple[str, int, datetime]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii"))
        payload = _json.loads(raw)
        if payload["t"] not in _EVENT_RANK:
            raise ValueError(f"event type {payload['t']!r}")
        return (
            str(payload["t"]),
            int(payload["i"]),
            datetime.fromisoformat(payload["c"]),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400, detail=f"invalid cursor: {exc}"
        ) from exc


@admin_router.get(
    "/events",
    response_model=EventList,
    summary="Unified violation + activity stream for SIEM/SOAR",
)
async def list_events(
    sensor_id: Optional[int] = Query(default=None, description="Filter by sensor"),
    event_type: str = Query(
        default="all",
        description="all | violation | activity",
    ),
    since: Optional[datetime] = Query(default=None, description="Inclusive start"),
    until: Optional[datetime] = Query(default=None, description="Exclusive end"),
    limit: int = Query(default=500, ge=1, le=2000),
    cursor: Optional[str] = Query(default=None, description="Value of next_cursor from a previous page"),
    db: AsyncSession = Depends(get_db),
    org_id: int = Depends(export_reader("egress_events")),
):
    """Return violations and activity as one chronological feed.

    Read with an export key (X-Export-Key, made on the SIEM export page) or
    an administrator's session.

    Sort order is created_at DESC, then the table (violations before
    activity), then id DESC: a total order across both tables, so the
    newest event is first and ties - a batch the sensor sent without event
    times shares one created_at - still have one place. Pagination is
    cursor-based: pass next_cursor back as ?cursor=... and the server
    continues strictly after that event, with no skips or repeats and
    without the "rows shift when new data arrives" problem of offsets.

    Filters:
      - sensor_id: only events from that sensor
      - event_type: "all" (default), "violation", or "activity"
      - since / until: half-open interval [since, until)
    """
    if event_type not in ("all", "violation", "activity"):
        raise HTTPException(
            status_code=422,
            detail=f"event_type must be all|violation|activity, got {event_type!r}",
        )

    # Parse cursor once; it affects both selects the same way.
    cursor_tuple: Optional[tuple[str, int, datetime]] = None
    if cursor:
        cursor_tuple = _decode_cursor(cursor)

    async def fetch(table, et: str) -> list:
        q = select(table).where(table.org_id == org_id)
        if sensor_id is not None:
            q = q.where(table.sensor_id == sensor_id)
        if since is not None:
            q = q.where(table.created_at >= since)
        if until is not None:
            q = q.where(table.created_at < until)
        if cursor_tuple is not None:
            # Continue strictly after the cursor in the order
            # (created_at, table rank, id) DESC. At the cursor's time, a
            # table ranked above the cursor's was already sent in full,
            # one ranked below is still to come in full, and the cursor's
            # own table continues below its id.
            from sqlalchemy import and_, false, or_, true
            cur_et, cur_id, cur_ts = cursor_tuple
            rank, cur_rank = _EVENT_RANK[et], _EVENT_RANK[cur_et]
            if rank == cur_rank:
                tie = table.id < cur_id
            else:
                tie = true() if rank < cur_rank else false()
            q = q.where(or_(table.created_at < cur_ts, and_(table.created_at == cur_ts, tie)))
        # Fetch limit+1 so we can detect "there is more".
        q = q.order_by(table.created_at.desc(), table.id.desc()).limit(limit + 1)
        rows = (await db.execute(q)).scalars().all()
        return [(et, r) for r in rows]

    batches: list[tuple[str, any]] = []
    if event_type in ("all", "violation"):
        batches.extend(await fetch(EgressViolation, "violation"))
    if event_type in ("all", "activity"):
        batches.extend(await fetch(SensorActivity, "activity"))

    # Merge in the same order as the cursor: (created_at, table rank, id) DESC.
    batches.sort(
        key=lambda pair: (pair[1].created_at, _EVENT_RANK[pair[0]], pair[1].id),
        reverse=True,
    )

    has_more = len(batches) > limit
    page = batches[:limit]

    events = [
        EventOut(
            event_type=et,
            id=r.id,
            sensor_id=r.sensor_id,
            workload_id=r.workload_id,
            action=r.action,
            kind=r.kind,
            protocol=r.protocol,
            dst_ip=r.dst_ip,
            dst_port=r.dst_port,
            dst_name=r.dst_name,
            comm=r.comm,
            cgroup=r.cgroup,
            isolated=bool(r.isolated),
            count=r.count,
            created_at=r.created_at,
        )
        for et, r in page
    ]

    next_cursor = None
    if has_more and page:
        last_et, last_row = page[-1]
        next_cursor = _encode_cursor(last_et, last_row.id, last_row.created_at)

    return EventList(events=events, next_cursor=next_cursor)

@admin_router.post(
    "/workloads",
    response_model=WorkloadOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_workload(
    data: WorkloadIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    exists = await db.execute(
        select(EgressWorkload.id).where(
            EgressWorkload.org_id == current_user.org_id,
            EgressWorkload.name == data.name,
            EgressWorkload.deleted_at.is_(None),
        )
    )
    if exists.scalar_one_or_none() is not None:
        raise api_error(status.HTTP_409_CONFLICT, "egress_workload.name_taken", name=data.name)

    payload = data.model_dump()
    payload["org_id"] = current_user.org_id
    payload["created_by"] = current_user.id
    payload["egress_allow"] = [r.model_dump(exclude_none=True) for r in data.egress_allow]
    payload["ingress_allow"] = [r.model_dump(exclude_none=True) for r in data.ingress_allow]

    w = EgressWorkload(**payload)
    db.add(w)
    await db.flush()
    await svc.bump_revision(db, current_user.org_id)

    await AuditService(db).log(
        current_user.org_id, current_user.id, "egress_workload", w.id, "created",
        {"name": w.name, "mode": w.mode, "dns": w.dns,
         "cgroup_patterns": w.cgroup_patterns, "run_as_users": w.run_as_users,
         "egress_allow": w.egress_allow, "ingress_allow": w.ingress_allow},
    )
    await db.refresh(w)
    return w


@admin_router.get("/workloads", response_model=list[WorkloadOut])
async def list_workloads(
    include_deleted: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    q = select(EgressWorkload).where(EgressWorkload.org_id == current_user.org_id)
    if not include_deleted:
        q = q.where(EgressWorkload.deleted_at.is_(None))
    q = q.order_by(EgressWorkload.id.asc())
    result = await db.execute(q)
    return list(result.scalars().all())


@admin_router.get("/workloads/{workload_id}", response_model=WorkloadOut)
async def get_workload(
    workload_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    return await _get_org_workload(db, workload_id, current_user.org_id)


@admin_router.patch("/workloads/{workload_id}", response_model=WorkloadOut)
async def update_workload(
    workload_id: int,
    data: WorkloadUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    w = await _get_org_workload(db, workload_id, current_user.org_id)
    fields = data.model_dump(exclude_unset=True)

    if "name" in fields and fields["name"] != w.name:
        clash = await db.execute(
            select(EgressWorkload.id).where(
                EgressWorkload.org_id == current_user.org_id,
                EgressWorkload.name == fields["name"],
                EgressWorkload.id != w.id,
                EgressWorkload.deleted_at.is_(None),
            )
        )
        if clash.scalar_one_or_none() is not None:
            raise api_error(status.HTTP_409_CONFLICT, "egress_workload.name_taken", name=fields["name"])

    for allow_field in ("egress_allow", "ingress_allow"):
        if allow_field in fields and fields[allow_field] is not None:
            fields[allow_field] = [
                r.model_dump(exclude_none=True) if hasattr(r, "model_dump") else r
                for r in fields[allow_field]
            ]

    changes: dict = {}
    for k, v in fields.items():
        changes[k] = {"from": getattr(w, k), "to": v}
    for k, v in fields.items():
        setattr(w, k, v)

    await svc.bump_revision(db, current_user.org_id)
    await db.flush()

    await AuditService(db).log(
        current_user.org_id, current_user.id, "egress_workload", w.id, "updated",
        {"changes": changes},
    )
    await db.refresh(w)
    return w


@admin_router.delete("/workloads/{workload_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_workload(
    workload_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    w = await _get_org_workload(db, workload_id, current_user.org_id)
    w.deleted_at = svc.now_utc()
    w.enabled = False
    await svc.bump_revision(db, current_user.org_id)
    await db.flush()

    await AuditService(db).log(
        current_user.org_id, current_user.id, "egress_workload", w.id, "deleted",
        {"name": w.name},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@admin_router.get("/policy", summary="The policy the sensors of this org receive")
async def preview_policy(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    pol = await svc.build_policy(db, current_user.org_id)
    return pol.model_dump(by_alias=True, exclude_none=True)


@admin_router.get("/violations", response_model=list[ViolationOut])
async def list_all_violations(
    workload_id: Optional[int] = Query(None),
    action: Optional[str] = Query(None),
    sensor_id: Optional[int] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """All violations of this organization, newest first. Filters match the
    old /runtime/violations endpoint so the UI can move over without changing
    its shape."""
    q = select(EgressViolation).where(EgressViolation.org_id == current_user.org_id)
    if workload_id is not None:
        q = q.where(EgressViolation.workload_id == workload_id)
    if sensor_id is not None:
        q = q.where(EgressViolation.sensor_id == sensor_id)
    if action:
        q = q.where(EgressViolation.action == action)
    q = q.order_by(EgressViolation.created_at.desc()).limit(limit)
    return list((await db.execute(q)).scalars().all())


@admin_router.get(
    "/settings",
    response_model=PolicySettingsOut,
    summary="The organization's policy settings (created with defaults on first read)",
)
async def get_settings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    row = await svc.settings_for(db, current_user.org_id)
    await db.commit()
    await db.refresh(row)
    return row


@admin_router.patch(
    "/settings",
    response_model=PolicySettingsOut,
    summary="Update the organization's policy settings",
)
async def patch_settings(
    data: PolicySettingsUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    before = await svc.settings_for(db, current_user.org_id)
    changes: dict = {}
    fields = data.model_dump(exclude_unset=True)
    for k, v in fields.items():
        old = getattr(before, k)
        if old != v:
            changes[k] = {"from": old, "to": v}

    row = await svc.update_settings(db, current_user.org_id, current_user.id, data)

    if not changes:
        await db.commit()
        await db.refresh(row)
        return row

    # Settings are part of the policy the sensors fetch (refresh_seconds
    # and heartbeat_seconds appear in it verbatim). Bump the revision so
    # the version they compare against If-None-Match changes, and they
    # refetch on the next poll instead of getting a 304 and keeping the
    # old intervals. default_mode/default_dns do not appear in the policy,
    # but the extra bump is cheap and keeps the rule simple: any settings
    # change makes sensors look again.
    await svc.bump_revision(db, current_user.org_id)

    await AuditService(db).log(
        current_user.org_id, current_user.id, "egress_policy_settings",
        current_user.org_id, "updated", {"changes": changes},
    )

    await db.refresh(row)
    return row


# ---- signing key rotation (admin)

@admin_router.get(
    "/settings/signing-key",
    response_model=SigningKeyOut,
    summary="The organization's command signing key (public half) and its status",
)
async def get_org_signing_key(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    key = await cmd_svc.signing_key_for(db, current_user.org_id, current_user.id)
    await db.commit()
    return SigningKeyOut(
        public_key=key.public_key,
        fingerprint=key.fingerprint,
        sensor_id=0,  # admin view; not for a specific sensor
        previous_public_key=key.previous_public_key,
        previous_fingerprint=key.previous_fingerprint,
        previous_valid_until=key.previous_valid_until,
    )


@admin_router.post(
    "/settings/signing-key/rotate",
    response_model=SigningKeyRotationOut,
    summary="Generate a new command signing key and hand it to every sensor",
)
async def rotate_org_signing_key(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """A new key replaces the current one for everything signed from now
    on, and one update-signing-key command per enabled sensor is queued.
    Each is signed with the OLD key, which every sensor already trusts.

    Sensors pick the new key up on their next heartbeat; until they do,
    any other command issued in that window may fail verification on a
    sensor that has not updated yet. Wait one refresh_seconds before
    issuing unrelated commands.
    """
    key, count = await cmd_svc.rotate_signing_key(db, current_user.org_id, current_user.id)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "egress_sensor_signing_key",
        current_user.org_id, "rotated",
        {
            "fingerprint": key.fingerprint,
            "previous_fingerprint": key.previous_fingerprint,
            "sensors_notified": count,
            "previous_valid_until": key.previous_valid_until.isoformat()
                if key.previous_valid_until else None,
        },
    )
    await db.refresh(key)
    return SigningKeyRotationOut(
        fingerprint=key.fingerprint,
        previous_fingerprint=key.previous_fingerprint,
        previous_valid_until=key.previous_valid_until,
        sensors_notified=count,
        rotated_at=key.rotated_at,
    )


@admin_router.post(
    "/settings/signing-key/finalize",
    response_model=SigningKeyRotationOut,
    summary="Drop the previous key once its grace period has passed",
)
async def finalize_org_signing_key(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """After this, commands signed by the old key no longer verify on any
    sensor. Do it once every sensor has had time to receive the update
    (the default grace is 24 hours, shown in the rotation response)."""
    removed = await cmd_svc.finalize_rotation(db, current_user.org_id)
    key = await cmd_svc.signing_key_for(db, current_user.org_id, current_user.id)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "egress_sensor_signing_key",
        current_user.org_id, "finalized",
        {"fingerprint": key.fingerprint, "previous_removed": removed},
    )
    await db.commit()
    await db.refresh(key)
    return SigningKeyRotationOut(
        fingerprint=key.fingerprint,
        sensors_notified=0,
        rotated_at=key.rotated_at,
    )


# ---- commands (admin)

@admin_router.post(
    "/sensors/{sensor_id}/commands",
    response_model=CommandOut,
    status_code=status.HTTP_201_CREATED,
    summary="Queue a command for one sensor (delivered on its next heartbeat)",
)
async def create_sensor_command(
    sensor_id: int,
    data: CommandIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    sensor = await _get_org_sensor(db, sensor_id, current_user.org_id, include_revoked=True)
    try:
        row = await cmd_svc.create_command(db, sensor, data.kind, current_user.id)
    except cmd_svc.UnknownKind as e:
        raise api_error(status.HTTP_422_UNPROCESSABLE_CONTENT, e.code, **e.context)

    await AuditService(db).log(
        current_user.org_id, current_user.id, "egress_sensor_command", row.id, "issued",
        {
            "sensor_id": sensor.id,
            "sensor_name": sensor.name,
            "kind": row.kind,
            "expires_at": row.expires_at.isoformat(),
        },
    )
    await db.refresh(row)
    return row


@admin_router.get(
    "/sensors/{sensor_id}/commands",
    response_model=list[CommandOut],
    summary="The command history for one sensor, newest first",
)
async def list_sensor_commands(
    sensor_id: int,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    await _get_org_sensor(db, sensor_id, current_user.org_id, include_revoked=True)
    rows = (await db.execute(
        select(EgressSensorCommand)
        .where(
            EgressSensorCommand.sensor_id == sensor_id,
            EgressSensorCommand.org_id == current_user.org_id,
        )
        .order_by(EgressSensorCommand.id.desc())
        .limit(limit)
    )).scalars().all()
    return list(rows)


# ---------------------------------------------------------------- sensor

sensor_router = APIRouter()


async def get_current_sensor(
    x_sensor_key: Optional[str] = Header(None, alias="X-Sensor-Key"),
    db: AsyncSession = Depends(get_db),
) -> EgressSensor:
    """Authenticate a sensor by X-Sensor-Key. A revoked or disabled sensor is
    refused with 401; the daemon treats that as "keep what you have" and
    retries later."""
    if not x_sensor_key:
        raise api_error(status.HTTP_401_UNAUTHORIZED, "egress_sensor.no_key")
    sensor = await svc.find_sensor_by_key(db, x_sensor_key)
    if sensor is None or sensor.revoked_at is not None or not sensor.enabled:
        raise api_error(status.HTTP_401_UNAUTHORIZED, "egress_sensor.bad_key")
    return sensor


@sensor_router.get(
    "/config",
    summary="Fetch the policy (ETag aware: 304 means nothing changed)",
)
async def get_config(
    request: Request,
    db: AsyncSession = Depends(get_db),
    sensor: EgressSensor = Depends(get_current_sensor),
):
    etag = (request.headers.get("if-none-match") or "").strip().strip('"')

    # Cheap path: answer from the revision alone when nothing has changed.
    current = await svc.policy_version(db, sensor.org_id)
    if etag and etag == current:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)

    pol = await svc.build_policy(db, sensor.org_id)
    body = pol.model_dump(by_alias=True, exclude_none=True)
    return JSONResponse(body, headers={"ETag": svc.policy_etag(pol.version)})


@sensor_router.post(
    "/heartbeat",
    response_model=HeartbeatResponseOut,
    status_code=status.HTTP_200_OK,
    summary="Sensor reports itself; the response carries any queued commands",
)
async def post_heartbeat(
    data: HeartbeatIn,
    db: AsyncSession = Depends(get_db),
    sensor: EgressSensor = Depends(get_current_sensor),
):
    """The sensor reports its state on every heartbeat and, in the same
    round trip, receives whatever commands are queued for it. An empty
    commands list is the normal case.

    A sensor older than the command feature will see 200 instead of 204
    and ignore the body; nothing about heartbeat ingestion changes."""
    await svc.ingest_heartbeat(db, sensor, data)

    pending = await cmd_svc.pending_for_sensor(db, sensor.id)
    out: list[CommandForSensor] = []
    delivered_ids: list[int] = []
    for row in pending:
        out.append(CommandForSensor(
            id=row.id,
            kind=row.kind,
            payload=row.payload,
            signature=row.signature,
            expires_at=row.expires_at,
        ))
        delivered_ids.append(row.id)
    if delivered_ids:
        await cmd_svc.mark_delivered(db, delivered_ids)

    await db.commit()
    return HeartbeatResponseOut(commands=out)


@sensor_router.post(
    "/commands/{command_id}/ack",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="The sensor acknowledges a command it was given",
)
async def ack_command(
    command_id: int,
    data: CommandAckIn,
    db: AsyncSession = Depends(get_db),
    sensor: EgressSensor = Depends(get_current_sensor),
):
    """The sensor calls this after it has verified the command signature
    and (for detach) before it uninstalls, so the ack is recorded even
    though the daemon is about to exit."""
    try:
        await cmd_svc.ack_command(db, sensor.id, command_id, data.status, data.result, data.error)
    except cmd_svc.NotFound as e:
        raise api_error(status.HTTP_404_NOT_FOUND, e.code, **e.context)
    except cmd_svc.CommandError as e:
        raise api_error(status.HTTP_422_UNPROCESSABLE_CONTENT, e.code, **e.context)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@sensor_router.get(
    "/signing-key",
    response_model=SigningKeyOut,
    summary="The public key a sensor uses to verify queued commands",
)
async def get_signing_key(
    db: AsyncSession = Depends(get_db),
    sensor: EgressSensor = Depends(get_current_sensor),
):
    """The sensor caches this key on disk; it can then verify a command
    even when the control plane is unreachable. Only enrolled sensors get
    it (the same X-Sensor-Key check as every other call)."""
    key = await cmd_svc.signing_key_for(db, sensor.org_id)
    await db.commit()
    return SigningKeyOut(
        public_key=key.public_key,
        fingerprint=key.fingerprint,
        sensor_id=sensor.id,
        previous_public_key=key.previous_public_key,
        previous_fingerprint=key.previous_fingerprint,
        previous_valid_until=key.previous_valid_until,
    )


@sensor_router.post(
    "/violations",
    status_code=status.HTTP_200_OK,
    summary="A batch of violation events (up to 500 per call)",
)
async def post_violations(
    data: ViolationsBatch,
    db: AsyncSession = Depends(get_db),
    sensor: EgressSensor = Depends(get_current_sensor),
):
    """Ingest a batch. Events whose workload_id is not this organization's
    are dropped (the workload was likely deleted since the sensor's last
    config fetch); they are counted in the response so the sensor can log
    them. Incidents and notifications are created for alerted/blocked events
    on agent-linked workloads only."""
    dropped = await svc.ingest_violations(db, sensor, data.events)
    await db.commit()
    return {"accepted": len(data.events) - dropped, "dropped": dropped}


@sensor_router.post(
    "/activity",
    status_code=status.HTTP_200_OK,
    summary="A batch of sampled allowed connections (up to 500 per call)",
)
async def post_activity(
    data: ActivityBatch,
    db: AsyncSession = Depends(get_db),
    sensor: EgressSensor = Depends(get_current_sensor),
):
    """Ingest a batch of sampled allowed connects. Same shape as /violations
    but a distinct feed: rows land in sensor_activity, no incidents or
    notifications are created."""
    dropped = await svc.ingest_activities(db, sensor, data.events)
    await db.commit()
    return {"accepted": len(data.events) - dropped, "dropped": dropped}
