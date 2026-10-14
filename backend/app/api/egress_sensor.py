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

from fastapi import APIRouter, Depends, Header, Query, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.core.errors import api_error
from app.models.egress_sensor import (
    EgressSensor,
    EgressViolation,
    EgressWorkload,
)
from app.models.user import User, UserRole
from app.schemas.egress_sensor import (
    HeartbeatIn,
    SensorCreated,
    SensorOut,
    SensorRegister,
    SensorUpdate,
    ViolationOut,
    ViolationsBatch,
    WorkloadIn,
    WorkloadOut,
    WorkloadUpdate,
)
from app.services import egress_sensor as svc

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
    await db.commit()
    await db.refresh(sensor)

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
    for k, v in fields.items():
        setattr(sensor, k, v)
    await db.commit()
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
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


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
    await db.commit()
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

    for k, v in fields.items():
        setattr(w, k, v)

    await svc.bump_revision(db, current_user.org_id)
    await db.commit()
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
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@admin_router.get("/policy", summary="The policy the sensors of this org receive")
async def preview_policy(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    pol = await svc.build_policy(db, current_user.org_id)
    return pol.model_dump(by_alias=True, exclude_none=True)


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
    current_rev = await svc.revision_for(db, sensor.org_id)
    if etag and etag == str(current_rev):
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)

    pol = await svc.build_policy(db, sensor.org_id)
    body = pol.model_dump(by_alias=True, exclude_none=True)
    return JSONResponse(body, headers={"ETag": svc.policy_etag(pol.version)})


@sensor_router.post(
    "/heartbeat",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Sensor reports itself: hostname, version, attached hooks, warnings",
)
async def post_heartbeat(
    data: HeartbeatIn,
    db: AsyncSession = Depends(get_db),
    sensor: EgressSensor = Depends(get_current_sensor),
):
    sensor.hostname = data.hostname
    sensor.version = data.version
    sensor.kernel = data.kernel
    sensor.enforcing = data.enforcing
    sensor.hooks = list(data.hooks)
    sensor.warnings = list(data.warnings)
    sensor.errors = list(data.errors)
    sensor.dropped_events = data.dropped_events
    sensor.config_version = data.config_version
    sensor.last_seen_at = svc.now_utc()
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@sensor_router.post(
    "/violations",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="A batch of violation events (up to 500 per call)",
)
async def post_violations(
    data: ViolationsBatch,
    db: AsyncSession = Depends(get_db),
    sensor: EgressSensor = Depends(get_current_sensor),
):
    if not data.events:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    rows = [
        EgressViolation(
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
        for e in data.events
    ]
    db.add_all(rows)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
