# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Business logic for the egress sensor API.

Nothing here touches the request/response cycle: it takes a session and
returns plain data, so it can be reused from background jobs (a future
"push policy to sensors" worker) without dragging FastAPI into it.

Three things live here:

  * API key generation and lookup — the sensor key is pvz_sensor_... with
    the same hashing scheme as everything else (SHA-256 hex). The plaintext
    is returned once at registration and never stored.
  * Policy assembly — build_policy() turns the active workloads of an
    organization into the exact document sensor/internal/config/policy.go
    expects. The revision is what the sensor echoes in If-None-Match; it
    moves every time a workload changes, so a poll that finds nothing new
    can be answered with 304 without assembling anything.
  * Revision bumping — every mutating operation on a workload calls
    bump_revision(); nothing else should write EgressPolicyRevision.
"""

import secrets
from datetime import datetime, timezone
from typing import Any, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_api_key
from app.models.egress_sensor import (
    EgressPolicyRevision,
    EgressSensor,
    EgressWorkload,
)
from app.schemas.egress_sensor import PolicyAllow, PolicyOut, PolicyWorkload

SENSOR_KEY_PREFIX = "pvz_sensor_"
# How much of the key is shown in the UI so two keys can be told apart.
# The full key is 11 + 32 = 43 chars; the prefix we keep is 11 + 8 = 19.
KEY_DISPLAY_LEN = 19


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
    Their order is the id order: the sensor assigns each workload an
    index that positions its per-workload DNS proxy port, so a stable
    order keeps a sensor's ports stable across polls.
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
