# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Retention of agent telemetry, per organization.

  settings  how long policy checks and the content agents sent and got back
            are kept (None: indefinitely); the defaults keep 90 days.
  run       a beat task every 5 minutes, and an admin's "run now": the
            purge itself is services/telemetry_retention.py. A run that
            changed something, or was started by hand, is recorded.
"""

from datetime import datetime, timezone
from typing import Dict

from sqlalchemy import null, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.retention import RetentionRun, RetentionSettings

DEFAULTS = {"agent_check_retention_days": 90, "agent_content_retention_days": 90}


async def org_settings(db: AsyncSession, org_id: int) -> dict:
    row = (await db.execute(select(RetentionSettings).where(RetentionSettings.org_id == org_id))).scalar_one_or_none()
    if not row:
        return {**DEFAULTS, "source": "default"}
    return {k: getattr(row, k) for k in DEFAULTS} | {"source": "org"}


async def save_settings(db: AsyncSession, org_id: int, values: dict, user_id: int) -> tuple:
    row = (await db.execute(select(RetentionSettings).where(RetentionSettings.org_id == org_id))).scalar_one_or_none()
    before = None if row is None else {k: getattr(row, k) for k in DEFAULTS}
    if row is None:
        row = RetentionSettings(org_id=org_id)
        db.add(row)
    after = {}
    for k in DEFAULTS:
        if k in values:
            after[k] = values[k]
        else:  # not sent: unchanged, or the default for a new row
            after[k] = before[k] if before is not None else DEFAULTS[k]
        # null(): a plain None on a new row would let the server default (90) win
        setattr(row, k, after[k] if after[k] is not None else null())
    row.updated_by = user_id
    await db.commit()
    return before, after


async def run_org(db: AsyncSession, org_id: int, trigger: str = "beat") -> Dict[str, int]:
    from app.services.telemetry_retention import purge

    cfg = await org_settings(db, org_id)
    counts = await purge(db, org_id, datetime.now(timezone.utc), cfg["agent_check_retention_days"],
                         cfg["agent_content_retention_days"])
    if trigger == "manual" or any(counts.values()):
        db.add(RetentionRun(org_id=org_id, trigger=trigger, **counts))
    await db.commit()
    return counts


async def run_all(db: AsyncSession) -> Dict[int, Dict[str, int]]:
    """Every organization with agents: only agents leave telemetry behind."""
    from app.models.agent import Agent

    org_ids = (await db.execute(select(Agent.org_id).distinct())).scalars().all()
    return {oid: await run_org(db, oid) for oid in sorted(set(org_ids))}


async def overview(db: AsyncSession, org_id: int) -> dict:
    runs = (await db.execute(
        select(RetentionRun).where(RetentionRun.org_id == org_id)
        .order_by(RetentionRun.ran_at.desc(), RetentionRun.id.desc()).limit(50)
    )).scalars().all()
    return {
        "settings": await org_settings(db, org_id),
        "runs": [{"id": r.id, "ran_at": r.ran_at, "trigger": r.trigger, "purged_checks": r.purged_checks,
                  "scrubbed_content": r.scrubbed_content} for r in runs],
    }
