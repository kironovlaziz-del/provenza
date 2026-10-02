# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Time limits for the asynchronous request pipeline.

  enqueue   every "request.process" task is sent with Celery `expires`
            (the organization's queue TTL) and the request records when it
            was queued (enqueued_at) - on creation, or on approval.

  claim     the worker atomically moves the request pending/approved ->
            processing (row lock) before calling the provider. A task
            delivered twice (task_acks_late redelivery after a worker crash)
            finds "processing" / "completed" and does nothing, so a provider
            is never called twice for one request. A task that starts after
            the queue TTL marks the request "expired" instead of running.

  sweep     a beat task every 5 minutes, per organization:
              queued (pending / approved) past the queue TTL   -> expired
              pending_approval past the approval TTL            -> expired
              processing far past any task limit (worker lost)  -> failed
              encrypted raw prompts past retention_expires_at or the
              organization's retention period                   -> wiped
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_request import AIRequest
from app.models.queue_ttl import QueueSettings, QueueSweep

DEFAULTS = {"queue_ttl_seconds": 900, "approval_ttl_hours": 72, "raw_prompt_retention_days": None,
            "agent_check_retention_days": 90, "agent_content_retention_days": 90}
QUEUED = ("pending", "approved")
# Celery hard time limit (celery_app.task_time_limit) + margin: past this a
# "processing" request has no live worker any more
STUCK_AFTER = timedelta(seconds=3900 + 300)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def org_settings(db: AsyncSession, org_id: int) -> dict:
    row = (await db.execute(select(QueueSettings).where(QueueSettings.org_id == org_id))).scalar_one_or_none()
    if not row:
        return {**DEFAULTS, "source": "default"}
    return {k: getattr(row, k) for k in DEFAULTS} | {"source": "org"}


async def save_settings(db: AsyncSession, org_id: int, values: dict, user_id: int) -> tuple:
    row = (await db.execute(select(QueueSettings).where(QueueSettings.org_id == org_id))).scalar_one_or_none()
    before = None if row is None else {k: getattr(row, k) for k in DEFAULTS}
    if row is None:
        row = QueueSettings(org_id=org_id)
        db.add(row)
    for k in DEFAULTS:
        if k in values:
            setattr(row, k, values[k])
        elif before is None:  # a new row: keys not sent take their defaults
            setattr(row, k, DEFAULTS[k])
    row.updated_by = user_id
    after = {k: getattr(row, k) for k in DEFAULTS}
    await db.commit()
    return before, after


# ---------------------------------------------------------------------- enqueue / claim
async def enqueue_request(db: AsyncSession, request: AIRequest, org_id: int) -> None:
    """Replaces the bare send_task("request.process") calls."""
    from app.core.celery_app import celery_app

    cfg = await org_settings(db, org_id)
    request_id = request.id
    request.enqueued_at = datetime.now(timezone.utc)
    await db.commit()
    celery_app.send_task("request.process", args=[request_id, org_id], expires=cfg["queue_ttl_seconds"])


async def claim_for_processing(db: AsyncSession, request_id: int, org_id: int) -> bool:
    """True if this worker may call the provider for the request."""
    req = (await db.execute(
        select(AIRequest).where(AIRequest.id == request_id, AIRequest.org_id == org_id).with_for_update()
    )).scalar_one_or_none()
    if req is None or req.status not in QUEUED:
        await db.rollback()
        return False
    cfg = await org_settings(db, org_id)
    queued_at = _aware(req.enqueued_at) or _aware(req.created_at)
    if queued_at is not None and datetime.now(timezone.utc) - queued_at > timedelta(seconds=cfg["queue_ttl_seconds"]):
        req.status = "expired"
        req.error_message = f"Not processed within the queue TTL ({cfg['queue_ttl_seconds']}s); not sent to the provider."
        await db.commit()
        return False
    req.status = "processing"
    await db.commit()
    return True


# ---------------------------------------------------------------------- sweep
async def sweep_org(db: AsyncSession, org_id: int, trigger: str = "beat") -> Dict[str, int]:
    cfg = await org_settings(db, org_id)
    now = datetime.now(timezone.utc)
    queued_at = func.coalesce(AIRequest.enqueued_at, AIRequest.created_at)

    r1 = await db.execute(
        update(AIRequest)
        .where(AIRequest.org_id == org_id, AIRequest.status.in_(QUEUED),
               queued_at < now - timedelta(seconds=cfg["queue_ttl_seconds"]))
        .values(status="expired",
                error_message=f"Not processed within the queue TTL ({cfg['queue_ttl_seconds']}s).")
        .execution_options(synchronize_session=False)
    )
    r2 = await db.execute(
        update(AIRequest)
        .where(AIRequest.org_id == org_id, AIRequest.status == "pending_approval",
               AIRequest.created_at < now - timedelta(hours=cfg["approval_ttl_hours"]))
        .values(status="expired",
                error_message=f"No approval decision within {cfg['approval_ttl_hours']}h.")
        .execution_options(synchronize_session=False)
    )
    r3 = await db.execute(
        update(AIRequest)
        .where(AIRequest.org_id == org_id, AIRequest.status == "processing",
               queued_at < now - timedelta(seconds=cfg["queue_ttl_seconds"]) - STUCK_AFTER)
        .values(status="failed", error_message="The worker processing this request was lost.")
        .execution_options(synchronize_session=False)
    )
    purge_cond = [AIRequest.retention_expires_at < now]
    if cfg["raw_prompt_retention_days"]:
        purge_cond.append(AIRequest.created_at < now - timedelta(days=cfg["raw_prompt_retention_days"]))
    r4 = await db.execute(
        update(AIRequest)
        .where(AIRequest.org_id == org_id, AIRequest.input_text_encrypted.is_not(None), or_(*purge_cond))
        .values(input_text_encrypted=None)
        .execution_options(synchronize_session=False)
    )
    counts = {"expired_queued": r1.rowcount or 0, "expired_approvals": r2.rowcount or 0,
              "failed_stuck": r3.rowcount or 0, "purged_prompts": r4.rowcount or 0}
    from app.services.telemetry_retention import purge
    counts.update(await purge(db, org_id, now, cfg["agent_check_retention_days"], cfg["agent_content_retention_days"]))
    if trigger == "manual" or any(counts.values()):
        db.add(QueueSweep(org_id=org_id, trigger=trigger, **counts))
    await db.commit()
    return counts


async def sweep_all(db: AsyncSession) -> Dict[int, Dict[str, int]]:
    """Organizations that have anything a sweep could touch."""
    from app.models.agent import Agent
    agent_orgs = set((await db.execute(select(Agent.org_id).distinct())).scalars().all())
    org_ids = (await db.execute(
        select(AIRequest.org_id).where(or_(
            AIRequest.status.in_(QUEUED + ("pending_approval", "processing")),
            and_(AIRequest.input_text_encrypted.is_not(None),
                 or_(AIRequest.retention_expires_at.is_not(None),
                     AIRequest.org_id.in_(select(QueueSettings.org_id)
                                          .where(QueueSettings.raw_prompt_retention_days.is_not(None))))),
        )).distinct()
    )).scalars().all()
    return {oid: await sweep_org(db, oid) for oid in sorted(set(org_ids) | agent_orgs)}


# ---------------------------------------------------------------------- overview
async def overview(db: AsyncSession, org_id: int) -> dict:
    now = datetime.now(timezone.utc)
    queued_at = func.coalesce(AIRequest.enqueued_at, AIRequest.created_at)
    live = {}
    for st in ("pending", "approved", "processing", "pending_approval"):
        n, oldest = (await db.execute(
            select(func.count(), func.min(queued_at if st != "pending_approval" else AIRequest.created_at))
            .where(AIRequest.org_id == org_id, AIRequest.status == st)
        )).one()
        oldest = _aware(oldest)
        live[st] = {"count": n, "oldest_age_seconds": int((now - oldest).total_seconds()) if oldest else None}
    expired_7d = (await db.execute(
        select(func.count()).select_from(AIRequest)
        .where(AIRequest.org_id == org_id, AIRequest.status == "expired", AIRequest.created_at >= now - timedelta(days=7))
    )).scalar_one()
    raw_kept = (await db.execute(
        select(func.count()).select_from(AIRequest)
        .where(AIRequest.org_id == org_id, AIRequest.input_text_encrypted.is_not(None))
    )).scalar_one()
    sweeps = (await db.execute(
        select(QueueSweep).where(QueueSweep.org_id == org_id).order_by(QueueSweep.ran_at.desc(), QueueSweep.id.desc()).limit(50)
    )).scalars().all()
    return {
        "settings": await org_settings(db, org_id),
        "live": live,
        "expired_7d": expired_7d,
        "raw_prompts_kept": raw_kept,
        "sweeps": [{"id": s.id, "ran_at": s.ran_at, "trigger": s.trigger, "expired_queued": s.expired_queued,
                    "expired_approvals": s.expired_approvals, "failed_stuck": s.failed_stuck,
                    "purged_prompts": s.purged_prompts, "purged_checks": s.purged_checks,
                    "scrubbed_content": s.scrubbed_content} for s in sweeps],
    }
