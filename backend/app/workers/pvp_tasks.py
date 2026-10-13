"""Seal recorded agent actions into the signed audit log (app/pvp/seal.py)."""

import asyncio

from app.core.celery_app import celery_app
from app.core.celery_database import CelerySessionLocal


async def _run() -> dict:
    from app.pvp.seal import seal_all

    async with CelerySessionLocal() as db:
        return await seal_all(db)


@celery_app.task(name="pvp.seal_actions", ignore_result=True, expires=55)
def seal_actions_task() -> dict:
    return asyncio.run(_run())


async def _prune() -> int:
    """Nonces of signed action requests outlive their freshness window by far:
    a request older than that is refused anyway, so its nonce can go."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import delete

    from app.models.delegation import ActionNonce

    async with CelerySessionLocal() as db:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
        result = await db.execute(delete(ActionNonce).where(ActionNonce.created_at < cutoff))
        await db.commit()
        return result.rowcount or 0


@celery_app.task(name="pvp.prune_nonces", ignore_result=True, expires=600)
def prune_nonces_task() -> int:
    return asyncio.run(_prune())
