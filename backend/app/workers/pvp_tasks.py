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
