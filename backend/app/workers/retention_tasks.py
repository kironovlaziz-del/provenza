"""
Beat task: retention of agent telemetry (app/services/retention.py). Same
asyncio.run + CelerySessionLocal pattern as telemetry_tasks.py.
"""

import asyncio

from app.core.celery_app import celery_app
from app.core.celery_database import CelerySessionLocal


async def _run() -> dict:
    from app.services.retention import run_all
    async with CelerySessionLocal() as db:
        return {str(k): v for k, v in (await run_all(db)).items()}


@celery_app.task(name="retention.run")
def retention_task() -> dict:
    return asyncio.run(_run())
