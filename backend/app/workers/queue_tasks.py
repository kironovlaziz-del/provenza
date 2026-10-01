"""
Beat task: enforce the request pipeline's time limits (see
app/services/queue_ttl.py). Same asyncio.run + CelerySessionLocal pattern as
request_tasks.py.
"""

import asyncio

from app.core.celery_app import celery_app
from app.core.celery_database import CelerySessionLocal


async def _sweep() -> dict:
    from app.services.queue_ttl import sweep_all
    async with CelerySessionLocal() as db:
        return {str(k): v for k, v in (await sweep_all(db)).items()}


@celery_app.task(name="requests.sweep")
def sweep_requests_task() -> dict:
    return asyncio.run(_sweep())
