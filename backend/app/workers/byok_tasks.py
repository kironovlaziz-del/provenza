"""Re-encryption of a large organization after enabling / rotating / disabling BYOK."""

import asyncio

from app.core.celery_app import celery_app
from app.core.celery_database import CelerySessionLocal


async def _run(job_id: int) -> dict:
    from app.services.byok_service import ByokService
    async with CelerySessionLocal() as db:
        job = await ByokService(db).reencrypt(job_id)
        return {"job_id": job.id, "status": job.status, "done": job.done, "failed": job.failed}


@celery_app.task(name="byok.reencrypt")
def reencrypt_task(job_id: int) -> dict:
    return asyncio.run(_run(job_id))
