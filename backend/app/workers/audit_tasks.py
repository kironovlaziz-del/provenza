"""Signed checkpoints of the audit log (docs/audit-proofs.md)."""

import asyncio
import logging

from app.core.celery_app import celery_app
from app.core.celery_database import CelerySessionLocal

log = logging.getLogger(__name__)


async def _run() -> dict:
    from app.services import audit_keys, audit_proofs

    signed, failed = 0, 0
    async with CelerySessionLocal() as db:
        orgs = await audit_proofs.stale_orgs(db)
        await db.rollback()
        for org_id in orgs:
            try:
                await audit_proofs.checkpoint(db, org_id)
                signed += 1
            except Exception:  # noqa: BLE001 - one organization must not stop the others
                await db.rollback()
                failed += 1
                log.exception("audit checkpoint failed for org %s", org_id)
        # key changes whose notice period is over and that have their quorum
        rotations = await audit_keys.complete_due(db)
    return {"signed": signed, "failed": failed, **rotations}


@celery_app.task(name="audit.checkpoint", ignore_result=True, expires=240)
def checkpoint_task() -> dict:
    return asyncio.run(_run())
