# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza - https://github.com/kironovlaziz-del/provenza

"""Background jobs for the egress sensor command queue."""

import asyncio

from app.core.celery_app import celery_app
from app.core.database import AsyncSessionLocal


async def _expire() -> int:
    from app.services import egress_sensor_commands as cmd
    async with AsyncSessionLocal() as db:
        try:
            n = await cmd.expire_old_commands(db)
            await db.commit()
            return n
        except Exception:
            await db.rollback()
            raise


@celery_app.task(name="egress_sensor.expire_commands", ignore_result=True, expires=300)
def expire_commands_task() -> int:
    return asyncio.run(_expire())
