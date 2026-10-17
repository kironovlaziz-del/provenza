# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza - https://github.com/kironovlaziz-del/provenza

"""Background jobs for the egress sensor."""

import asyncio

from app.core.celery_app import celery_app
from app.core.celery_database import CelerySessionLocal


async def _warn_offline() -> int:
    from app.services import egress_sensor as svc
    async with CelerySessionLocal() as db:
        try:
            return await svc.warn_offline_sensors(db)
        finally:
            await db.commit()


@celery_app.task(name="egress_sensor.warn_offline", ignore_result=True, expires=300)
def warn_offline_task() -> int:
    return asyncio.run(_warn_offline())

async def _prune_activity() -> int:
    from app.services import egress_sensor as svc
    async with CelerySessionLocal() as db:
        try:
            return await svc.prune_sensor_activity(db)
        finally:
            await db.commit()


@celery_app.task(name="egress_sensor.prune_activity", ignore_result=True, expires=3500)
def prune_activity_task() -> int:
    return asyncio.run(_prune_activity())

async def _prune_violations() -> int:
    from app.services import egress_sensor as svc
    async with CelerySessionLocal() as db:
        try:
            return await svc.prune_violations(db)
        finally:
            await db.commit()


@celery_app.task(name="egress_sensor.prune_violations", ignore_result=True, expires=3500)
def prune_violations_task() -> int:
    return asyncio.run(_prune_violations())

