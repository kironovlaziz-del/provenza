# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""OpenTelemetry export of PVP decisions (app/services/otel_export.py)."""

import asyncio

from app.core.celery_app import celery_app
from app.core.celery_database import CelerySessionLocal


async def _export() -> dict:
    from app.services import otel_export

    async with CelerySessionLocal() as db:
        return await otel_export.export_all(db)


@celery_app.task(name="otel.export", ignore_result=True, expires=25)
def export_task() -> dict:
    """What is new for every organization with the export switched on."""
    return asyncio.run(_export())
