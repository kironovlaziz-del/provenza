"""
Celery task for the telemetry ingestion pipeline.

TelemetryService.ingest_events does real per-event work (domain
classification, sighting/incident creation, notification dispatch) -
for a full 500-event batch that adds up to more than an HTTP handler
should block on. Handing it to a worker means POST /shadow-ai/ingest
returns 202 immediately; the agent/extension don't wait for or poll the
result, so processing failures are surfaced only in this worker's own
logs and via whatever sightings/incidents do or don't show up - not
back to the caller.
"""

import asyncio
from typing import Any, Dict, List

from app.core.celery_app import celery_app
from app.core.celery_database import CelerySessionLocal
from app.schemas.telemetry import TelemetryEventIn
from app.services.telemetry_service import TelemetryService


async def _process_telemetry_batch_async(
    org_id: int, ingestion_source_id: int, raw_events: List[Dict[str, Any]]
) -> Dict[str, Any]:
    # raw_events were produced by TelemetryEventIn.model_dump(mode="json")
    # at the API layer (so they survive Celery's JSON transport) -
    # re-validating here reconstructs real datetime objects etc. from
    # that JSON-safe form, exactly as if this were the original request.
    events = [TelemetryEventIn.model_validate(e) for e in raw_events]
    async with CelerySessionLocal() as db:
        service = TelemetryService(db)
        result = await service.ingest_events(org_id, ingestion_source_id, events)
        return result.model_dump()


@celery_app.task(name="telemetry.process_batch")
def process_telemetry_batch(
    org_id: int, ingestion_source_id: int, raw_events: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Celery wrapper around the async TelemetryService.ingest_events.
    Celery's prefork pool has no running event loop, so a fresh one is
    started per task invocation - same pattern as retention_tasks.py.

    Returns the same breakdown TelemetryIngestResponse would have, as a
    plain dict (Celery's result backend is configured for JSON) - not
    delivered to the original caller (which already got its 202), but
    available via the task_id for anyone who wants to check afterwards.
    """
    return asyncio.run(
        _process_telemetry_batch_async(org_id, ingestion_source_id, raw_events)
    )
