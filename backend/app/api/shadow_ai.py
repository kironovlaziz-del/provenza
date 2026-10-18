import io
import os
import re
import zipfile

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional

from app.core import rate_limit
from app.core.config import settings
from app.core.errors import api_error
from app.core.database import get_db
from app.core.pagination import PaginationParams
from app.schemas.shadow_ai import (
    ShadowSightingCreate,
    ShadowSightingUpdate,
    ShadowSightingRegister,
    ShadowSightingOut,
)
from app.schemas.telemetry import (
    DOMAIN_EVENT_TYPE,
    TelemetryIngestAcceptedResponse,
    TelemetryIngestRequest,
)
from app.schemas.ingestion_source import IngestionSourceCreate
from app.schemas.pagination import Page
from app.services.shadow_ai_service import ShadowAIService
from app.services.ingestion_source_service import IngestionSourceService
from app.services.audit_service import AuditService
from app.services import notification_service
from app.workers.telemetry_tasks import process_telemetry_batch
from app.models.user import User, UserRole
from app.models.ingestion_source import IngestionSource
from app.api.deps import get_current_user, require_role, get_ingestion_source

router = APIRouter()


@router.post("/ingest", response_model=TelemetryIngestAcceptedResponse, status_code=202)
async def ingest_telemetry(
    request: Request,
    data: TelemetryIngestRequest,
    source: IngestionSource = Depends(get_ingestion_source),
):
    """
    Batch ingestion endpoint for external telemetry collectors (Go
    endpoint agent, browser extension). Authenticated via
    X-Ingestion-Key, not a user session - see get_ingestion_source.

    Hands the batch to a Celery worker and returns immediately: actual
    classification/sighting/incident creation happens asynchronously
    (see app/workers/telemetry_tasks.py) - the collector does not wait
    for or poll the result, so this only ever reports that the batch was
    accepted, not what came of it.
    """
    extension = source.source_type == "browser_extension"
    rate_limit.enforce(
        request, scope="ingest", extra_key=f"source-{source.id}", window_seconds=60,
        limit=settings.INGEST_EXTENSION_BATCHES_PER_MINUTE if extension else settings.INGEST_BATCHES_PER_MINUTE,
    )
    # an extension's key is public: it may report domain visits, nothing else
    if extension and any(e.event_type != DOMAIN_EVENT_TYPE for e in data.events):
        raise api_error(status.HTTP_403_FORBIDDEN, "ingestion.event_type_not_allowed")
    raw_events = [e.model_dump(mode="json") for e in data.events]
    task = process_telemetry_batch.delay(source.org_id, source.id, raw_events)
    return TelemetryIngestAcceptedResponse(
        status="accepted",
        received=len(data.events),
        task_id=task.id,
    )


@router.post("/", response_model=ShadowSightingOut)
async def create_sighting(
    data: ShadowSightingCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = ShadowAIService(db)
    sighting = await service.create_sighting(current_user.org_id, current_user.id, data)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "shadow_ai_sighting", sighting.id, "created",
        {"tool_name": sighting.tool_name, "detected_via": sighting.detected_via},
    )
    await notification_service.notify(
        db, current_user.org_id, "shadow_ai_reported",
        f"Unsanctioned AI usage detected: {sighting.tool_name}",
        f"Source: {sighting.detected_via}. Needs review in Shadow AI Monitor.",
        {"sighting_id": sighting.id},
    )
    return sighting


@router.get("/", response_model=Page[ShadowSightingOut])
async def list_sightings(
    status_filter: Optional[str] = None,
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = ShadowAIService(db)
    items, total = await service.list_sightings(
        current_user.org_id,
        status_filter,
        skip=pagination.skip,
        limit=pagination.limit,
    )
    return Page(items=items, total=total, skip=pagination.skip, limit=pagination.limit)


@router.get("/summary")
async def summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = ShadowAIService(db)
    return await service.summary_counts(current_user.org_id)


@router.put("/{sighting_id}", response_model=ShadowSightingOut)
async def update_sighting(
    sighting_id: int,
    data: ShadowSightingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.approver)),
):
    """Reviewers only: dismissing a sighting hides unsanctioned AI use."""
    service = ShadowAIService(db)
    sighting = await service.update_status(sighting_id, current_user.org_id, data)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "shadow_ai_sighting", sighting.id,
        data.status or "updated",
        {"notes": data.notes},
    )
    return sighting


@router.post("/{sighting_id}/register", response_model=ShadowSightingOut)
async def register_sighting(
    sighting_id: int,
    data: ShadowSightingRegister,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    service = ShadowAIService(db)
    sighting = await service.register_as_provider(sighting_id, current_user.org_id, data)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "shadow_ai_sighting", sighting.id, "registered",
        {"registered_provider_id": sighting.registered_provider_id},
    )
    return sighting


@router.get("/extension/download")
async def download_extension(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, mints=True)),  # issues a key
):
    """
    Packages the browser extension pre-configured with a freshly minted
    browser_extension IngestionSource for the admin's own organization -
    one click, no manual key copy-paste.

    A NEW source is created on every download rather than looking one
    up: IngestionSource deliberately never stores or re-exposes a raw
    key after creation (see ingestion_source_service.py) - "find the
    existing key" is not a thing that can exist by design, so "mint a
    fresh one for this download" is the only correct move, and it is
    scoped to current_user.org_id specifically so this can never hand
    out a key belonging to a different organization.
    """
    base_url = str(request.base_url).rstrip("/")
    api_url = f"{base_url}{settings.API_V1_STR}/shadow-ai/ingest"

    source_service = IngestionSourceService(db)
    source, raw_key = await source_service.create_source(
        current_user.org_id,
        current_user.id,
        IngestionSourceCreate(
            name=f"Browser extension ({current_user.email})",
            source_type="browser_extension",
        ),
    )
    await AuditService(db).log(
        current_user.org_id, current_user.id, "ingestion_source", source.id, "created",
        {"name": source.name, "source_type": source.source_type, "via": "extension_download"},
    )

    ext_dir = settings.EXTENSION_TEMPLATE_DIR
    if not os.path.isdir(ext_dir):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Extension template not found on this server.",
        )

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for root, _, files in os.walk(ext_dir):
            for file in files:
                if file.endswith((".zip", ".tar.gz")):
                    continue
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, ext_dir)

                if rel_path == os.path.join("background", "service-worker.js"):
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    content = re.sub(r'apiUrl:\s*".*?"', f'apiUrl: "{api_url}"', content)
                    content = re.sub(
                        r'ingestionKey:\s*".*?"', f'ingestionKey: "{raw_key}"', content
                    )
                    zip_file.writestr(rel_path, content)
                else:
                    zip_file.write(file_path, rel_path)

    zip_buffer.seek(0)
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="shadow-ai-extension.zip"'
        },
    )
