from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.core.database import get_db
from app.core.errors import api_error
from app.core.pagination import PaginationParams
from app.schemas.discovery import (
    DiscoveryReportRequest,
    DiscoveryReportResponse,
    DiscoveredServiceOut,
    ServiceConnectRequest,
    ServiceConnectionOut,
    ServiceIgnoreRequest,
)
from app.schemas.pagination import Page
from app.services.discovery_service import DiscoveryService
from app.services.audit_service import AuditService
from app.models.ingestion_source import IngestionSource
from app.models.user import User, UserRole
from app.api.deps import get_current_user, require_role, get_ingestion_source

router = APIRouter()

# Ingestion keys allowed to report network services. A browser-extension key
# ships inside the extension zip every employee installs, so it must not be
# able to add an "Active Directory server" an admin may later send domain
# credentials to.
DISCOVERY_SOURCE_TYPES = {"gateway", "endpoint"}


@router.post("/report", response_model=DiscoveryReportResponse)
async def report_discovery(
    data: DiscoveryReportRequest,
    db: AsyncSession = Depends(get_db),
    source: IngestionSource = Depends(get_ingestion_source),
):
    """
    Receives passively-discovered network services from the discovery
    layer (sniffer/agent). Machine-authenticated via X-Ingestion-Key,
    same as telemetry ingestion. Recording a service here is a read-only
    observation and never triggers a connection.
    """
    if source.source_type not in DISCOVERY_SOURCE_TYPES:
        raise api_error(status.HTTP_403_FORBIDDEN, "ingestion.scope_denied")
    service = DiscoveryService(db)
    new_count, updated_count = await service.report_services(
        source.org_id, data.services, reported_by=source.name
    )
    return DiscoveryReportResponse(
        received=len(data.services), new_services=new_count, updated_services=updated_count
    )


@router.get("/", response_model=Page[DiscoveredServiceOut])
async def list_discovered(
    status_filter: Optional[str] = None,
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = DiscoveryService(db)
    items, total = await service.list_services(
        current_user.org_id, status_filter, skip=pagination.skip, limit=pagination.limit
    )
    return Page(items=items, total=total, skip=pagination.skip, limit=pagination.limit)


@router.post("/{service_id}/connect", response_model=DiscoveredServiceOut)
async def connect_discovered(
    service_id: int,
    creds: ServiceConnectRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """
    Admin explicitly connects one discovered service with real
    credentials. Admin-only, and the only path that establishes a real
    connection - there is no anonymous auto-attach.
    """
    service = DiscoveryService(db)
    svc = await service.connect_service(
        service_id, current_user.org_id, current_user.id, creds
    )
    await AuditService(db).log(
        current_user.org_id, current_user.id, "discovered_service", svc.id, "connect_attempt",
        {"service_type": svc.service_type, "host": svc.host, "result": svc.connect_status},
    )
    return svc


@router.post("/{service_id}/ignore", response_model=DiscoveredServiceOut)
async def ignore_discovered(
    service_id: int,
    data: ServiceIgnoreRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    service = DiscoveryService(db)
    svc = await service.ignore_service(service_id, current_user.org_id, data.reason)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "discovered_service", svc.id, "ignored",
        {"reason": data.reason},
    )
    return svc


@router.get("/{service_id}/connection", response_model=Optional[ServiceConnectionOut])
async def get_service_connection(
    service_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """
    Return the credentialed connection details for a discovered service
    (bind DN, what the one-time read found, last verification), or null
    if it was never connected. The stored secret is never included.
    """
    service = DiscoveryService(db)
    return await service.get_connection(service_id, current_user.org_id)


@router.post("/{service_id}/reverify", response_model=Optional[ServiceConnectionOut])
async def reverify_service_connection(
    service_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """
    Manually re-check a stored connection using its saved credentials.
    Returns the updated connection (with refreshed last_verified_at /
    last_error), or null if the service was never connected.
    """
    service = DiscoveryService(db)
    conn = await service.reverify_connection(service_id, current_user.org_id)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "discovered_service", service_id, "reverified",
        {"ok": conn.last_error is None if conn else None},
    )
    return conn
