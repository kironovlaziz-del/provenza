from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from app.core.database import get_db
from app.core.pagination import PaginationParams
from app.schemas.incident import IncidentCreate, IncidentUpdate, IncidentOut
from app.schemas.pagination import Page
from app.services.incident_service import IncidentService
from app.services.audit_service import AuditService
from app.services import notification_service
from app.models.user import User, UserRole
from app.api.deps import get_current_user, require_role

router = APIRouter()

@router.post("/", response_model=IncidentOut)
async def create_incident(
    data: IncidentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    service = IncidentService(db)
    incident = await service.create_incident(current_user.org_id, data)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "incident", incident.id, "created",
        {"category": incident.category, "severity": incident.severity},
    )
    await notification_service.notify(
        db, current_user.org_id, "incident_created",
        f"New incident: {incident.category}",
        f"Severity: {incident.severity}\n{incident.summary}",
        {"incident_id": incident.id},
    )
    return incident

@router.get("/", response_model=Page[IncidentOut])
async def list_incidents(
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = IncidentService(db)
    items, total = await service.list_incidents(
        current_user.org_id, skip=pagination.skip, limit=pagination.limit
    )
    return Page(items=items, total=total, skip=pagination.skip, limit=pagination.limit)

@router.get("/{incident_id}", response_model=IncidentOut)
async def get_incident(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    service = IncidentService(db)
    return await service.get_incident(incident_id, current_user.org_id)

@router.put("/{incident_id}", response_model=IncidentOut)
async def update_incident(
    incident_id: int,
    data: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.approver)),
):
    """Triage is for reviewers: anyone may report an incident, but closing one
    or lowering its severity is a decision."""
    service = IncidentService(db)
    incident = await service.update_incident(incident_id, current_user.org_id, data)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "incident", incident.id, "updated",
        data.model_dump(exclude_unset=True),
    )
    return incident
