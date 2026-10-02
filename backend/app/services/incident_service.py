from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status
from typing import List
from datetime import datetime, timezone
from app.core.errors import api_error
from app.models.ai_incident import AIIncident
from app.models.ai_request import AIRequest
from app.schemas.incident import IncidentCreate, IncidentUpdate

class IncidentService:
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_incident(self, org_id: int, data: IncidentCreate) -> AIIncident:
        if data.request_id is not None:
            # The request an incident points at must be this organization's.
            found = await self.db.scalar(
                select(AIRequest.id).where(AIRequest.id == data.request_id, AIRequest.org_id == org_id)
            )
            if found is None:
                raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "incident.request_not_found")
        incident = AIIncident(
            org_id=org_id,
            request_id=data.request_id,
            severity=data.severity,
            category=data.category,
            summary=data.summary,
            impact=data.impact,
            status="open"
        )
        self.db.add(incident)
        await self.db.commit()
        await self.db.refresh(incident)
        return incident
    
    async def get_incident(self, incident_id: int, org_id: int) -> AIIncident:
        result = await self.db.execute(
            select(AIIncident).where(
                AIIncident.id == incident_id,
                AIIncident.org_id == org_id
            )
        )
        incident = result.scalar_one_or_none()
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Incident not found"
            )
        return incident
    
    async def list_incidents(
        self, org_id: int, skip: int = 0, limit: int = 50
    ) -> "tuple[List[AIIncident], int]":
        from sqlalchemy import func

        base = select(AIIncident).where(AIIncident.org_id == org_id)
        total = await self.db.scalar(
            select(func.count()).select_from(base.subquery())
        )
        result = await self.db.execute(
            base.order_by(AIIncident.created_at.desc()).offset(skip).limit(limit)
        )
        return list(result.scalars().all()), int(total or 0)
    
    async def update_incident(
        self, incident_id: int, org_id: int, data: IncidentUpdate
    ) -> AIIncident:
        incident = await self.get_incident(incident_id, org_id)
        
        if data.severity is not None:
            incident.severity = data.severity
        if data.category is not None:
            incident.category = data.category
        if data.summary is not None:
            incident.summary = data.summary
        if data.impact is not None:
            incident.impact = data.impact
        if data.root_cause is not None:
            incident.root_cause = data.root_cause
        if data.status is not None:
            incident.status = data.status
            if data.status == "resolved":
                incident.resolved_at = datetime.now(timezone.utc)
        
        await self.db.commit()
        await self.db.refresh(incident)
        return incident

