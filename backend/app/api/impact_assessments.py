# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza - https://github.com/kironovlaziz-del/provenza

"""Impact assessments of AI systems (services/impact_assessment.py).

  GET  /template                      the questionnaire
  GET  /systems/{id}                  the draft, the approved version, the history
  PUT  /systems/{id}/draft            save the draft (creates it on first save)
  POST /systems/{id}/approve          approve the draft: it becomes a frozen version

Reading takes an admin or approver (the oversight roles read too); editing
and approving take an admin or the compliance officer.
"""

from datetime import date, datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
from app.core.errors import api_error
from app.models.ai_system import AISystem
from app.models.impact_assessment import ImpactAssessment
from app.models.user import User, UserRole
from app.services import impact_assessment as ia
from app.services.audit_service import AuditService

router = APIRouter()

READ = require_role(UserRole.admin, UserRole.approver)
EDIT = require_role(UserRole.admin, UserRole.compliance)


class DraftIn(BaseModel):
    answers: Dict[str, Any] = Field(default_factory=dict)


def _full(a):
    if a is None:
        return None
    return {**ia.summary(a), "answers": a.answers or {}}


async def _system(db: AsyncSession, org_id: int, system_id: int) -> AISystem:
    s = (await db.execute(select(AISystem).where(AISystem.id == system_id, AISystem.org_id == org_id))).scalar_one_or_none()
    if s is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "impact_assessment.system_not_found")
    return s


async def _draft(db: AsyncSession, system_id: int):
    return (await db.execute(select(ImpactAssessment).where(
        ImpactAssessment.system_id == system_id, ImpactAssessment.status == "draft"))).scalar_one_or_none()


@router.get("/template")
async def template(current_user: User = Depends(READ)):
    return {"version": ia.TEMPLATE_VERSION, "sections": ia.TEMPLATE}


@router.get("/systems/{system_id}")
async def for_system(system_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(READ)):
    await _system(db, current_user.org_id, system_id)
    approved = (await db.execute(select(ImpactAssessment).where(
        ImpactAssessment.system_id == system_id, ImpactAssessment.status == "approved",
    ).order_by(ImpactAssessment.version.desc()))).scalars().all()
    draft = await _draft(db, system_id)
    return {
        "system_id": system_id,
        "draft": _full(draft),
        "missing": ia.missing(draft.answers or {}) if draft else None,
        "approved": _full(approved[0]) if approved else None,
        "history": [ia.summary(a) for a in approved],
    }


@router.put("/systems/{system_id}/draft")
async def save_draft(system_id: int, data: DraftIn, db: AsyncSession = Depends(get_db),
                     current_user: User = Depends(EDIT)):
    await _system(db, current_user.org_id, system_id)
    try:
        answers = ia.clean(data.answers)
    except ValueError as e:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "impact_assessment.invalid_answer", question=str(e))
    draft = await _draft(db, system_id)
    created = draft is None
    if created:
        last = (await db.execute(select(func.max(ImpactAssessment.version)).where(
            ImpactAssessment.system_id == system_id))).scalar() or 0
        draft = ImpactAssessment(org_id=current_user.org_id, system_id=system_id, version=last + 1,
                                 status="draft", template_version=ia.TEMPLATE_VERSION,
                                 created_by=current_user.id)
        db.add(draft)
    draft.answers = answers
    draft.template_version = ia.TEMPLATE_VERSION
    draft.updated_by = current_user.id
    await db.commit()
    await db.refresh(draft)
    if created:
        await AuditService(db).log(current_user.org_id, current_user.id, "impact_assessment", draft.id,
                                   "draft_started", {"system_id": system_id, "version": draft.version})
    return {**_full(draft), "missing": ia.missing(draft.answers)}


@router.post("/systems/{system_id}/approve")
async def approve(system_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(EDIT)):
    await _system(db, current_user.org_id, system_id)
    draft = await _draft(db, system_id)
    if draft is None:
        raise api_error(status.HTTP_409_CONFLICT, "impact_assessment.no_draft")
    gaps = ia.missing(draft.answers or {})
    if gaps:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "impact_assessment.incomplete", missing=gaps)
    rd = (draft.answers or {}).get("review_date")
    if rd and date.fromisoformat(rd) <= date.today():
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "impact_assessment.review_in_past")
    now = datetime.now(timezone.utc)
    draft.status = "approved"
    draft.approved_by = current_user.id
    draft.approved_at = now
    draft.review_due = ia.review_due(draft.answers, now)
    await db.commit()
    await db.refresh(draft)
    ans = draft.answers or {}
    await AuditService(db).log(current_user.org_id, current_user.id, "impact_assessment", draft.id, "approved",
                               {"system_id": system_id, "version": draft.version, "residual": ans.get("residual"),
                                "decision": ans.get("decision"), "review_due": draft.review_due.isoformat()})
    return _full(draft)
