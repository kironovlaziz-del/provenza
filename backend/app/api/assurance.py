# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza - https://github.com/kironovlaziz-del/provenza

"""Assurance records of AI systems: evaluations, bias tests, red teaming,
robustness tests (models/assurance.py).

  GET  /                   every record of the organization, newest first
  GET  /systems/{id}       one system's records
  POST /systems/{id}       record a test (admin, approver, compliance officer)

Records are append-only: a correction is a new record. Reading takes an
admin or approver; the oversight roles read too.
"""

from datetime import date
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
from app.core.errors import api_error
from app.models.ai_system import AISystem
from app.models.assurance import AssuranceRecord
from app.models.user import User, UserRole
from app.services.audit_service import AuditService

router = APIRouter()

READ = require_role(UserRole.admin, UserRole.approver)
WRITE = require_role(UserRole.admin, UserRole.approver, UserRole.compliance)

Kind = Literal["evaluation", "bias", "red_team", "robustness"]
Result = Literal["passed", "passed_with_findings", "failed"]


class RecordIn(BaseModel):
    kind: Kind
    title: str = Field(min_length=1, max_length=255)
    performed_on: date
    performed_by: Optional[str] = Field(default=None, max_length=255)
    result: Result
    summary: Optional[str] = Field(default=None, max_length=10_000)
    findings: Optional[str] = Field(default=None, max_length=10_000)
    evidence_url: Optional[str] = Field(default=None, max_length=500, pattern=r"^(https?://|/)\S+$")
    next_due: Optional[date] = None

    @field_validator("performed_on")
    @classmethod
    def _not_future(cls, v):
        if v > date.today():
            raise ValueError("a test cannot be performed in the future")
        return v


class RecordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    system_id: int
    kind: str
    title: str
    performed_on: date
    performed_by: Optional[str] = None
    result: str
    summary: Optional[str] = None
    findings: Optional[str] = None
    evidence_url: Optional[str] = None
    next_due: Optional[date] = None
    created_by: Optional[int] = None


async def _system(db: AsyncSession, org_id: int, system_id: int) -> AISystem:
    s = (await db.execute(select(AISystem).where(AISystem.id == system_id, AISystem.org_id == org_id))).scalar_one_or_none()
    if s is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "assurance.system_not_found")
    return s


def _order(q):
    return q.order_by(AssuranceRecord.performed_on.desc(), AssuranceRecord.id.desc())


@router.get("/", response_model=List[RecordOut])
async def list_records(kind: Optional[Kind] = None, limit: int = Query(200, ge=1, le=1000),
                       db: AsyncSession = Depends(get_db), current_user: User = Depends(READ)):
    q = select(AssuranceRecord).where(AssuranceRecord.org_id == current_user.org_id)
    if kind:
        q = q.where(AssuranceRecord.kind == kind)
    return (await db.execute(_order(q).limit(limit))).scalars().all()


@router.get("/systems/{system_id}", response_model=List[RecordOut])
async def for_system(system_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(READ)):
    await _system(db, current_user.org_id, system_id)
    q = select(AssuranceRecord).where(AssuranceRecord.system_id == system_id)
    return (await db.execute(_order(q))).scalars().all()


@router.post("/systems/{system_id}", response_model=RecordOut, status_code=status.HTTP_201_CREATED)
async def record(system_id: int, data: RecordIn, db: AsyncSession = Depends(get_db),
                 current_user: User = Depends(WRITE)):
    await _system(db, current_user.org_id, system_id)
    rec = AssuranceRecord(org_id=current_user.org_id, system_id=system_id, created_by=current_user.id,
                          **data.model_dump())
    db.add(rec)
    await db.commit()
    await db.refresh(rec)
    await AuditService(db).log(current_user.org_id, current_user.id, "assurance_record", rec.id, "recorded",
                               {"system_id": system_id, "kind": rec.kind, "result": rec.result,
                                "performed_on": rec.performed_on.isoformat()})
    return rec
