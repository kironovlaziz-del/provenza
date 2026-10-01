# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Compliance auto-mapping: live status, attestations, immutable reports."""

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
from app.models.ai_system import AISystem
from app.models.compliance import ComplianceAttestation, ComplianceReport
from app.models.user import User, UserRole
from app.schemas.compliance import AttestationIn, ReportIn
from app.services.audit_service import AuditService
from app.services.compliance_catalog import BY_ID, CATALOG_VERSION, FRAMEWORKS, REQUIREMENTS
from app.services.compliance_engine import canonical_hash, evaluate

router = APIRouter()


def _roles(*names):
    return [getattr(UserRole, n) for n in names if hasattr(UserRole, n)]


READ = require_role(*_roles("admin", "approver", "auditor", "compliance"))
ATTEST = require_role(*_roles("admin", "compliance"))


def _frameworks(param: Optional[str]):
    if not param:
        return None
    return [p for p in param.split(",") if p in FRAMEWORKS]


@router.get("/catalog")
async def catalog(current_user: User = Depends(READ)):
    return {"version": CATALOG_VERSION, "frameworks": FRAMEWORKS, "requirements": REQUIREMENTS}


@router.get("/status")
async def status(frameworks: Optional[str] = None, db: AsyncSession = Depends(get_db),
                 current_user: User = Depends(READ)):
    return await evaluate(db, current_user.org_id, _frameworks(frameworks))


@router.get("/systems/{system_id}")
async def system_status(system_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(READ)):
    ok = (await db.execute(select(AISystem.id).where(AISystem.id == system_id,
                                                     AISystem.org_id == current_user.org_id))).scalar_one_or_none()
    if not ok:
        raise HTTPException(status_code=404, detail="AI system not found")
    result = await evaluate(db, current_user.org_id)
    rows = []
    for r in result["requirements"]:
        for s in r.get("systems") or []:
            if s["system_id"] == system_id:
                rows.append({k: r[k] for k in ("id", "framework", "ref", "title", "attest", "fix")} | s)
    return {"system_id": system_id, "requirements": rows}


@router.get("/attestations")
async def attestations(requirement_id: Optional[str] = None, system_id: Optional[int] = None,
                       limit: int = Query(100, ge=1, le=500),
                       db: AsyncSession = Depends(get_db), current_user: User = Depends(READ)):
    q = select(ComplianceAttestation).where(ComplianceAttestation.org_id == current_user.org_id)
    if requirement_id:
        q = q.where(ComplianceAttestation.requirement_id == requirement_id)
    if system_id is not None:
        q = q.where(ComplianceAttestation.system_id == system_id)
    rows = (await db.execute(q.order_by(ComplianceAttestation.attested_at.desc(), ComplianceAttestation.id.desc()).limit(limit))).scalars().all()
    return [{"id": a.id, "requirement_id": a.requirement_id, "system_id": a.system_id, "status": a.status,
             "note": a.note, "evidence_url": a.evidence_url, "attested_by": a.attested_by,
             "attested_at": a.attested_at, "valid_until": a.valid_until} for a in rows]


@router.post("/attestations")
async def attest(data: AttestationIn, db: AsyncSession = Depends(get_db), current_user: User = Depends(ATTEST)):
    req = BY_ID.get(data.requirement_id)
    if req is None:
        raise HTTPException(status_code=404, detail="Unknown requirement")
    if not req["attest"]:
        raise HTTPException(status_code=409, detail="This requirement is checked automatically from Provenza data")
    if req["scope"] == "system":
        if data.system_id is None:
            raise HTTPException(status_code=422, detail="This requirement is per AI system: system_id is required")
        ok = (await db.execute(select(AISystem.id).where(AISystem.id == data.system_id,
                                                         AISystem.org_id == current_user.org_id))).scalar_one_or_none()
        if not ok:
            raise HTTPException(status_code=404, detail="AI system not found")
    elif data.system_id is not None:
        raise HTTPException(status_code=422, detail="This requirement is organization-wide: omit system_id")
    a = ComplianceAttestation(
        org_id=current_user.org_id, requirement_id=data.requirement_id, system_id=data.system_id,
        status=data.status, note=data.note, evidence_url=data.evidence_url, attested_by=current_user.id,
        valid_until=datetime.now(timezone.utc) + timedelta(days=data.valid_days) if data.valid_days else None,
    )
    db.add(a)
    await db.commit()
    await db.refresh(a)
    await AuditService(db).log(current_user.org_id, current_user.id, "compliance_attestation", a.id, "attested",
                               {"requirement_id": a.requirement_id, "system_id": a.system_id, "status": a.status,
                                "evidence_url": a.evidence_url})
    return {"id": a.id, "requirement_id": a.requirement_id, "system_id": a.system_id, "status": a.status,
            "valid_until": a.valid_until}


@router.post("/reports")
async def create_report(data: ReportIn, db: AsyncSession = Depends(get_db), current_user: User = Depends(READ)):
    content = await evaluate(db, current_user.org_id, data.frameworks)
    content["generated_by"] = current_user.id
    # plain JSON (datetimes -> ISO strings) so the stored JSONB hashes the same on read-back
    content = json.loads(json.dumps(content, default=str))
    digest = canonical_hash(content)
    rep = ComplianceReport(org_id=current_user.org_id, frameworks=content["frameworks"], summary=content["summary"],
                           content=content, sha256=digest, created_by=current_user.id)
    db.add(rep)
    await db.commit()
    await db.refresh(rep)
    await AuditService(db).log(current_user.org_id, current_user.id, "compliance_report", rep.id, "generated",
                               {"frameworks": rep.frameworks, "sha256": digest})
    return {"id": rep.id, "sha256": digest, "created_at": rep.created_at}


@router.get("/reports")
async def list_reports(db: AsyncSession = Depends(get_db), current_user: User = Depends(READ)):
    rows = (await db.execute(
        select(ComplianceReport).where(ComplianceReport.org_id == current_user.org_id)
        .order_by(ComplianceReport.created_at.desc(), ComplianceReport.id.desc()).limit(100)
    )).scalars().all()
    return [{"id": r.id, "created_at": r.created_at, "created_by": r.created_by, "frameworks": r.frameworks,
             "summary": r.summary, "sha256": r.sha256} for r in rows]


@router.get("/reports/{report_id}")
async def get_report(report_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(READ)):
    r = (await db.execute(select(ComplianceReport).where(
        ComplianceReport.id == report_id, ComplianceReport.org_id == current_user.org_id))).scalar_one_or_none()
    if r is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"id": r.id, "created_at": r.created_at, "created_by": r.created_by, "sha256": r.sha256,
            "integrity_ok": canonical_hash(r.content) == r.sha256, "content": r.content}
