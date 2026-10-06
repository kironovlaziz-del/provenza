# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Agent enrollment (services/enrollment.py):

    POST /agent-enrollment/tokens                admin: issue a one-time token (shown once)
    GET  /agent-enrollment/tokens                admin/approver: list (never the token)
    POST /agent-enrollment/tokens/{id}/revoke    admin
    POST /agent-enrollment/challenge             agent, with the token: a fresh challenge
    POST /agent-enrollment/enroll                agent: the signed challenge -> agent created / re-keyed

The last two are unauthenticated - the token is the credential - and
throttled per IP.
"""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core import rate_limit
from app.core.database import get_db
from app.models.user import User, UserRole
from app.schemas.enrollment import ChallengeIn, EnrollIn, EnrollmentCreate
from app.services import enrollment
from app.services.audit_service import AuditService

router = APIRouter()
_admin = require_role(UserRole.admin)
_viewer = require_role(UserRole.admin, UserRole.approver)

ENROLL_LIMIT = 30          # attempts per IP ...
ENROLL_WINDOW = 600        # ... per 10 minutes


@router.post("/tokens")
async def issue_token(data: EnrollmentCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    e, raw = await enrollment.issue(db, current_user.org_id, current_user.id, data.model_dump())
    meta = {k: v for k, v in enrollment.out(e).items() if k not in ("created_at",)}
    await AuditService(db).log(current_user.org_id, current_user.id, "agent_enrollment", e.id, "token_issued", meta)
    return {**enrollment.out(e), "token": raw, "attestation": await enrollment.attestation_hint(db, e)}


@router.get("/tokens")
async def list_tokens(db: AsyncSession = Depends(get_db), current_user: User = Depends(_viewer)):
    return [enrollment.out(e) for e in await enrollment.list_for(db, current_user.org_id)]


@router.post("/tokens/{enrollment_id}/revoke")
async def revoke_token(enrollment_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    e = await enrollment.revoke(db, current_user.org_id, enrollment_id)
    await AuditService(db).log(current_user.org_id, current_user.id, "agent_enrollment", e.id, "token_revoked", None)
    return enrollment.out(e)


@router.post("/challenge")
async def get_challenge(data: ChallengeIn, request: Request, db: AsyncSession = Depends(get_db)):
    rate_limit.enforce(request, scope="enroll", limit=ENROLL_LIMIT, window_seconds=ENROLL_WINDOW)
    return await enrollment.challenge(db, data.token)


@router.post("/enroll")
async def enroll(data: EnrollIn, request: Request, db: AsyncSession = Depends(get_db)):
    rate_limit.enforce(request, scope="enroll", limit=ENROLL_LIMIT, window_seconds=ENROLL_WINDOW)
    return await enrollment.enroll(
        db, data.token, public_key=data.public_key, pq_public_key=data.pq_public_key, name=data.name,
        challenge_value=data.challenge, signature=data.signature, pq_signature=data.pq_signature)
