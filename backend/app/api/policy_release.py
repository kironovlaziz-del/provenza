# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Signed policy releases (app/services/policy_release.py, docs/pvp/edge.md
section 3).

  GET  /policy-releases/state           the release in force, the draft and
                                        what is not signed yet
  GET  /policy-releases                 history
  GET  /policy-releases/{id}            a release as signed: both documents and
                                        every signature (to check it offline)
  PUT  /policy-releases/settings        quorum, validity, offline time, egress
                                        proxy binaries (take effect with the
                                        next release)
  POST /policy-releases/prepare         a draft from the working copy
  POST /policy-releases/{id}/challenge  the statement for the passkey
  POST /policy-releases/{id}/sign       an administrator's passkey over it
  POST /policy-releases/{id}/withdraw   drop a draft
"""

from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.api.signing import Assertion
from app.core import rate_limit
from app.core.database import get_db
from app.models.user import User, UserRole
from app.services import notification_service
from app.services import policy_release as pr
from app.services.audit_service import AuditService

router = APIRouter()
READERS = (UserRole.admin, UserRole.approver, UserRole.auditor, UserRole.compliance)


def _limit(request: Request, user: User) -> None:
    rate_limit.enforce(request, scope="policy-release", limit=30, window_seconds=300, extra_key=f"user-{user.id}")


class SettingsIn(BaseModel):
    quorum: int = Field(ge=1, le=10)
    validity_days: int = Field(ge=1, le=365)
    offline_seconds: int = Field(ge=60, le=86400)
    # SHA-256 of the egress proxy binaries sensors let out of a proxy host (None: unchanged)
    proxy_binaries: Optional[List[str]] = Field(default=None, max_length=20)
    # SHA-256 of the configurations such a proxy may run with (None: unchanged)
    proxy_configs: Optional[List[str]] = Field(default=None, max_length=20)
    # observe | enforce (None: unchanged)
    enforcement: Optional[Literal["observe", "enforce"]] = None


class SignIn(BaseModel):
    statement: Dict[str, Any]
    assertion: Assertion


@router.get("/state")
async def release_state(db: AsyncSession = Depends(get_db), user: User = Depends(require_role(*READERS))):
    return await pr.state(db, user)


@router.get("")
async def release_history(db: AsyncSession = Depends(get_db), user: User = Depends(require_role(*READERS))):
    return await pr.history(db, user.org_id)


@router.get("/{release_id}")
async def release_document(release_id: int, db: AsyncSession = Depends(get_db),
                           user: User = Depends(require_role(*READERS))):
    return await pr.document(db, user.org_id, release_id)


@router.put("/settings")
async def save_release_settings(data: SettingsIn, db: AsyncSession = Depends(get_db),
                                user: User = Depends(require_role(UserRole.admin))):
    org_id, user_id = user.org_id, user.id
    before = await pr.settings(db, org_id)
    after = await pr.save_settings(db, org_id, user_id, data.model_dump())
    await AuditService(db).log(org_id, user_id, "policy_release", None, "settings_changed",
                               {"before": before, "after": after})
    return after


@router.post("/prepare")
async def prepare_release(request: Request, db: AsyncSession = Depends(get_db),
                          user: User = Depends(require_role(UserRole.admin))):
    _limit(request, user)
    org_id, user_id, email = user.org_id, user.id, user.email
    r = await pr.prepare(db, user)
    number, rid, changes = r.number, r.id, len(r.changes or [])
    await AuditService(db).log(org_id, user_id, "policy_release", rid, "prepared",
                               {"number": number, "bundle_sha256": r.bundle_sha256,
                                "manifest_sha256": r.manifest_sha256, "changes": changes})
    await notification_service.notify(
        db, org_id, pr.NOTIFY_EVENT, f"Policy release #{number} waits for signatures",
        f"{email} prepared release #{number} ({changes} changes). It takes effect when the quorum of "
        f"administrators has signed it with their passkeys.", {"release": number, "changes": changes})
    return await pr.state(db, user)


@router.post("/{release_id}/challenge")
async def release_challenge(release_id: int, request: Request, db: AsyncSession = Depends(get_db),
                            user: User = Depends(require_role(UserRole.admin))):
    _limit(request, user)
    return await pr.challenge(db, user, release_id)


@router.post("/{release_id}/sign")
async def sign_release(release_id: int, data: SignIn, request: Request, db: AsyncSession = Depends(get_db),
                       user: User = Depends(require_role(UserRole.admin))):
    _limit(request, user)
    org_id, user_id = user.org_id, user.id
    r = await pr.sign(db, user, release_id, data.statement, data.assertion.model_dump())
    number, status_ = r.number, r.status
    await AuditService(db).log(org_id, user_id, "policy_release", r.id, "signed",
                               {"number": number, "status": status_, "credential_id": data.assertion.credential_id})
    if status_ == "in_force":
        await AuditService(db).log(org_id, user_id, "policy_release", r.id, "in_force", {"number": number})
        await notification_service.notify(
            db, org_id, pr.NOTIFY_EVENT, f"Policy release #{number} is in force",
            f"The quorum signed release #{number}; decisions are checked against it from now on.",
            {"release": number})
    return await pr.state(db, user)


@router.post("/{release_id}/withdraw")
async def withdraw_release(release_id: int, db: AsyncSession = Depends(get_db),
                           user: User = Depends(require_role(UserRole.admin))):
    org_id, user_id = user.org_id, user.id
    await pr.withdraw(db, user, release_id)
    await AuditService(db).log(org_id, user_id, "policy_release", release_id, "withdrawn", {})
    return await pr.state(db, user)
