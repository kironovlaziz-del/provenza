# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Workload attestation, admin side (services/attestation.py). The agent side
is /agents/{id}/attestation/challenge and /agents/{id}/attestation.

    GET    /attestation/policies              policies (with the roles using each)
    POST   /attestation/policies              create (admin)
    PATCH  /attestation/policies/{id}         change (admin) - earlier attestations stop counting
    DELETE /attestation/policies/{id}         delete (admin) - refused while a role uses it
    POST   /attestation/policies/{id}/test    check a token against the policy, nothing recorded (admin)
    GET    /attestation/records               attestation attempts, newest first
    GET    /attestation/agents/{agent_id}     what an agent needs and has
"""

from typing import Any, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.user import User, UserRole
from app.services import attestation
from app.services.audit_service import AuditService

router = APIRouter()
_admin = require_role(UserRole.admin)


def _name(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    v = v.strip()
    if not v:
        raise ValueError("name is required")
    return v


class PolicyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=2000)
    kind: str = Field(default="k8s_sa", pattern="^k8s_sa$")
    issuer: str = Field(min_length=8, max_length=500)
    audience: str = Field(default="provenza", min_length=1, max_length=200)
    jwks: Optional[Any] = None
    jwks_url: Optional[str] = Field(default=None, max_length=500)
    namespaces: List[str] = Field(default_factory=list, max_length=100)
    service_accounts: List[str] = Field(default_factory=list, max_length=100)
    require_pod_bound: bool = True
    validity_minutes: int = Field(default=60, ge=5, le=1440)

    @field_validator("name")
    @classmethod
    def _n(cls, v):
        return _name(v)

    @field_validator("issuer", "audience", "jwks_url")
    @classmethod
    def _strip(cls, v):
        return (v.strip() or None) if isinstance(v, str) else v


class PolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=2000)
    issuer: Optional[str] = Field(default=None, min_length=8, max_length=500)
    audience: Optional[str] = Field(default=None, min_length=1, max_length=200)
    jwks: Optional[Any] = None
    jwks_url: Optional[str] = Field(default=None, max_length=500)
    namespaces: Optional[List[str]] = Field(default=None, max_length=100)
    service_accounts: Optional[List[str]] = Field(default=None, max_length=100)
    require_pod_bound: Optional[bool] = None
    validity_minutes: Optional[int] = Field(default=None, ge=5, le=1440)

    @field_validator("name")
    @classmethod
    def _n(cls, v):
        return _name(v)

    @field_validator("issuer", "audience", "jwks_url")
    @classmethod
    def _strip(cls, v):
        return (v.strip() or None) if isinstance(v, str) else v


class TokenIn(BaseModel):
    token: str = Field(min_length=10, max_length=16384)


@router.get("/policies")
async def list_policies(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return await attestation.list_policies(db, current_user.org_id)


@router.post("/policies")
async def create_policy(data: PolicyIn, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    p = await attestation.create_policy(db, current_user.org_id, current_user.id, data.model_dump())
    out = attestation.policy_out(p)
    await AuditService(db).log(current_user.org_id, current_user.id, "attestation_policy", p.id, "created", out)
    return out


@router.patch("/policies/{policy_id}")
async def update_policy(policy_id: int, data: PolicyUpdate, db: AsyncSession = Depends(get_db),
                        current_user: User = Depends(_admin)):
    changes = data.model_dump(exclude_unset=True)
    p = await attestation.update_policy(db, current_user.org_id, policy_id, changes)
    out = attestation.policy_out(p)
    logged = {k: v for k, v in changes.items() if k != "jwks"}
    if "jwks" in changes:
        logged["jwks_keys"] = out["jwks_keys"]
    await AuditService(db).log(current_user.org_id, current_user.id, "attestation_policy", p.id, "updated", logged)
    return out


@router.delete("/policies/{policy_id}")
async def delete_policy(policy_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    snapshot = await attestation.delete_policy(db, current_user.org_id, policy_id)
    await AuditService(db).log(current_user.org_id, current_user.id, "attestation_policy", policy_id, "deleted",
                               snapshot)
    return {"deleted": policy_id}


@router.post("/policies/{policy_id}/test")
async def test_policy(policy_id: int, data: TokenIn, db: AsyncSession = Depends(get_db),
                      current_user: User = Depends(_admin)):
    return await attestation.dry_run(db, current_user.org_id, policy_id, data.token)


@router.get("/records")
async def list_records(agent_id: Optional[int] = None, limit: int = Query(50, ge=1, le=200),
                       db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return await attestation.list_attestations(db, current_user.org_id, agent_id, limit)


@router.get("/agents/{agent_id}")
async def agent_status(agent_id: int, db: AsyncSession = Depends(get_db),
                       current_user: User = Depends(get_current_user)):
    return await attestation.status_of(db, current_user.org_id, agent_id)
