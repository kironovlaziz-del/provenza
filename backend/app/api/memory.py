# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Memory integrity (ASI06): agent-memory attestation, RAG document trust, settings."""

from typing import Literal, Optional

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.user import User, UserRole
from app.schemas.memory import MemorySettingsIn, MemoryVerifyIn, MemoryWriteIn
from app.services.audit_service import AuditService
from app.services.memory_guard import MemoryGuard

router = APIRouter()


@router.get("/")
async def overview(
    entry_status: Optional[Literal["trusted", "quarantined", "revoked", "rejected"]] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.approver)),
):
    return await MemoryGuard(db).overview(current_user.org_id, entry_status)


@router.put("/settings")
async def update_settings(
    data: MemorySettingsIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    before, after = await MemoryGuard(db).save_settings(current_user.org_id, data.model_dump(), current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "memory_guard", 0, "settings_updated",
                               {"before": before, "after": after})
    return after


# ---------------------------------------------------------------- agent memory
@router.post("/write")
async def write(
    data: MemoryWriteIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Attest a memory write before the agent stores it. The content is scanned, never stored."""
    return await MemoryGuard(db).write(current_user.org_id, data.model_dump())


@router.post("/verify")
async def verify(
    data: MemoryVerifyIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Check retrieved memory before it goes into a prompt; use only items with use=true."""
    return await MemoryGuard(db).verify(current_user.org_id, data.agent_id, [i.model_dump() for i in data.items])


@router.post("/entries/{entry_id}/trust")
async def trust_entry(entry_id: int, db: AsyncSession = Depends(get_db),
                      current_user: User = Depends(require_role(UserRole.admin))):
    r = await MemoryGuard(db).set_entry_status(current_user.org_id, entry_id, True, current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "memory_entry", entry_id, "memory_trusted", r)
    return r


@router.post("/entries/{entry_id}/revoke")
async def revoke_entry(entry_id: int, db: AsyncSession = Depends(get_db),
                       current_user: User = Depends(require_role(UserRole.admin))):
    r = await MemoryGuard(db).set_entry_status(current_user.org_id, entry_id, False, current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "memory_entry", entry_id, "memory_revoked", r)
    return r


# ---------------------------------------------------------------- RAG documents
@router.post("/documents/{document_id}/trust")
async def trust_document(document_id: int, db: AsyncSession = Depends(get_db),
                         current_user: User = Depends(require_role(UserRole.admin))):
    r = await MemoryGuard(db).set_document_trust(current_user.org_id, document_id, True, current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "rag_document", document_id, "document_trusted", r)
    return r


@router.post("/documents/{document_id}/revoke")
async def revoke_document(document_id: int, db: AsyncSession = Depends(get_db),
                          current_user: User = Depends(require_role(UserRole.admin))):
    r = await MemoryGuard(db).set_document_trust(current_user.org_id, document_id, False, current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "rag_document", document_id, "document_revoked", r)
    return r


@router.post("/collections/{collection_id}/rescan")
async def rescan_collection(collection_id: int, db: AsyncSession = Depends(get_db),
                            current_user: User = Depends(require_role(UserRole.admin))):
    r = await MemoryGuard(db).rescan_collection(current_user.org_id, collection_id)
    await AuditService(db).log(current_user.org_id, current_user.id, "document_collection", collection_id,
                               "collection_rescanned", r)
    return r
