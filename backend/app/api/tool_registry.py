# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Tool Registry (ASI04): mode, entries, approval, pinning, manifest digest."""

from typing import List, Optional

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.user import User, UserRole
from app.schemas.tool_registry import (
    ManifestIn, SupplyChainMode, ToolEntryCreate, ToolEntryOut, ToolEntryUpdate,
)
from app.services.audit_service import AuditService
from app.services.supply_chain import MODES, SupplyChain, manifest_digest

router = APIRouter()


@router.get("/settings")
async def get_settings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return {"mode": await SupplyChain(db).mode(current_user.org_id), "modes": list(MODES)}


@router.put("/settings")
async def set_settings(
    data: SupplyChainMode,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    before, after = await SupplyChain(db).set_mode(current_user.org_id, data.mode, current_user.id)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "tool_registry", 0, "mode_changed", {"from": before, "to": after},
    )
    return {"mode": after}


@router.post("/manifest-digest")
async def compute_manifest_digest(
    data: ManifestIn,
    current_user: User = Depends(get_current_user),
):
    """Canonical sha256 of a tool manifest (e.g. an MCP server's tools/list
    result) - paste it into pinned_digest; agents report the same value."""
    return {"digest": "sha256:" + manifest_digest(data.manifest)}


@router.get("/", response_model=List[ToolEntryOut])
async def list_entries(
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return await SupplyChain(db).entries(current_user.org_id, status)


@router.post("/", response_model=ToolEntryOut)
async def create_entry(
    data: ToolEntryCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    service = SupplyChain(db)
    entry_id = await service.create(current_user.org_id, current_user.id, data.model_dump())
    await AuditService(db).log(
        current_user.org_id, current_user.id, "tool_registry", entry_id, "created", data.model_dump(),
    )
    return await service.get(current_user.org_id, entry_id)


@router.patch("/{entry_id}", response_model=ToolEntryOut)
async def update_entry(
    entry_id: int,
    data: ToolEntryUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    service = SupplyChain(db)
    changes = data.model_dump(exclude_unset=True)
    await service.update(current_user.org_id, entry_id, changes)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "tool_registry", entry_id, "updated", changes,
    )
    return await service.get(current_user.org_id, entry_id)


async def _set_status(db, user, entry_id, new_status, action):
    service = SupplyChain(db)
    previous = await service.set_status(user.org_id, entry_id, new_status, user.id)
    await AuditService(db).log(user.org_id, user.id, "tool_registry", entry_id, action,
                               {"from": previous, "to": new_status})
    return await service.get(user.org_id, entry_id)


@router.post("/{entry_id}/approve", response_model=ToolEntryOut)
async def approve_entry(
    entry_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    return await _set_status(db, current_user, entry_id, "approved", "approved")


@router.post("/{entry_id}/block", response_model=ToolEntryOut)
async def block_entry(
    entry_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    return await _set_status(db, current_user, entry_id, "blocked", "blocked")


@router.delete("/{entry_id}")
async def delete_entry(
    entry_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    snapshot = await SupplyChain(db).delete(current_user.org_id, entry_id)
    await AuditService(db).log(current_user.org_id, current_user.id, "tool_registry", entry_id, "deleted", snapshot)
    return {"deleted": True}
