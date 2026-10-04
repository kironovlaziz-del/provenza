# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Discovery: reporting devices (/devices) and AI agents found on them (/agents-found)."""

from typing import Literal, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
from app.core.pagination import PaginationParams
from app.models.user import User, UserRole
from app.schemas.endpoint_device import DeviceDetail, DeviceOut, FoundAgentOut, FoundSummary, LinkAgentIn
from app.schemas.pagination import Page
from app.services.audit_service import AuditService
from app.services.endpoint_inventory import EndpointInventory

# Who uses what on which machine is personal data: reviewers and admins only.
_viewer = require_role(UserRole.admin, UserRole.approver)
_admin = require_role(UserRole.admin)

devices_router = APIRouter()
found_router = APIRouter()


@devices_router.get("/", response_model=Page[DeviceOut])
async def list_devices(
    q: Optional[str] = Query(None, max_length=100),
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(_viewer),
):
    items, total = await EndpointInventory(db).list_devices(current_user.org_id, q, pagination.skip, pagination.limit)
    return Page(items=items, total=total, skip=pagination.skip, limit=pagination.limit)


@devices_router.get("/{device_id}", response_model=DeviceDetail)
async def get_device(device_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(_viewer)):
    return await EndpointInventory(db).device(current_user.org_id, device_id)


@found_router.get("/summary", response_model=FoundSummary)
async def found_summary(db: AsyncSession = Depends(get_db), current_user: User = Depends(_viewer)):
    return await EndpointInventory(db).summary(current_user.org_id)


@found_router.get("/", response_model=Page[FoundAgentOut])
async def list_found(
    status: Optional[Literal["new", "registered", "ignored"]] = None,
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(_viewer),
):
    items, total = await EndpointInventory(db).list_found(
        current_user.org_id, status, pagination.skip, pagination.limit)
    return Page(items=items, total=total, skip=pagination.skip, limit=pagination.limit)


@found_router.post("/{found_id}/link")
async def link_found(found_id: int, data: LinkAgentIn, db: AsyncSession = Depends(get_db),
                     current_user: User = Depends(_admin)):
    """The finding was registered as this governed agent."""
    r = await EndpointInventory(db).link(current_user.org_id, found_id, data.agent_id, current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "discovered_agent", found_id,
                               "found_agent_registered", r)
    return r


@found_router.post("/{found_id}/ignore")
async def ignore_found(found_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    r = await EndpointInventory(db).set_ignored(current_user.org_id, found_id, True, current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "discovered_agent", found_id,
                               "found_agent_ignored", r)
    return r


@found_router.post("/{found_id}/restore")
async def restore_found(found_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    r = await EndpointInventory(db).set_ignored(current_user.org_id, found_id, False, current_user.id)
    await AuditService(db).log(current_user.org_id, current_user.id, "discovered_agent", found_id,
                               "found_agent_restored", r)
    return r
