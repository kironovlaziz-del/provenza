# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.core.pagination import PaginationParams
from app.models.user import User, UserRole
from app.schemas.ai_system import (
    AISystemCreate, AISystemOut, AISystemUpdate, DataLinkCreate, RiskConfirm, StageChange,
)
from app.schemas.pagination import Page
from app.services.audit_service import AuditService
from app.services.inventory_service import InventoryService
from app.services.risk_classifier import (
    ANNEX_III, DOMAINS, MODIFIER_FLAGS, PROHIBITED_FLAGS, SAFETY_FLAGS, TIERS, TRANSPARENCY_FLAGS,
)

router = APIRouter()


async def _sync_and_log(db: AsyncSession, user: User) -> list:
    created = await InventoryService(db).sync(user.org_id)
    audit = AuditService(db)
    for item in created:
        await audit.log(user.org_id, user.id, "ai_system", item["id"], "discovered",
                        {"source_key": item["source_key"], "name": item["name"]})
    return created


@router.get("/meta")
async def inventory_meta(current_user: User = Depends(get_current_user)):
    """Vocabulary for the UI: domains, risk flags (grouped), tiers, stages, kinds."""
    return {
        "domains": [{"id": k, "label": v, "annex_iii": ANNEX_III.get(k)} for k, v in DOMAINS.items()],
        "flags": {
            "prohibited": PROHIBITED_FLAGS,
            "safety": SAFETY_FLAGS,
            "transparency": TRANSPARENCY_FLAGS,
            "modifiers": MODIFIER_FLAGS,
        },
        "tiers": list(TIERS),
        "stages": ["idea", "development", "validation", "production", "retired"],
        "kinds": ["agent", "llm_provider", "model", "rag_app", "shadow", "other"],
    }


@router.get("/summary")
async def inventory_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    await _sync_and_log(db, current_user)
    return await InventoryService(db).summary(current_user.org_id)


@router.post("/sync")
async def sync_inventory(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    created = await _sync_and_log(db, current_user)
    return {"created": len(created), "items": created}


@router.get("/", response_model=Page[AISystemOut])
async def list_systems(
    kind: Optional[str] = None,
    stage: Optional[str] = None,
    tier: Optional[str] = None,
    review_status: Optional[str] = None,
    q: Optional[str] = None,
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    await _sync_and_log(db, current_user)
    items, total = await InventoryService(db).list(
        current_user.org_id, kind=kind, stage=stage, tier=tier, review_status=review_status, q=q,
        skip=pagination.skip, limit=pagination.limit,
    )
    return Page(items=items, total=total, skip=pagination.skip, limit=pagination.limit)


@router.post("/", response_model=AISystemOut)
async def create_system(
    data: AISystemCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    service = InventoryService(db)
    system_id = await service.create(current_user.org_id, data)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "ai_system", system_id, "created",
        {"name": data.name, "kind": data.kind, "domain": data.domain, "risk_flags": data.risk_flags},
    )
    return await service.get(system_id, current_user.org_id)


@router.get("/{system_id}", response_model=AISystemOut)
async def get_system(
    system_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return await InventoryService(db).get(system_id, current_user.org_id)


@router.get("/{system_id}/metrics")
async def system_metrics(
    system_id: int,
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Activity and trust signals for one system over the last `days` days."""
    return await InventoryService(db).metrics(system_id, current_user.org_id, days)


@router.patch("/{system_id}", response_model=AISystemOut)
async def update_system(
    system_id: int,
    data: AISystemUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    service = InventoryService(db)
    changes, reset = await service.update(system_id, current_user.org_id, data)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "ai_system", system_id, "updated",
        {"changes": changes, "risk_confirmation_reset": reset},
    )
    return await service.get(system_id, current_user.org_id)


@router.post("/{system_id}/stage", response_model=AISystemOut)
async def change_stage(
    system_id: int,
    data: StageChange,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    service = InventoryService(db)
    previous = await service.set_stage(system_id, current_user.org_id, data.stage)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "ai_system", system_id, "stage_changed",
        {"from": previous, "to": data.stage},
    )
    return await service.get(system_id, current_user.org_id)


@router.post("/{system_id}/confirm-risk", response_model=AISystemOut)
async def confirm_risk(
    system_id: int,
    data: RiskConfirm,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.approver)),
):
    service = InventoryService(db)
    suggested = await service.confirm_risk(
        system_id, current_user.org_id, current_user.id, data.tier, data.justification,
    )
    await AuditService(db).log(
        current_user.org_id, current_user.id, "ai_system", system_id, "risk_confirmed",
        {"tier": data.tier, "suggested": suggested, "justification": data.justification},
    )
    return await service.get(system_id, current_user.org_id)


@router.post("/{system_id}/data-links", response_model=AISystemOut)
async def add_data_link(
    system_id: int,
    data: DataLinkCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    service = InventoryService(db)
    link_id = await service.add_data_link(system_id, current_user.org_id, data)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "ai_system", system_id, "data_link_added",
        {"link_id": link_id, **data.model_dump()},
    )
    return await service.get(system_id, current_user.org_id)


@router.delete("/{system_id}/data-links/{link_id}", response_model=AISystemOut)
async def remove_data_link(
    system_id: int,
    link_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    service = InventoryService(db)
    await service.remove_data_link(system_id, current_user.org_id, link_id)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "ai_system", system_id, "data_link_removed",
        {"link_id": link_id},
    )
    return await service.get(system_id, current_user.org_id)
