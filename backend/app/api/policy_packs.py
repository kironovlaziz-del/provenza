# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Rule packs (services/rule_packs.py), on the Policy hierarchy page.

    GET    /policy-packs                                 the built-in packs and the organization's own
    POST   /policy-packs                                 a new pack (admin)
    PUT    /policy-packs/{id}                            change an own pack (admin)
    DELETE /policy-packs/{id}                            delete an own pack (admin; levels keep what it set)
    POST   /policy-packs/preview                         what applying a pack to a level would change (admin)
    POST   /policy-packs/apply                           apply it (admin)
    GET    /policy-packs/applications                    what was applied where, and what was undone
    POST   /policy-packs/applications/{id}/preview-undo  what undoing would change (admin)
    POST   /policy-packs/applications/{id}/undo          undo it (admin)
"""

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core import policy_doc
from app.core.database import get_db
from app.models.user import User, UserRole
from app.services import rule_packs

router = APIRouter()
_admin = require_role(UserRole.admin)
_reviewer = require_role(UserRole.admin, UserRole.approver)


class PackIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=2000)
    kind: str = Field(pattern="^(profile|guard)$")
    level: str = Field(default="any", pattern="^(org|team|agent|any)$")
    yaml: str = Field(min_length=1, max_length=policy_doc.MAX_YAML_BYTES)


class TargetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pack: str = Field(max_length=120)
    scope: str = Field(pattern="^(org|team|agent)$")
    target_id: Optional[int] = None
    # the level's revision the admin saw in the preview
    revision: Optional[int] = Field(default=None, ge=0)


class UndoIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision: Optional[int] = Field(default=None, ge=0)
    # a profile's undo puts the old level back over changes made since
    confirm_edited: bool = False


@router.get("")
async def list_packs(db: AsyncSession = Depends(get_db), user: User = Depends(_reviewer)):
    return await rule_packs.list_packs(db, user.org_id)


@router.post("")
async def create_pack(data: PackIn, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    return await rule_packs.create(db, user.org_id, user.id, data.name, data.description, data.kind, data.level,
                                   data.yaml)


@router.put("/{pack_id}")
async def update_pack(pack_id: int, data: PackIn, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    return await rule_packs.update(db, user.org_id, user.id, pack_id, data.name, data.description, data.kind,
                                   data.level, data.yaml)


@router.delete("/{pack_id}")
async def delete_pack(pack_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    await rule_packs.delete(db, user.org_id, user.id, pack_id)
    return {"deleted": pack_id}


@router.post("/preview")
async def preview(data: TargetIn, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    return await rule_packs.preview(db, user.org_id, data.pack, data.scope, data.target_id)


@router.post("/apply")
async def apply(data: TargetIn, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    return await rule_packs.apply(db, user.org_id, user.id, data.pack, data.scope, data.target_id, data.revision)


@router.get("/applications")
async def applications(db: AsyncSession = Depends(get_db), user: User = Depends(_reviewer)):
    return await rule_packs.applications(db, user.org_id)


@router.post("/applications/{app_id}/preview-undo")
async def preview_undo(app_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    return await rule_packs.preview_undo(db, user.org_id, app_id)


@router.post("/applications/{app_id}/undo")
async def undo(app_id: int, data: UndoIn, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    return await rule_packs.undo(db, user.org_id, user.id, app_id, data.revision, data.confirm_edited)
