# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Blocked terms (services/blocked_terms.py).

    GET    /blocked-terms                    terms, categories, targets
    POST   /blocked-terms                    add a term (admin)
    PATCH  /blocked-terms/{id}               change it (admin)
    DELETE /blocked-terms/{id}               remove it - kept as deleted (admin)
    POST   /blocked-terms/categories         add a category (admin)
    PATCH  /blocked-terms/categories/{id}    rename, switch on/off (admin)
    DELETE /blocked-terms/categories/{id}    remove; its terms stay, uncategorized (admin)
    POST   /blocked-terms/test               a sample against the terms (and a draft)
    GET    /blocked-terms/export.csv         every term as CSV
    POST   /blocked-terms/import             add terms from CSV (admin; dry_run to preview)
"""

from typing import Optional

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
from app.core.errors import api_error
from app.core.term_match import MAX_TERM_LENGTH
from app.models.user import User, UserRole
from app.services import blocked_terms as bt
from app.services.audit_service import AuditService

router = APIRouter()
_admin = require_role(UserRole.admin)
# the list says what is watched for: not for every user
_reviewer = require_role(UserRole.admin, UserRole.approver)

_SCOPE = "^(org|agents|team|agent|policy)$"


class TermIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    term: str = Field(min_length=1, max_length=MAX_TERM_LENGTH)
    match: str = Field(default="word", pattern="^(word|substring)$")
    action: str = Field(default="block", pattern="^(block|monitor)$")
    scope: str = Field(default="org", pattern=_SCOPE)
    target_id: Optional[int] = None
    category_id: Optional[int] = None
    enabled: bool = True
    note: Optional[str] = Field(default=None, max_length=1000)


class TermPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    term: Optional[str] = Field(default=None, min_length=1, max_length=MAX_TERM_LENGTH)
    match: Optional[str] = Field(default=None, pattern="^(word|substring)$")
    action: Optional[str] = Field(default=None, pattern="^(block|monitor)$")
    scope: Optional[str] = Field(default=None, pattern=_SCOPE)
    target_id: Optional[int] = None
    category_id: Optional[int] = None
    enabled: Optional[bool] = None
    note: Optional[str] = Field(default=None, max_length=1000)


class CategoryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=1000)
    enabled: bool = True


class CategoryPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=1000)
    enabled: Optional[bool] = None


class DraftTerm(BaseModel):
    model_config = ConfigDict(extra="forbid")
    term: str = Field(min_length=1, max_length=MAX_TERM_LENGTH)
    match: str = Field(default="word", pattern="^(word|substring)$")
    action: str = Field(default="block", pattern="^(block|monitor)$")


class TestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sample: str = Field(max_length=20000)
    term: Optional[DraftTerm] = None


class ImportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    csv: str = Field(max_length=2_000_000)
    dry_run: bool = True


def _non_null(values: dict, keys) -> None:
    for k in keys:
        if k in values and values[k] is None:
            raise api_error(422, "terms.value_required", field=k)


@router.get("")
async def overview(db: AsyncSession = Depends(get_db), current_user: User = Depends(_reviewer)):
    return await bt.overview(db, current_user.org_id)


@router.post("", status_code=201)
async def create_term(data: TermIn, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    t = await bt.create_term(db, current_user.org_id, current_user.id, data.model_dump())
    await AuditService(db).log(current_user.org_id, current_user.id, "blocked_term", t.id, "created", bt.snapshot(t))
    return {"id": t.id, **bt.snapshot(t)}


@router.patch("/{term_id}")
async def update_term(term_id: int, data: TermPatch, db: AsyncSession = Depends(get_db),
                      current_user: User = Depends(_admin)):
    values = data.model_dump(exclude_unset=True)
    _non_null(values, ("term", "match", "action", "scope", "enabled"))
    before, t = await bt.update_term(db, current_user.org_id, current_user.id, term_id, values)
    after = bt.snapshot(t)
    await AuditService(db).log(current_user.org_id, current_user.id, "blocked_term", term_id, "updated", {
        "before": {k: v for k, v in before.items() if after[k] != v},
        "after": {k: v for k, v in after.items() if before[k] != v}})
    return {"id": t.id, **after}


@router.delete("/{term_id}")
async def delete_term(term_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    snap = await bt.delete_term(db, current_user.org_id, current_user.id, term_id)
    await AuditService(db).log(current_user.org_id, current_user.id, "blocked_term", term_id, "deleted", snap)
    return {"deleted": term_id}


@router.post("/categories", status_code=201)
async def create_category(data: CategoryIn, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    c = await bt.create_category(db, current_user.org_id, current_user.id, data.model_dump())
    await AuditService(db).log(current_user.org_id, current_user.id, "blocked_term_category", c.id, "created",
                               {"name": c.name, "enabled": c.enabled})
    return {"id": c.id, "name": c.name, "description": c.description, "enabled": c.enabled}


@router.patch("/categories/{category_id}")
async def update_category(category_id: int, data: CategoryPatch, db: AsyncSession = Depends(get_db),
                          current_user: User = Depends(_admin)):
    values = data.model_dump(exclude_unset=True)
    _non_null(values, ("name", "enabled"))
    before, c = await bt.update_category(db, current_user.org_id, category_id, values)
    after = {"name": c.name, "description": c.description, "enabled": c.enabled}
    await AuditService(db).log(current_user.org_id, current_user.id, "blocked_term_category", c.id, "updated",
                               {"before": before, "after": after})
    return {"id": c.id, **after}


@router.delete("/categories/{category_id}")
async def delete_category(category_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    snap = await bt.delete_category(db, current_user.org_id, category_id)
    await AuditService(db).log(current_user.org_id, current_user.id, "blocked_term_category", category_id,
                               "deleted", snap)
    return {"deleted": category_id, **snap}


@router.post("/test")
async def test(data: TestIn, db: AsyncSession = Depends(get_db), current_user: User = Depends(_reviewer)):
    """Nothing is stored or counted."""
    return await bt.test(db, current_user.org_id, data.sample, data.term.model_dump() if data.term else None)


@router.get("/export.csv")
async def export_csv(db: AsyncSession = Depends(get_db), current_user: User = Depends(_reviewer)):
    body = await bt.export_csv(db, current_user.org_id)
    return Response(content="\ufeff" + body, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="blocked-terms.csv"'})


@router.post("/import")
async def import_csv(data: ImportIn, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    out = await bt.import_csv(db, current_user.org_id, current_user.id, data.csv, data.dry_run)
    if not data.dry_run and out["added"]:
        await AuditService(db).log(current_user.org_id, current_user.id, "blocked_term", None, "imported",
                                   {"added": out["added"], "skipped": len(out["skipped"]),
                                    "errors": len(out["errors"])})
    return out
