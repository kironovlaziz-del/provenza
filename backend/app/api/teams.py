# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Teams and role templates (services/teams.py)."""

from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.user import User, UserRole
from app.schemas.team import RoleIn, RoleUpdate, TeamIn, TeamUpdate
from app.services import teams
from app.services.audit_service import AuditService

router = APIRouter()
_admin = require_role(UserRole.admin)


@router.get("/")
async def list_teams(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return await teams.list_teams(db, current_user.org_id)


@router.post("/")
async def create_team(data: TeamIn, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    t = await teams.create_team(db, current_user.org_id, current_user.id, data.model_dump())
    await AuditService(db).log(current_user.org_id, current_user.id, "team", t.id, "created", teams.team_out(t))
    return teams.team_out(t)


# roles before /{team_id}: a literal path segment must win over the parameter
@router.get("/roles")
async def list_roles(team_id: Optional[int] = None, db: AsyncSession = Depends(get_db),
                     current_user: User = Depends(get_current_user)):
    return await teams.list_roles(db, current_user.org_id, team_id)


@router.post("/roles")
async def create_role(data: RoleIn, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    r = await teams.create_role(db, current_user.org_id, current_user.id, data.model_dump())
    await AuditService(db).log(current_user.org_id, current_user.id, "role_template", r.id, "created", teams.role_out(r))
    return teams.role_out(r)


@router.patch("/roles/{role_id}")
async def update_role(role_id: int, data: RoleUpdate, db: AsyncSession = Depends(get_db),
                      current_user: User = Depends(_admin)):
    changes = data.model_dump(exclude_unset=True)
    r, changed = await teams.update_role(db, current_user.org_id, role_id, changes)
    await AuditService(db).log(current_user.org_id, current_user.id, "role_template", r.id, "updated",
                               {"changes": changes, "agents_updated": changed})
    return {**teams.role_out(r), "agents_updated": changed}


@router.delete("/roles/{role_id}")
async def delete_role(role_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    snapshot = await teams.delete_role(db, current_user.org_id, role_id)
    await AuditService(db).log(current_user.org_id, current_user.id, "role_template", role_id, "deleted", snapshot)
    return {"deleted": role_id}


@router.patch("/{team_id}")
async def update_team(team_id: int, data: TeamUpdate, db: AsyncSession = Depends(get_db),
                      current_user: User = Depends(_admin)):
    changes = data.model_dump(exclude_unset=True)
    t = await teams.update_team(db, current_user.org_id, team_id, changes)
    await AuditService(db).log(current_user.org_id, current_user.id, "team", t.id, "updated", changes)
    return teams.team_out(t)


@router.delete("/{team_id}")
async def delete_team(team_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    snapshot = await teams.delete_team(db, current_user.org_id, team_id)
    await AuditService(db).log(current_user.org_id, current_user.id, "team", team_id, "deleted", snapshot)
    return {"deleted": team_id}
