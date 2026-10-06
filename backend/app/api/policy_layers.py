# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Hierarchical policies (services/hier_policy.py, core/policy_doc.py).

    GET  /policy-layers/overview                         which levels have rules
    GET  /policy-layers?scope=org|team|agent&target_id=  one level (empty when never written)
    PUT  /policy-layers                                  write a level (admin), YAML or document
    POST /policy-layers/preview                          a draft and the effective policy it gives
    GET  /policy-layers/effective?agent_id= | team_id=   the combined policy, with sources
    GET  /policy-layers/schema                           fields and how levels combine
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core import policy_doc
from app.core.database import get_db
from app.core.errors import api_error
from app.models.agent import Agent
from app.models.user import User, UserRole
from app.services import hier_policy
from app.services.audit_service import AuditService

router = APIRouter()
_admin = require_role(UserRole.admin)
# reading shows blocked terms and rules: what the firewall looks for is not for every user
_reviewer = require_role(UserRole.admin, UserRole.approver)


class LayerIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope: str = Field(pattern="^(org|team|agent)$")
    target_id: Optional[int] = None
    yaml: Optional[str] = Field(default=None, max_length=policy_doc.MAX_YAML_BYTES)
    document: Optional[Dict[str, Any]] = None
    # the revision the editor started from (0 = the level did not exist)
    revision: Optional[int] = Field(default=None, ge=0)


@router.get("/overview")
async def overview(db: AsyncSession = Depends(get_db), current_user: User = Depends(_reviewer)):
    return await hier_policy.overview(db, current_user.org_id)


@router.get("/schema")
async def schema(current_user: User = Depends(_reviewer)):
    return [{"field": f"{s}.{k}", "combine": mode, "type": typ, "range": list(b) if b else None}
            for (s, k), (mode, typ, b) in policy_doc.FIELDS.items()]


@router.get("")
async def get_layer(scope: str = Query(..., pattern="^(org|team|agent)$"), target_id: Optional[int] = None,
                    db: AsyncSession = Depends(get_db), current_user: User = Depends(_reviewer)):
    layer = await hier_policy.get_layer(db, current_user.org_id, scope, target_id)
    return hier_policy.layer_out(layer, scope, target_id)


@router.put("")
async def put_layer(data: LayerIn, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    layer, before = await hier_policy.save_layer(db, current_user.org_id, current_user.id, data.scope,
                                                 data.target_id, data.yaml, data.document, data.revision)
    out = hier_policy.layer_out(layer, data.scope, data.target_id)
    entity_id = data.target_id if data.scope != "org" else None
    await AuditService(db).log(current_user.org_id, current_user.id, f"policy_layer_{data.scope}", entity_id,
                               "updated" if before or layer.revision > 1 else "created",
                               {"revision": layer.revision, "before": before, "after": layer.document})
    return out


@router.post("/preview")
async def preview(data: LayerIn, db: AsyncSession = Depends(get_db), current_user: User = Depends(_reviewer)):
    return await hier_policy.preview(db, current_user.org_id, data.scope, data.target_id, data.yaml, data.document)


@router.get("/effective")
async def effective(agent_id: Optional[int] = None, team_id: Optional[int] = None,
                    db: AsyncSession = Depends(get_db), current_user: User = Depends(_reviewer)):
    agent = None
    if agent_id is not None:
        agent = (await db.execute(select(Agent).where(Agent.id == agent_id, Agent.org_id == current_user.org_id))
                 ).scalar_one_or_none()
        if agent is None:
            raise api_error(404, "agent.not_found")
    elif team_id is not None:
        await hier_policy._target(db, current_user.org_id, "team", team_id)
    levels = await hier_policy.chain(db, current_user.org_id, team_id=team_id, agent=agent)
    return {"levels": levels, "effective": hier_policy.combine(levels)}
