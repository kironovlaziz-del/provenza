# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
PII rules of the prompt firewall (services/pii_rules.py).

    GET    /pii                  built-in types, custom rules, NER status
    PUT    /pii/builtin          switch built-in types on/off, mask or block (admin)
    POST   /pii/rules            add a custom rule (admin)
    PATCH  /pii/rules/{id}       change it (admin)
    DELETE /pii/rules/{id}       remove it - kept as deleted for the record (admin)
    POST   /pii/test             a sample through the firewall, with a draft rule
"""

from typing import Dict, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core import pii_patterns as pp
from app.core.database import get_db
from app.core.errors import api_error
from app.models.user import User, UserRole
from app.services import pii_rules
from app.services.audit_service import AuditService

router = APIRouter()
_admin = require_role(UserRole.admin)
# the rules say what the firewall looks for: not for every user
_reviewer = require_role(UserRole.admin, UserRole.approver)

_ACTION = "^(mask|block)$"


class BuiltinType(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: Optional[bool] = None
    action: Optional[str] = Field(default=None, pattern=_ACTION)


class BuiltinIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    types: Dict[str, BuiltinType]
    revision: Optional[int] = Field(default=None, ge=0)


class RuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    label: str = Field(min_length=2, max_length=32)
    description: Optional[str] = Field(default=None, max_length=2000)
    pattern: str = Field(min_length=1, max_length=pp.MAX_PATTERN_LENGTH)
    ignore_case: bool = False
    action: str = Field(default="mask", pattern=_ACTION)
    enabled: bool = True


class RulePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    label: Optional[str] = Field(default=None, min_length=2, max_length=32)
    description: Optional[str] = Field(default=None, max_length=2000)
    pattern: Optional[str] = Field(default=None, min_length=1, max_length=pp.MAX_PATTERN_LENGTH)
    ignore_case: Optional[bool] = None
    action: Optional[str] = Field(default=None, pattern=_ACTION)
    enabled: Optional[bool] = None
    revision: Optional[int] = Field(default=None, ge=1)


class DraftRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: Optional[str] = Field(default=None, max_length=32)
    pattern: str = Field(min_length=1, max_length=pp.MAX_PATTERN_LENGTH)
    ignore_case: bool = False
    action: str = Field(default="mask", pattern=_ACTION)


class TestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sample: str = Field(max_length=pp.MAX_SAMPLE_LENGTH)
    rule: Optional[DraftRule] = None
    # editing a rule: test the draft instead of its saved version
    rule_id: Optional[int] = None


@router.get("")
async def overview(db: AsyncSession = Depends(get_db), current_user: User = Depends(_reviewer)):
    return await pii_rules.overview(db, current_user.org_id)


@router.put("/builtin")
async def save_builtin(data: BuiltinIn, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    types = {t: v.model_dump(exclude_none=True) for t, v in data.types.items()}
    changed = await pii_rules.save_builtin(db, current_user.org_id, current_user.id, types, data.revision)
    diff = {t: {"before": changed["before"][t], "after": changed["after"][t]}
            for t in changed["after"] if changed["before"][t] != changed["after"][t]}
    await AuditService(db).log(current_user.org_id, current_user.id, "pii_settings", None, "updated",
                               {"changes": diff, "revision": changed["revision"]})
    return await pii_rules.overview(db, current_user.org_id)


@router.post("/rules", status_code=201)
async def create_rule(data: RuleIn, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    r = await pii_rules.create_rule(db, current_user.org_id, current_user.id, data.model_dump())
    out = pii_rules.rule_out(r)
    await AuditService(db).log(current_user.org_id, current_user.id, "pii_rule", r.id, "created",
                               {k: out[k] for k in ("name", "label", "pattern", "ignore_case", "action", "enabled")})
    return out


@router.patch("/rules/{rule_id}")
async def update_rule(rule_id: int, data: RulePatch, db: AsyncSession = Depends(get_db),
                      current_user: User = Depends(_admin)):
    values = data.model_dump(exclude_unset=True)
    revision = values.pop("revision", None)
    nulls = [k for k, v in values.items() if v is None and k != "description"]
    if nulls:
        raise api_error(422, "pii.value_required", field=nulls[0])
    res = await pii_rules.update_rule(db, current_user.org_id, current_user.id, rule_id, values, revision)
    out = pii_rules.rule_out(res["rule"])
    keys = ("name", "label", "description", "pattern", "ignore_case", "action", "enabled")
    await AuditService(db).log(current_user.org_id, current_user.id, "pii_rule", rule_id, "updated", {
        "before": {k: res["before"][k] for k in keys if res["before"][k] != out[k]},
        "after": {k: out[k] for k in keys if res["before"][k] != out[k]},
    })
    return out


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(_admin)):
    snapshot = await pii_rules.delete_rule(db, current_user.org_id, current_user.id, rule_id)
    await AuditService(db).log(current_user.org_id, current_user.id, "pii_rule", rule_id, "deleted",
                               {k: snapshot[k] for k in ("name", "label", "pattern", "action")})
    return {"deleted": rule_id}


@router.post("/test")
async def test(data: TestIn, db: AsyncSession = Depends(get_db), current_user: User = Depends(_reviewer)):
    """Nothing is stored or logged: the sample only runs through the firewall."""
    draft = data.rule.model_dump() if data.rule else None
    return await pii_rules.test(db, current_user.org_id, data.sample, draft, data.rule_id)
