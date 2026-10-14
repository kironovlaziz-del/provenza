# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Admin API of the intent guardrail (services/guardrail.py): which connection
and model classify prompts, the categories, monitor or enforce, where it
applies - and a try-out on a sample prompt.
"""

import asyncio
from typing import List, Optional

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
from app.core.errors import api_error
from app.models.ai_provider import AIProvider
from app.models.guardrail import GuardrailSettings
from app.models.user import User, UserRole
from app.services import guardrail, provider_policy
from app.services.audit_service import AuditService

router = APIRouter()


class Category(BaseModel):
    code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,39}$")
    description: str = Field(min_length=3, max_length=300)


class GuardrailIn(BaseModel):
    enabled: bool = False
    provider_id: Optional[int] = None
    model: str = Field(default="llama-guard3", min_length=1, max_length=200)
    kind: str = Field(default="llama_guard", pattern="^(llama_guard|instruct)$")
    mode: str = Field(default="monitor", pattern="^(monitor|enforce)$")
    on_error: str = Field(default="allow", pattern="^(allow|block)$")
    categories: List[Category] = Field(default_factory=list, max_length=30)
    blocked_categories: List[str] = Field(default_factory=list, max_length=40)
    timeout_ms: int = Field(default=4000, ge=500, le=30000)
    surfaces: List[str] = Field(default_factory=lambda: list(guardrail.SURFACES), max_length=3)


class TryIn(BaseModel):
    text: str = Field(min_length=1, max_length=20000)


@router.get("/settings")
async def get_guardrail(db: AsyncSession = Depends(get_db), user: User = Depends(require_role(UserRole.admin))):
    return guardrail.settings_out(await guardrail.get_settings(db, user.org_id))


@router.put("/settings")
async def put_guardrail(data: GuardrailIn, db: AsyncSession = Depends(get_db),
                        user: User = Depends(require_role(UserRole.admin))):
    org_id, user_id = user.org_id, user.id
    if any(s not in guardrail.SURFACES for s in data.surfaces):
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "guardrail.bad_surface")
    codes = [c.code for c in data.categories]
    if len(set(codes)) != len(codes):
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "guardrail.duplicate_category")
    if data.kind == "instruct" and not codes:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "guardrail.categories_required")
    known = set(codes) if data.kind == "instruct" else set(guardrail.LLAMA_GUARD_CATEGORIES)
    blocked = [c.upper() for c in data.blocked_categories]
    if any(c not in known for c in blocked):
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "guardrail.unknown_category")
    if data.enabled and data.provider_id is None:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "guardrail.provider_required")
    if data.provider_id is not None:
        provider = await db.get(AIProvider, data.provider_id)
        if provider is None or provider.org_id != org_id:
            raise api_error(status.HTTP_404_NOT_FOUND, "guardrail.provider_not_found")
        if await provider_policy.self_hosted_required(db, org_id) and \
                provider_policy.cloud_reason(provider.type, provider.base_url):
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "guardrail.provider_not_self_hosted")
    row = await guardrail.get_settings(db, org_id)
    if row is None:
        row = GuardrailSettings(org_id=org_id)
        db.add(row)
    row.enabled, row.provider_id, row.model, row.kind = data.enabled, data.provider_id, data.model.strip(), data.kind
    row.mode, row.on_error, row.timeout_ms = data.mode, data.on_error, data.timeout_ms
    row.categories = [c.model_dump() for c in data.categories]
    row.blocked_categories, row.surfaces = blocked, list(dict.fromkeys(data.surfaces))
    row.updated_by = user_id
    await db.commit()
    out = guardrail.settings_out(row)
    await AuditService(db).log(org_id, user_id, "guardrail", org_id, "settings_updated",
                               {k: v for k, v in out.items()
                                if k not in ("llama_guard_categories", "example_categories")})
    return out


@router.post("/test")
async def try_guardrail(data: TryIn, db: AsyncSession = Depends(get_db),
                        user: User = Depends(require_role(UserRole.admin))):
    """The stored settings on a sample prompt - also while switched off. The
    sample goes through the Prompt Firewall first, like a real prompt."""
    from app.services import prompt_firewall

    if await guardrail.get_settings(db, user.org_id) is None:
        raise api_error(status.HTTP_409_CONFLICT, "guardrail.not_configured")
    masked = (await asyncio.to_thread(prompt_firewall.scan, data.text)).masked_text
    v = await guardrail.classify(db, user.org_id, masked, "test")
    if v is None:
        raise api_error(status.HTTP_409_CONFLICT, "guardrail.not_configured")
    return {"safe": v.safe, "categories": v.categories, "flags": v.flags, "block": v.block,
            "error": v.error, "reason": v.reason}
