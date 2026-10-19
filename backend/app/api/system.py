# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""GET /api/v1/system/health - database, Redis, Celery workers and beat."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
from app.models.user import User, UserRole
from app.services import system_health

router = APIRouter()


def _roles(*names):
    return [getattr(UserRole, n) for n in names if hasattr(UserRole, n)]


@router.get("/health")
async def health(db: AsyncSession = Depends(get_db),
                 current_user: User = Depends(require_role(*_roles("admin", "approver")))):
    return await system_health.check(db)


@router.get("/setup")
async def setup_checklist(db: AsyncSession = Depends(get_db),
                          current_user: User = Depends(require_role(*_roles("admin")))):
    """What a new installation still needs, for the dashboard's setup checklist.
    `optional` items do not count against `complete`."""
    from sqlalchemy import func, select, text

    from app.models.agent import Agent
    from app.models.ai_provider import AIProvider
    from app.models.enrollment import AgentEnrollment
    from app.models.ingestion_source import IngestionSource
    from app.models.notification_channel import NotificationChannel
    from app.models.organization import Organization
    from app.models.policy_layer import PolicyLayer

    org_id = current_user.org_id

    async def count(model, *where) -> int:
        return int(await db.scalar(select(func.count()).select_from(model).where(model.org_id == org_id, *where)) or 0)

    mfa = await db.scalar(select(Organization.mfa_required).where(Organization.id == org_id))
    items = [
        {"key": "provider", "done": await count(AIProvider, AIProvider.api_key_encrypted.isnot(None)) > 0,
         "href": "/providers"},
        {"key": "policy", "done": await count(PolicyLayer, PolicyLayer.document != text("'{}'::jsonb")) > 0,
         "href": "/policy-hierarchy"},
        {"key": "agent", "done": await count(Agent) + await count(AgentEnrollment) > 0, "href": "/agents"},
        {"key": "notifications", "done": await count(NotificationChannel, NotificationChannel.enabled.is_(True)) > 0,
         "href": "/notifications"},
        {"key": "mfa", "done": (mfa or "none") != "none", "href": "/users"},
        {"key": "discovery", "done": await count(IngestionSource) > 0, "href": "/ingestion-sources", "optional": True},
    ]
    return {"items": items, "complete": all(i["done"] for i in items if not i.get("optional"))}
