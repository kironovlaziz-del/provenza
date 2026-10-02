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
