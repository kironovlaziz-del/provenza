from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from app.core.database import get_db
from app.core.pagination import PaginationParams
from app.schemas.notification_channel import (
    NotificationChannelCreate,
    NotificationChannelUpdate,
    NotificationChannelOut,
    EVENT_TYPES,
)
from app.schemas.pagination import Page
from app.services.notification_service import NotificationChannelService
from app.services.audit_service import AuditService
from app.models.user import User
from app.api.deps import require_role
from app.models.user import UserRole

router = APIRouter()


@router.get("/event-types")
async def list_event_types():
    return {"event_types": EVENT_TYPES}


@router.post("/", response_model=NotificationChannelOut)
async def create_channel(
    data: NotificationChannelCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    service = NotificationChannelService(db)
    channel = await service.create_channel(current_user.org_id, current_user.id, data)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "notification_channel", channel.id, "created",
        {"channel_type": channel.channel_type, "events": channel.events_json},
    )
    return channel


@router.get("/", response_model=Page[NotificationChannelOut])
async def list_channels(
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),  # targets are webhook URLs: secrets
):
    service = NotificationChannelService(db)
    items, total = await service.list_channels(
        current_user.org_id, skip=pagination.skip, limit=pagination.limit
    )
    return Page(items=items, total=total, skip=pagination.skip, limit=pagination.limit)


@router.put("/{channel_id}", response_model=NotificationChannelOut)
async def update_channel(
    channel_id: int,
    data: NotificationChannelUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    service = NotificationChannelService(db)
    channel = await service.update_channel(channel_id, current_user.org_id, data)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "notification_channel", channel.id, "updated",
        data.model_dump(exclude_unset=True),
    )
    return channel


@router.delete("/{channel_id}")
async def delete_channel(
    channel_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    service = NotificationChannelService(db)
    await service.delete_channel(channel_id, current_user.org_id)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "notification_channel", channel_id, "deleted", None,
    )
    return {"status": "deleted"}


@router.post("/{channel_id}/test")
async def test_channel(
    channel_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """Admins only: a test sends a real message to the channel's address."""
    service = NotificationChannelService(db)
    await service.send_test(channel_id, current_user.org_id)
    return {"status": "sent"}
