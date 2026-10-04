"""
Notification Service.

Two entry points into the same send logic:
  - notify()      - async, for use from FastAPI request handlers/services.
  - notify_sync() - sync, for use from Celery workers,
                    which has no event loop to await into.

Email is optional: if settings.SMTP_HOST is empty, email channels are
skipped with a log line rather than failing loudly - most self-hosted
installs won't have SMTP configured on day one, and that shouldn't block
webhook notifications or the rest of the platform.
"""

import asyncio
import logging
import smtplib
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

import httpx

from app.core.outbound import OutboundBlocked, guarded_client
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.notification_channel import NotificationChannel
from app.schemas.notification_channel import NotificationChannelCreate, NotificationChannelUpdate

logger = logging.getLogger("notifications")


def _send_email(target: str, subject: str, message: str) -> None:
    if not settings.SMTP_HOST:
        logger.info("SMTP not configured - skipping email notification to %s", target)
        return
    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = target
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
            if settings.SMTP_USE_TLS:
                server.starttls()
            if settings.SMTP_USER:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_FROM, [target], msg.as_string())
    except Exception:
        logger.exception("Failed to send email notification to %s", target)


def _webhook_client() -> httpx.Client:
    # SSRF guard in the connection layer (core/outbound.py): the address is
    # resolved, checked and connected to in one step, so a host that
    # resolves to an internal address - or is repointed after creation,
    # DNS rebinding included - is refused.
    return guarded_client(timeout=10.0)


def _send_webhook(target: str, subject: str, message: str, metadata: Optional[Dict[str, Any]]) -> None:
    try:
        with _webhook_client() as client:
            client.post(target, json={"subject": subject, "message": message, "metadata": metadata or {}})
    except httpx.ConnectError as exc:
        if isinstance(exc.__cause__, OutboundBlocked) or "Outbound connection refused" in str(exc):
            logger.warning("Refusing webhook to unsafe target %s (SSRF guard)", target)
        else:
            logger.exception("Failed to send webhook notification to %s", target)
    except httpx.HTTPError:
        logger.exception("Failed to send webhook notification to %s", target)


def _dispatch(channel: NotificationChannel, subject: str, message: str, metadata: Optional[Dict[str, Any]]) -> None:
    if not channel.enabled:
        return
    if channel.channel_type == "email":
        _send_email(channel.target, subject, message)
    elif channel.channel_type == "webhook":
        _send_webhook(channel.target, subject, message, metadata)


async def notify(
    db: AsyncSession,
    org_id: int,
    event_type: str,
    subject: str,
    message: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    result = await db.execute(
        select(NotificationChannel).where(
            NotificationChannel.org_id == org_id,
            NotificationChannel.enabled == True,  # noqa: E712
        )
    )
    channels = list(result.scalars().all())
    if not channels:
        return

    # Defensive deduplication: even with the DB constraint, old data or
    # a race could leave two identical channels. Only dispatch each
    # (channel_type, target) pair once per event.
    seen: set[tuple[str, str]] = set()
    unique: list[NotificationChannel] = []
    for ch in channels:
        key = (ch.channel_type, ch.target)
        if key in seen:
            continue
        seen.add(key)
        unique.append(ch)

    # SMTP and webhook delivery are blocking calls. Running them on the
    # event loop would freeze every other coroutine for the duration of
    # the network round-trip. Fan out to a thread pool instead.
    tasks = [
        asyncio.to_thread(_dispatch, channel, subject, message, metadata)
        for channel in unique
        if event_type in (channel.events_json or [])
    ]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


def notify_sync(
    db: Session,
    org_id: int,
    event_type: str,
    subject: str,
    message: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    channels = (
        db.query(NotificationChannel)
        .filter(NotificationChannel.org_id == org_id, NotificationChannel.enabled == True)  # noqa: E712
        .all()
    )
    seen: set[tuple[str, str]] = set()
    for channel in channels:
        key = (channel.channel_type, channel.target)
        if key in seen:
            continue
        seen.add(key)
        if event_type in (channel.events_json or []):
            _dispatch(channel, subject, message, metadata)


class NotificationChannelService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_channel(
        self, org_id: int, created_by: int, data: NotificationChannelCreate
    ) -> NotificationChannel:
        # Reject duplicates at the application layer so the user gets a
        # clear message instead of an IntegrityError from the DB.
        existing = await self.db.execute(
            select(NotificationChannel).where(
                NotificationChannel.org_id == org_id,
                NotificationChannel.channel_type == data.channel_type,
                NotificationChannel.target == data.target,
            )
        )
        if existing.scalar_one_or_none():
            from fastapi import HTTPException, status

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"A {data.channel_type} channel for '{data.target}' "
                    "already exists in this organization."
                ),
            )

        channel = NotificationChannel(
            org_id=org_id,
            channel_type=data.channel_type,
            target=data.target,
            events_json=data.events,
            enabled=data.enabled,
            created_by=created_by,
        )
        self.db.add(channel)
        await self.db.commit()
        await self.db.refresh(channel)
        return channel

    async def list_channels(
        self, org_id: int, skip: int = 0, limit: int = 50
    ) -> "tuple[List[NotificationChannel], int]":
        from sqlalchemy import func

        base = select(NotificationChannel).where(NotificationChannel.org_id == org_id)
        total = await self.db.scalar(
            select(func.count()).select_from(base.subquery())
        )
        result = await self.db.execute(
            base.order_by(NotificationChannel.id).offset(skip).limit(limit)
        )
        return list(result.scalars().all()), int(total or 0)

    async def get_channel(self, channel_id: int, org_id: int) -> NotificationChannel:
        from fastapi import HTTPException, status

        result = await self.db.execute(
            select(NotificationChannel).where(
                NotificationChannel.id == channel_id, NotificationChannel.org_id == org_id
            )
        )
        channel = result.scalar_one_or_none()
        if not channel:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification channel not found")
        return channel

    async def update_channel(
        self, channel_id: int, org_id: int, data: NotificationChannelUpdate
    ) -> NotificationChannel:
        channel = await self.get_channel(channel_id, org_id)
        if data.target is not None:
            channel.target = data.target
        if data.events is not None:
            channel.events_json = data.events
        if data.enabled is not None:
            channel.enabled = data.enabled
        await self.db.commit()
        await self.db.refresh(channel)
        return channel

    async def delete_channel(self, channel_id: int, org_id: int) -> None:
        channel = await self.get_channel(channel_id, org_id)
        await self.db.delete(channel)
        await self.db.commit()

    async def send_test(self, channel_id: int, org_id: int) -> None:
        channel = await self.get_channel(channel_id, org_id)
        _dispatch(
            channel,
            "AI Control Tower - test notification",
            "If you can see this, the notification channel is configured correctly.",
            {"test": True},
        )
