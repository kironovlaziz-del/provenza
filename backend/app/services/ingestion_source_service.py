from typing import List, Optional

from fastapi import HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_api_key, hash_api_key
from app.models.ingestion_source import IngestionSource
from app.schemas.ingestion_source import IngestionSourceCreate, IngestionSourceUpdate


# DNS and proxy log files uploaded in the console (app/services/log_import.py)
UPLOAD_SOURCE_TYPE = "log_upload"


class IngestionSourceService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_source(
        self, org_id: int, created_by: int, data: IngestionSourceCreate
    ) -> tuple[IngestionSource, str]:
        raw_key = generate_api_key()
        source = IngestionSource(
            org_id=org_id,
            name=data.name,
            source_type=data.source_type,
            api_key_hash=hash_api_key(raw_key),
            enabled=True,
            created_by=created_by,
        )
        self.db.add(source)
        await self.db.commit()
        await self.db.refresh(source)
        # The raw key is never stored - this is the only moment it exists
        # outside the caller's hands.
        return source, raw_key

    async def upload_source(self, org_id: int, created_by: int) -> IngestionSource:
        """The source the console's log uploads are recorded under (Shadow AI
        -> Import logs): one per organization, made on the first upload. Its
        key is random and never shown - nothing can send with it."""
        from datetime import datetime, timezone

        found = (await self.db.execute(
            select(IngestionSource).where(IngestionSource.org_id == org_id,
                                          IngestionSource.source_type == UPLOAD_SOURCE_TYPE)
            .order_by(IngestionSource.id).limit(1)
        )).scalar_one_or_none()
        if found is None:
            found = IngestionSource(org_id=org_id, name="Log uploads", source_type=UPLOAD_SOURCE_TYPE,
                                    api_key_hash=hash_api_key(generate_api_key()), enabled=True,
                                    created_by=created_by)
            self.db.add(found)
        found.last_seen_at = datetime.now(timezone.utc)
        await self.db.commit()
        await self.db.refresh(found)
        return found

    async def list_sources(
        self, org_id: int, skip: int = 0, limit: int = 50
    ) -> tuple[List[IngestionSource], int]:
        base = select(IngestionSource).where(IngestionSource.org_id == org_id)
        total = await self.db.scalar(select(func.count()).select_from(base.subquery()))
        result = await self.db.execute(
            base.order_by(IngestionSource.created_at.desc()).offset(skip).limit(limit)
        )
        return list(result.scalars().all()), int(total or 0)

    async def _get(self, source_id: int, org_id: int) -> IngestionSource:
        result = await self.db.execute(
            select(IngestionSource).where(
                IngestionSource.id == source_id, IngestionSource.org_id == org_id
            )
        )
        source = result.scalar_one_or_none()
        if not source:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Ingestion source not found"
            )
        return source

    async def update_source(
        self, source_id: int, org_id: int, data: IngestionSourceUpdate
    ) -> IngestionSource:
        source = await self._get(source_id, org_id)
        for field, value in data.model_dump(exclude_unset=True).items():
            setattr(source, field, value)
        await self.db.commit()
        await self.db.refresh(source)
        return source

    async def revoke_source(self, source_id: int, org_id: int) -> IngestionSource:
        """Soft-revoke rather than delete: AITelemetryEvent rows reference
        this source by FK, and revoked keys should stay visible in the
        admin UI as a record of what existed and was cut off, not vanish."""
        source = await self._get(source_id, org_id)
        source.enabled = False
        await self.db.commit()
        await self.db.refresh(source)
        return source
