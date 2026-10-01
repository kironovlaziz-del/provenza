from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status
from typing import List
from app.models.ai_provider import AIProvider
from app.schemas.provider import ProviderCreate, ProviderUpdate
from app.core.crypto import encrypt_secret


class ProviderService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_provider(self, org_id: int, data: ProviderCreate) -> AIProvider:
        provider = AIProvider(
            org_id=org_id,
            name=data.name,
            type=data.type,
            status=data.status,
            sla=data.sla,
            risk_score=data.risk_score,
            base_url=data.base_url,
            default_model=data.default_model,
            api_key_encrypted=encrypt_secret(data.api_key, org_id=org_id) if data.api_key else None,
        )
        self.db.add(provider)
        await self.db.commit()
        await self.db.refresh(provider)
        return provider

    async def list_providers(
        self, org_id: int, skip: int = 0, limit: int = 50
    ) -> tuple[List[AIProvider], int]:
        from sqlalchemy import func

        base = select(AIProvider).where(AIProvider.org_id == org_id)
        total = await self.db.scalar(
            select(func.count()).select_from(base.subquery())
        )
        result = await self.db.execute(
            base.order_by(AIProvider.name).offset(skip).limit(limit)
        )
        return list(result.scalars().all()), int(total or 0)

    async def get_provider(self, provider_id: int, org_id: int) -> AIProvider:
        result = await self.db.execute(
            select(AIProvider).where(
                AIProvider.id == provider_id,
                AIProvider.org_id == org_id,
            )
        )
        provider = result.scalar_one_or_none()
        if not provider:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Provider not found",
            )
        return provider

    async def update_provider(
        self, provider_id: int, org_id: int, data: ProviderUpdate
    ) -> AIProvider:
        provider = await self.get_provider(provider_id, org_id)

        if data.name is not None:
            provider.name = data.name
        if data.type is not None and data.type != provider.type:
            # Changing the provider type invalidates any stored credential:
            # an OpenAI key sent to Anthropic will just 401. Force the admin
            # to enter a matching key when switching vendors.
            provider.type = data.type
            provider.api_key_encrypted = None
        elif data.type is not None:
            provider.type = data.type
        if data.status is not None:
            provider.status = data.status
        if data.sla is not None:
            provider.sla = data.sla
        if data.risk_score is not None:
            provider.risk_score = data.risk_score
        if data.base_url is not None:
            provider.base_url = data.base_url
        if data.default_model is not None:
            provider.default_model = data.default_model
        if data.api_key is not None:
            # empty string clears the stored credential, anything else replaces it
            provider.api_key_encrypted = encrypt_secret(data.api_key, org_id=provider.org_id) if data.api_key else None

        await self.db.commit()
        await self.db.refresh(provider)
        return provider
