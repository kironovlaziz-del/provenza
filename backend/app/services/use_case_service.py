from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status
from typing import List, Optional
from app.core.errors import api_error
from app.models.ai_policy import AIPolicy, AIPolicyVersion
from app.models.ai_use_case import AIUseCase
from app.models.user import User
from app.schemas.use_case import UseCaseCreate, UseCaseUpdate

class UseCaseService:
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def _check_references(self, org_id: int, owner_user_id: Optional[int],
                                policy_version_id: Optional[int]) -> None:
        """Ids sent by the client must point inside the caller's organization,
        and the linked policy version must be an approved one - it is what
        decides approval routing and the firewall's blocked terms."""
        if owner_user_id is not None:
            owner = await self.db.scalar(
                select(User.id).where(User.id == owner_user_id, User.org_id == org_id)
            )
            if owner is None:
                raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "use_case.owner_not_found")
        if policy_version_id is not None:
            version = await self.db.scalar(
                select(AIPolicyVersion)
                .join(AIPolicy, AIPolicy.id == AIPolicyVersion.policy_id)
                .where(AIPolicyVersion.id == policy_version_id, AIPolicy.org_id == org_id)
            )
            if version is None:
                raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "use_case.policy_version_not_found")
            if version.approved_at is None:
                raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "use_case.policy_version_not_approved")

    async def create_use_case(self, org_id: int, data: UseCaseCreate) -> AIUseCase:
        await self._check_references(org_id, data.owner_user_id, data.approved_policy_version_id)
        use_case = AIUseCase(
            org_id=org_id,
            name=data.name,
            owner_user_id=data.owner_user_id,
            risk_level=data.risk_level,
            allowed_providers_json=data.allowed_providers_json,
            approved_policy_version_id=data.approved_policy_version_id,
            status="active"
        )
        self.db.add(use_case)
        await self.db.commit()
        await self.db.refresh(use_case)
        return use_case
    
    async def get_use_case(self, use_case_id: int, org_id: int) -> AIUseCase:
        result = await self.db.execute(
            select(AIUseCase).where(
                AIUseCase.id == use_case_id,
                AIUseCase.org_id == org_id
            )
        )
        use_case = result.scalar_one_or_none()
        if not use_case:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Use case not found"
            )
        return use_case
    
    async def list_use_cases(
        self, org_id: int, skip: int = 0, limit: int = 50
    ) -> tuple[List[AIUseCase], int]:
        from sqlalchemy import func

        base = select(AIUseCase).where(AIUseCase.org_id == org_id)
        total = await self.db.scalar(
            select(func.count()).select_from(base.subquery())
        )
        result = await self.db.execute(
            base.order_by(AIUseCase.id).offset(skip).limit(limit)
        )
        return list(result.scalars().all()), int(total or 0)
    
    async def update_use_case(
        self, use_case_id: int, org_id: int, data: UseCaseUpdate
    ) -> AIUseCase:
        use_case = await self.get_use_case(use_case_id, org_id)
        await self._check_references(org_id, data.owner_user_id, data.approved_policy_version_id)

        if data.name is not None:
            use_case.name = data.name
        if data.owner_user_id is not None:
            use_case.owner_user_id = data.owner_user_id
        if data.risk_level is not None:
            use_case.risk_level = data.risk_level
        if data.allowed_providers_json is not None:
            use_case.allowed_providers_json = data.allowed_providers_json
        if data.approved_policy_version_id is not None:
            use_case.approved_policy_version_id = data.approved_policy_version_id
        if data.status is not None:
            use_case.status = data.status
        
        await self.db.commit()
        await self.db.refresh(use_case)
        return use_case

