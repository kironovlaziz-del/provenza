from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from app.core.database import get_db
from app.core.pagination import PaginationParams
from app.schemas.use_case import UseCaseCreate, UseCaseOut, UseCaseUpdate
from app.schemas.pagination import Page
from app.services.use_case_service import UseCaseService
from app.services.audit_service import AuditService
from app.models.user import User, UserRole
from app.api.deps import get_current_user, require_role

router = APIRouter()

@router.post("/", response_model=UseCaseOut)
async def create_use_case(
    data: UseCaseCreate,
    db: AsyncSession = Depends(get_db),
    # A use case decides which policy version (and so which approval and
    # firewall rules) governs its requests - an admin decision, like the
    # policy itself.
    current_user: User = Depends(require_role(UserRole.admin))
):
    service = UseCaseService(db)
    use_case = await service.create_use_case(current_user.org_id, data)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "use_case", use_case.id, "created",
        {"name": use_case.name, "risk_level": use_case.risk_level},
    )
    return use_case

@router.get("/", response_model=Page[UseCaseOut])
async def list_use_cases(
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = UseCaseService(db)
    items, total = await service.list_use_cases(
        current_user.org_id, skip=pagination.skip, limit=pagination.limit
    )
    return Page(items=items, total=total, skip=pagination.skip, limit=pagination.limit)

@router.get("/{use_case_id}", response_model=UseCaseOut)
async def get_use_case(
    use_case_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    service = UseCaseService(db)
    return await service.get_use_case(use_case_id, current_user.org_id)

@router.put("/{use_case_id}", response_model=UseCaseOut)
async def update_use_case(
    use_case_id: int,
    data: UseCaseUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin))
):
    service = UseCaseService(db)
    use_case = await service.update_use_case(use_case_id, current_user.org_id, data)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "use_case", use_case.id, "updated",
        data.model_dump(exclude_unset=True),
    )
    return use_case
