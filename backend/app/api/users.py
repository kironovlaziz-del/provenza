from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
from app.core import rate_limit
from app.core.config import settings
from app.core.database import get_db
from app.core.errors import api_error
from app.core.pagination import PaginationParams
from app.core.security import get_password_hash, verify_password
from app.schemas.pagination import Page
from app.schemas.user import (
    UserCreate,
    UserInvite,
    UserOut,
    UserRoleUpdate,
    UserStatusUpdate,
    PasswordChange,
)
from app.models.user import User, UserRole
from app.models.organization import Organization
from app.services.audit_service import AuditService
from app.api.deps import get_current_user, require_role

router = APIRouter()

# Self-service sign-up throttle (only reachable with ALLOW_PUBLIC_SIGNUP).
SIGNUP_IP_LIMIT = 5
SIGNUP_WINDOW_SECONDS = 3600


@router.post("/register", response_model=UserOut)
async def register(
    user_data: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Self-service sign-up: creates a new organization and its first user,
    always an admin regardless of the role sent in the payload.

    Disabled unless ALLOW_PUBLIC_SIGNUP is set (see core/config.py); when
    enabled it is throttled per client IP.
    """
    if not settings.ALLOW_PUBLIC_SIGNUP:
        raise api_error(status.HTTP_403_FORBIDDEN, "auth.signup_disabled")
    rate_limit.enforce(
        request,
        scope="signup",
        limit=SIGNUP_IP_LIMIT,
        window_seconds=SIGNUP_WINDOW_SECONDS,
    )

    # The slug must be free - it is the org's public identifier.
    result = await db.execute(
        select(Organization).where(Organization.slug == user_data.org_slug)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Organization slug '{user_data.org_slug}' is already taken",
        )

    org = Organization(name=user_data.org_name, slug=user_data.org_slug)
    db.add(org)
    await db.flush()

    user = User(
        org_id=org.id,
        email=user_data.email,
        name=user_data.name,
        hashed_password=get_password_hash(user_data.password),
        role=UserRole.admin.value,
        status="active",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    await AuditService(db).log(
        org.id, user.id, "organization", org.id, "created", {"org_name": org.name}
    )
    await AuditService(db).log(
        org.id, user.id, "user", user.id, "registered",
        {"email": user.email, "role": user.role},
    )

    return user


@router.get("/me", response_model=UserOut)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/me/password")
async def change_my_password(
    data: PasswordChange,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not verify_password(data.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    current_user.hashed_password = get_password_hash(data.new_password)
    await db.commit()
    await AuditService(db).log(
        current_user.org_id, current_user.id, "user", current_user.id,
        "password_changed", None,
    )
    return {"status": "ok"}


@router.get("/", response_model=Page[UserOut])
async def list_users(
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    from sqlalchemy import func

    base = select(User).where(User.org_id == current_user.org_id)
    total = await db.scalar(select(func.count()).select_from(base.subquery()))
    result = await db.execute(
        base.order_by(User.created_at.asc()).offset(pagination.skip).limit(pagination.limit)
    )
    return Page(
        items=list(result.scalars().all()),
        total=int(total or 0),
        skip=pagination.skip,
        limit=pagination.limit,
    )


@router.post("/invite", response_model=UserOut)
async def invite_user(
    data: UserInvite,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    # Email only needs to be unique within this organization.
    result = await db.execute(
        select(User).where(
            User.email == data.email,
            User.org_id == current_user.org_id,
        )
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This email is already a member of your organization",
        )

    user = User(
        org_id=current_user.org_id,
        email=data.email,
        name=data.name,
        hashed_password=get_password_hash(data.password),
        role=data.role.value,
        status="active",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    await AuditService(db).log(
        current_user.org_id, current_user.id, "user", user.id, "invited",
        {"email": user.email, "role": user.role},
    )
    return user


@router.put("/{user_id}/role", response_model=UserOut)
async def update_user_role(
    user_id: int,
    data: UserRoleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    result = await db.execute(
        select(User).where(
            User.id == user_id,
            User.org_id == current_user.org_id,
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # An admin cannot demote themselves - that would leave the org without
    # an admin if they are the last one.
    if user.id == current_user.id and data.role != UserRole.admin:
        admin_count = await db.scalar(
            select(User.id)
            .where(User.org_id == current_user.org_id, User.role == UserRole.admin.value)
            .limit(2)
        )
        # Simplistic check: if the only admin in the org is me, refuse.
        result = await db.execute(
            select(User).where(
                User.org_id == current_user.org_id,
                User.role == UserRole.admin.value,
            )
        )
        admins = list(result.scalars().all())
        if len(admins) == 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot demote the last admin of the organization.",
            )

    previous_role = user.role
    user.role = data.role.value
    await db.commit()
    await db.refresh(user)

    await AuditService(db).log(
        current_user.org_id, current_user.id, "user", user.id, "role_changed",
        {"from": previous_role, "to": user.role},
    )
    return user


@router.put("/{user_id}/status", response_model=UserOut)
async def update_user_status(
    user_id: int,
    data: UserStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    result = await db.execute(
        select(User).where(
            User.id == user_id,
            User.org_id == current_user.org_id,
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    if user.id == current_user.id and data.status != "active":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account.",
        )

    previous_status = user.status
    user.status = data.status
    await db.commit()
    await db.refresh(user)

    await AuditService(db).log(
        current_user.org_id, current_user.id, "user", user.id, "status_changed",
        {"from": previous_status, "to": user.status},
    )
    return user


