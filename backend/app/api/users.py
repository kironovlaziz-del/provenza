from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta, timezone
from typing import List
from app.core import rate_limit
from app.core.config import settings
from app.core.database import get_db
from app.core.errors import api_error
from app.core.pagination import PaginationParams
from app.core.security import create_access_token, get_password_hash, verify_password
from app.schemas.pagination import Page
from app.schemas.user import (
    MeOut,
    UserCreate,
    UserInvite,
    UserOut,
    UserRoleUpdate,
    UserStatusUpdate,
    MfaCode,
    MfaDisable,
    MfaPolicy,
    PasswordChange,
)
from app.models.user import User, UserRole
from app.models.organization import Organization
from app.services import mfa
from app.services.audit_service import AuditService
from app.api.deps import get_current_user, is_operator, require_role

router = APIRouter()

# Self-service sign-up throttle (only reachable with ALLOW_PUBLIC_SIGNUP).
SIGNUP_IP_LIMIT = 5
PASSWORD_CHANGE_LIMIT = 5           # attempts per user
PASSWORD_CHANGE_WINDOW = 900        # seconds
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


@router.get("/me", response_model=MeOut)
async def get_me(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    me = MeOut.model_validate(current_user)
    me.is_operator = await is_operator(db, current_user)
    return me


@router.post("/me/password")
async def change_my_password(
    data: PasswordChange,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Every other session of the user ends with the old password (a stolen
    token stops working); this one continues with the token returned."""
    rate_limit.enforce(request, scope="password_change", limit=PASSWORD_CHANGE_LIMIT,
                       window_seconds=PASSWORD_CHANGE_WINDOW, extra_key=f"user-{current_user.id}")
    if not verify_password(data.current_password, current_user.hashed_password):
        raise api_error(status.HTTP_400_BAD_REQUEST, "user.current_password_wrong")
    current_user.hashed_password = get_password_hash(data.new_password)
    current_user.sessions_valid_after = datetime.now(timezone.utc)
    user_id = current_user.id
    await db.commit()
    await AuditService(db).log(
        current_user.org_id, user_id, "user", user_id,
        "password_changed", {"other_sessions": "ended"},
    )
    token = create_access_token(data={"sub": str(user_id)},
                                expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"status": "ok", "access_token": token, "token_type": "bearer"}


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
    if data.status == "disabled" and previous_status != "disabled":
        # a person leaves: their sessions end, their agents lose their keys (services/offboarding.py)
        from app.services.offboarding import offboard

        await offboard(db, user, actor_id=current_user.id, via="admin")
        await db.refresh(user)
        return user
    user.status = data.status
    await db.commit()
    await db.refresh(user)

    await AuditService(db).log(
        current_user.org_id, current_user.id, "user", user.id, "status_changed",
        {"from": previous_status, "to": user.status},
    )
    return user




# ---------------------------------------------------------------- two-factor sign-in (app/services/mfa.py)

@router.get("/me/mfa")
async def my_mfa(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return {"enabled": bool(current_user.totp_enabled), "required": await mfa.required_for(db, current_user),
            "recovery_codes_left": len(current_user.mfa_recovery_hashes or []),
            "enabled_at": current_user.mfa_enabled_at}


@router.post("/me/mfa/setup")
async def mfa_setup(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """A new secret for the authenticator app (shown now, confirmed by /enable)."""
    return await mfa.start_setup(db, current_user)


@router.post("/me/mfa/enable")
async def mfa_enable(data: MfaCode, request: Request, db: AsyncSession = Depends(get_db),
                     current_user: User = Depends(get_current_user)):
    rate_limit.enforce(request, scope="mfa_enable", limit=10, window_seconds=300, extra_key=f"user-{current_user.id}")
    org_id, user_id = current_user.org_id, current_user.id
    codes = await mfa.enable(db, current_user, data.code)
    await AuditService(db).log(org_id, user_id, "user", user_id, "mfa_enabled", None)
    return {"recovery_codes": codes}


@router.post("/me/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_disable(data: MfaDisable, request: Request, db: AsyncSession = Depends(get_db),
                      current_user: User = Depends(get_current_user)):
    rate_limit.enforce(request, scope="mfa_disable", limit=5, window_seconds=900, extra_key=f"user-{current_user.id}")
    org_id, user_id = current_user.org_id, current_user.id
    await mfa.disable(db, current_user, data.password, data.code)
    await AuditService(db).log(org_id, user_id, "user", user_id, "mfa_disabled", None)


@router.post("/me/mfa/recovery-codes")
async def mfa_recovery_codes(data: MfaCode, request: Request, db: AsyncSession = Depends(get_db),
                             current_user: User = Depends(get_current_user)):
    rate_limit.enforce(request, scope="mfa_codes", limit=5, window_seconds=900, extra_key=f"user-{current_user.id}")
    org_id, user_id = current_user.org_id, current_user.id
    codes = await mfa.new_recovery_codes(db, current_user, data.code)
    await AuditService(db).log(org_id, user_id, "user", user_id, "mfa_recovery_codes_renewed", None)
    return {"recovery_codes": codes}


@router.get("/mfa-policy", response_model=MfaPolicy)
async def get_mfa_policy(db: AsyncSession = Depends(get_db),
                         current_user: User = Depends(require_role(UserRole.admin))):
    return {"mfa_required": await mfa.org_policy(db, current_user.org_id)}


@router.put("/mfa-policy", response_model=MfaPolicy)
async def set_mfa_policy(data: MfaPolicy, db: AsyncSession = Depends(get_db),
                         current_user: User = Depends(require_role(UserRole.admin))):
    """Who must sign in with a second factor. Users it applies to who have not
    enrolled can do nothing but enroll until they do."""
    org_id, user_id = current_user.org_id, current_user.id
    if mfa.policy_applies(data.mfa_required, current_user.role) and not current_user.totp_enabled:
        # it would hold the admin who sets it to enrolling first: enroll, then require
        raise api_error(status.HTTP_409_CONFLICT, "mfa.enroll_first")
    org = await db.get(Organization, org_id)
    before = mfa.policy_name(org.mfa_required)
    org.mfa_required = data.mfa_required
    await db.commit()
    await AuditService(db).log(org_id, user_id, "organization", org_id, "mfa_policy_changed",
                               {"before": before, "after": mfa.policy_name(data.mfa_required)})
    return {"mfa_required": data.mfa_required}


@router.post("/{user_id}/mfa/reset", response_model=UserOut)
async def reset_user_mfa(user_id: int, db: AsyncSession = Depends(get_db),
                         current_user: User = Depends(require_role(UserRole.admin))):
    """For a lost device: the user's second factor is removed and their
    sessions end; they enroll again at their next sign-in."""
    org_id, admin_id = current_user.org_id, current_user.id
    target = (await db.execute(select(User).where(User.id == user_id, User.org_id == org_id))).scalar_one_or_none()
    if target is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "user.not_found")
    mfa.reset(target)
    await db.commit()
    await AuditService(db).log(org_id, admin_id, "user", user_id, "mfa_reset", {"by": admin_id})
    await db.refresh(target)
    return target
