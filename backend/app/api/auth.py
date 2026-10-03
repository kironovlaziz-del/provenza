from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import timedelta
from app.core.database import get_db
from app.core.errors import api_error
from app.core.security import verify_password, create_access_token
from app.core.config import settings
from app.core import rate_limit
from app.schemas.user import UserLogin, Token
from app.models.user import User
from app.models.organization import Organization

router = APIRouter()

# Login throttling: 10 attempts per 5 minutes from a single IP, and 5
# attempts per 5 minutes against a single account (organization + email).
# A successful login gives back its own IP attempt and clears that
# account's counter; it never clears the IP counter, so a valid password
# for one account cannot be used to reset the budget for guessing others.
LOGIN_IP_LIMIT = 10
LOGIN_EMAIL_LIMIT = 5
LOGIN_WINDOW_SECONDS = 300


@router.get("/config")
async def auth_config():
    """Public, unauthenticated: what the sign-in screens may offer."""
    return {"signup_enabled": settings.ALLOW_PUBLIC_SIGNUP}


def _account_key(org_slug: str, email: str) -> str:
    """Rate-limit key for one account, normalized exactly like the lookup
    below ("ACME ", " acme" and "acme" are the same organization, so they
    must share one counter)."""
    return f"{org_slug.strip().lower()}:{email.strip().lower()}"


@router.post("/login", response_model=Token)
async def login(
    user_data: UserLogin,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    # Throttle before hitting the DB, so brute-force attempts cannot be
    # used to amplify load on Postgres.
    account_key = _account_key(user_data.org_slug, user_data.email)
    rate_limit.enforce(
        request,
        scope="login",
        limit=LOGIN_IP_LIMIT,
        window_seconds=LOGIN_WINDOW_SECONDS,
    )
    rate_limit.enforce(
        request,
        scope="login",
        limit=LOGIN_EMAIL_LIMIT,
        window_seconds=LOGIN_WINDOW_SECONDS,
        extra_key=account_key,
    )

    # Resolve the organization first. A wrong slug and a wrong password
    # both return the same generic 401 so the response does not leak which
    # organizations exist.
    org_result = await db.execute(
        select(Organization).where(
            Organization.slug == user_data.org_slug.strip().lower()
        )
    )
    org = org_result.scalar_one_or_none()

    generic_error = api_error(
        status.HTTP_401_UNAUTHORIZED,
        "auth.invalid_credentials",
    )

    if not org:
        raise generic_error

    user_result = await db.execute(
        select(User).where(
            User.email == user_data.email,
            User.org_id == org.id,
        )
    )
    user = user_result.scalar_one_or_none()

    if not user or not verify_password(user_data.password, user.hashed_password):
        raise generic_error

    if user.status != "active":
        raise api_error(
            status.HTTP_403_FORBIDDEN,
            "auth.account_disabled",
            status=user.status,
        )

    # Successful login: this account's counter is cleared (a user who
    # mistyped a few times is not locked out), and this request's own IP
    # attempt is given back - the IP counter itself is never reset.
    rate_limit.reset_key(scope="login", extra_key=account_key)
    rate_limit.refund(request, scope="login")

    access_token = create_access_token(
        data={"sub": str(user.id)},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": access_token, "token_type": "bearer"}
