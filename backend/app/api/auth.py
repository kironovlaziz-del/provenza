from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import timedelta
from app.core.database import get_db
from app.core.errors import api_error
from app.core.security import verify_password, create_access_token
from app.core.config import settings
import jwt

from app.core import rate_limit, sessions
from app.schemas.user import LoginResult, MfaLogin, Token, UserLogin
from app.models.user import User
from app.models.organization import Organization
from app.services.audit_service import AuditService

router = APIRouter()

# Login throttling: 10 attempts per 5 minutes from a single IP, and 5
# attempts per 5 minutes against a single account (organization + email).
# A successful login gives back its own IP attempt and clears that
# account's counter; it never clears the IP counter, so a valid password
# for one account cannot be used to reset the budget for guessing others.
LOGIN_IP_LIMIT = 10
LOGIN_EMAIL_LIMIT = 5
LOGIN_WINDOW_SECONDS = 300
MFA_TOKEN_MINUTES = 5          # time to type the code after the password
MFA_IP_LIMIT = 20
MFA_USER_LIMIT = 5             # codes per user per window: 6 digits do not survive guessing
MFA_WINDOW_SECONDS = 300


@router.get("/config")
async def auth_config():
    """Public, unauthenticated: what the sign-in screens may offer."""
    return {
        "signup_enabled": settings.ALLOW_PUBLIC_SIGNUP,
        "features": {},
    }


def _account_key(org_slug: str, email: str) -> str:
    """Rate-limit key for one account, normalized exactly like the lookup
    below ("ACME ", " acme" and "acme" are the same organization, so they
    must share one counter)."""
    return f"{org_slug.strip().lower()}:{email.strip().lower()}"


@router.post("/login", response_model=LoginResult)
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
    if user.role != "admin":
        # SSO only: passwords are left to admins, the break-glass way in (app/services/sso.py)
        from app.services import sso

        cfg = await sso.get_settings(db, org.id)
        if cfg is not None and cfg.enabled and cfg.enforce:
            raise api_error(status.HTTP_403_FORBIDDEN, "auth.sso_required")

    # Successful login: this account's counter is cleared (a user who
    # mistyped a few times is not locked out), and this request's own IP
    # attempt is given back - the IP counter itself is never reset.
    rate_limit.reset_key(scope="login", extra_key=account_key)
    rate_limit.refund(request, scope="login")

    if user.totp_enabled:
        # half-way: the password was right, the second factor is still due
        mfa_token = create_access_token(data={"sub": str(user.id), "purpose": "mfa"},
                                        expires_delta=timedelta(minutes=MFA_TOKEN_MINUTES))
        return {"mfa_required": True, "mfa_token": mfa_token}

    access_token = create_access_token(
        data={"sub": str(user.id)},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/login/mfa", response_model=Token)
async def login_second_factor(data: MfaLogin, request: Request, db: AsyncSession = Depends(get_db)):
    """The second step of a two-factor sign-in: the token from /login and a
    code from the authenticator app (or a recovery code, used up)."""
    rate_limit.enforce(request, scope="mfa", limit=MFA_IP_LIMIT, window_seconds=MFA_WINDOW_SECONDS)
    invalid = api_error(status.HTTP_401_UNAUTHORIZED, "auth.mfa_invalid")
    try:
        payload = jwt.decode(data.mfa_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM],
                             options={"verify_sub": False})
        user_id = int(payload.get("sub"))
    except (jwt.PyJWTError, TypeError, ValueError):
        raise invalid
    if payload.get("purpose") != "mfa":
        raise invalid
    rate_limit.enforce(request, scope="mfa", limit=MFA_USER_LIMIT, window_seconds=MFA_WINDOW_SECONDS,
                       extra_key=f"user-{user_id}")
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None or user.status != "active" or not user.totp_enabled:
        raise invalid
    if user.sessions_valid_after is not None and payload.get("iat", 0) < user.sessions_valid_after.timestamp():
        raise invalid
    from app.services import mfa
    used = mfa.check_code(user, data.code)
    if used is None:
        raise invalid
    org_id, uid = user.org_id, user.id
    await db.commit()
    await AuditService(db).log(org_id, uid, "user", uid, "login_second_factor", {"with": used})
    access_token = create_access_token(data={"sub": str(uid)},
                                       expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request):
    """End this session: its token is refused from now on, not only forgotten
    by the browser (app/core/sessions.py). Always 204 - a token that is already
    invalid has nothing left to end."""
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        try:
            payload = jwt.decode(auth[7:].strip(), settings.SECRET_KEY, algorithms=[settings.ALGORITHM],
                                 options={"verify_sub": False})
        except jwt.PyJWTError:
            return None
        sessions.revoke(payload.get("jti"), payload.get("exp"))
    return None
