from typing import Optional
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone
from app.core.database import get_db
from app.core.config import settings
from app.core.errors import api_error
from app.core.security import hash_api_key
from app.models.user import User, UserRole
from app.models.ingestion_source import IngestionSource

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
# auto_error=False: a request may authenticate with an agent key instead
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme_optional),
    x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key"),
    db: AsyncSession = Depends(get_db),
) -> User:
    """A user session (Bearer JWT) or an agent (X-Agent-Key). An agent is
    accepted only on agent-acting endpoints, only as itself, and runs on
    behalf of its accountable human - see app/services/agent_identity.py."""
    from app.services.agent_identity import authenticate_agent_request, enforce_user_session_policy

    if x_agent_key:
        return await authenticate_agent_request(request, db, x_agent_key)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="auth.invalid_token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = await _user_from_token(token, db)
    await enforce_user_session_policy(request, db, user)
    return user


async def _user_from_token(token: str, db: AsyncSession) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="auth.invalid_token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == int(user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise credentials_exception

    # A user whose status has been flipped to anything other than "active"
    # is treated as deactivated: their existing JWT stops working even if
    # it has not expired yet.
    if user.status != "active":
        raise api_error(
            status.HTTP_403_FORBIDDEN,
            "auth.account_disabled",
            status=user.status,
        )

    return user


def require_role(*allowed: UserRole):
    """
    Dependency factory for role-based access control.

    Usage:
        @router.post("/...")
        async def endpoint(
            current_user: User = Depends(require_role(UserRole.admin)),
        ): ...

    The User.role column is a plain VARCHAR (see migration
    c3d5e7f9a1b4) so comparison is done against the .value of each role.
    """
    allowed_values = [r.value for r in allowed]

    async def checker(request: Request, current_user: User = Depends(get_current_user)) -> User:
        # an agent key never carries a human role
        if getattr(request.state, "agent", None) is not None:
            raise api_error(
                status.HTTP_403_FORBIDDEN,
                "rbac.insufficient_role",
                allowed=allowed_values,
            )
        if current_user.role not in allowed_values:
            raise api_error(
                status.HTTP_403_FORBIDDEN,
                "rbac.insufficient_role",
                allowed=allowed_values,
            )
        return current_user

    return checker


async def get_ingestion_source(
    x_ingestion_key: str = Header(..., alias="X-Ingestion-Key"),
    db: AsyncSession = Depends(get_db),
) -> IngestionSource:
    """
    Auth dependency for machine identities (Shadow AI telemetry
    collectors), deliberately separate from get_current_user: these are
    not human sessions, don't have roles, and are identified by a
    long-lived hashed API key in a custom header rather than a
    short-lived Bearer JWT.
    """
    result = await db.execute(
        select(IngestionSource).where(
            IngestionSource.api_key_hash == hash_api_key(x_ingestion_key)
        )
    )
    source = result.scalar_one_or_none()
    if source is None or not source.enabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ingestion.invalid_key",
        )
    source.last_seen_at = datetime.now(timezone.utc)
    await db.commit()
    return source
