"""
Two-factor sign-in (app/core/totp.py) for user accounts.

  setup -> enable(code)     a secret is generated and confirmed with a first
                            code; 10 recovery codes are shown once
  sign-in                   password, then a code (or a recovery code) - see
                            app/api/auth.py
  disable(password, code)   both factors; refused while the organization's
                            policy requires a second factor for this user
  admin reset               for a lost device: the user enrolls again, and
                            their sessions end

Organization policy (organizations.mfa_required): none | reviewers (admins and
approvers) | all. A user it applies to who has not enrolled may only open
their profile, enroll, change their password and sign out
(app/api/deps.py: MFA_SETUP_PATHS).
"""

from datetime import datetime, timezone
from typing import List, Optional

from fastapi import status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import totp
from app.core.crypto import decrypt_secret, encrypt_secret
from app.core.errors import api_error
from app.core.security import verify_password
from app.models.organization import Organization
from app.models.user import User, UserRole

POLICIES = ("none", "reviewers", "all")


def policy_applies(policy: Optional[str], role: Optional[str]) -> bool:
    if policy == "all":
        return True
    if policy == "reviewers":
        return role in (UserRole.admin.value, UserRole.approver.value)
    return False


async def org_policy(db: AsyncSession, org_id: int) -> str:
    return (await db.execute(select(Organization.mfa_required).where(Organization.id == org_id))).scalar() or "none"


async def required_for(db: AsyncSession, user: User) -> bool:
    return policy_applies(await org_policy(db, user.org_id), user.role)


def check_code(user: User, code: str) -> Optional[str]:
    """Verify a second factor and use it up. Returns "totp" or "recovery", or
    None. The caller commits."""
    if not user.totp_enabled or not user.totp_secret_encrypted:
        return None
    counter = totp.verify(decrypt_secret(user.totp_secret_encrypted), code, user.totp_last_counter)
    if counter is not None:
        user.totp_last_counter = counter
        return "totp"
    rest = totp.use_recovery_code(list(user.mfa_recovery_hashes or []), code)
    if rest is not None:
        user.mfa_recovery_hashes = rest
        return "recovery"
    return None


async def start_setup(db: AsyncSession, user: User) -> dict:
    if user.totp_enabled:
        raise api_error(status.HTTP_409_CONFLICT, "mfa.already_enabled")
    secret = totp.new_secret()
    user.totp_pending_encrypted = encrypt_secret(secret, user.org_id)
    email = user.email
    await db.commit()
    return {"secret": secret, "otpauth_uri": totp.otpauth_uri(secret, email)}


async def enable(db: AsyncSession, user: User, code: str) -> List[str]:
    if user.totp_enabled:
        raise api_error(status.HTTP_409_CONFLICT, "mfa.already_enabled")
    if not user.totp_pending_encrypted:
        raise api_error(status.HTTP_400_BAD_REQUEST, "mfa.setup_first")
    secret = decrypt_secret(user.totp_pending_encrypted)
    counter = totp.verify(secret, code, None)
    if counter is None:
        raise api_error(status.HTTP_400_BAD_REQUEST, "mfa.invalid_code")
    codes, hashes = totp.new_recovery_codes()
    user.totp_secret_encrypted, user.totp_pending_encrypted = user.totp_pending_encrypted, None
    user.totp_enabled, user.totp_last_counter = True, counter
    user.mfa_recovery_hashes, user.mfa_enabled_at = hashes, datetime.now(timezone.utc)
    await db.commit()
    return codes


async def disable(db: AsyncSession, user: User, password: str, code: str) -> None:
    if not user.totp_enabled:
        raise api_error(status.HTTP_409_CONFLICT, "mfa.not_enabled")
    if await required_for(db, user):
        raise api_error(status.HTTP_409_CONFLICT, "mfa.required_by_policy")
    if not verify_password(password, user.hashed_password) or check_code(user, code) is None:
        raise api_error(status.HTTP_400_BAD_REQUEST, "mfa.invalid_code")
    _clear(user)
    await db.commit()


async def new_recovery_codes(db: AsyncSession, user: User, code: str) -> List[str]:
    if check_code(user, code) is None:
        raise api_error(status.HTTP_400_BAD_REQUEST, "mfa.invalid_code")
    codes, hashes = totp.new_recovery_codes()
    user.mfa_recovery_hashes = hashes
    await db.commit()
    return codes


def reset(target: User) -> None:
    """An admin's reset for a lost device; the target's sessions end too. The caller commits."""
    _clear(target)
    target.sessions_valid_after = datetime.now(timezone.utc)


def _clear(user: User) -> None:
    user.totp_enabled = False
    user.totp_secret_encrypted = user.totp_pending_encrypted = None
    user.totp_last_counter = None
    user.mfa_recovery_hashes = None
    user.mfa_enabled_at = None
