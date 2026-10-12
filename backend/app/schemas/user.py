import re
from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from typing import Literal, Optional
from app.models.user import UserRole


SLUG_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$")


def _validate_slug(v: str) -> str:
    v = v.strip().lower()
    if not SLUG_PATTERN.match(v):
        raise ValueError(
            "slug must be 3-63 chars, lowercase letters, digits and hyphens"
        )
    return v


class UserBase(BaseModel):
    email: EmailStr
    name: str
    role: UserRole = UserRole.user


class UserCreate(UserBase):
    """First user of a new organization. Role is ignored server-side and
    forced to admin - see api/users.py."""
    password: str = Field(min_length=8)
    org_name: str
    org_slug: str

    @field_validator("org_slug")
    @classmethod
    def _slug(cls, v: str) -> str:
        return _validate_slug(v)


class UserInvite(BaseModel):
    """Admin inviting a teammate into the existing organization."""
    email: EmailStr
    name: str
    role: UserRole = UserRole.user
    password: str = Field(min_length=8)


class UserRoleUpdate(BaseModel):
    role: UserRole


class UserStatusUpdate(BaseModel):
    status: str = Field(pattern="^(active|disabled)$")


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


class UserOut(UserBase):
    id: int
    org_id: int
    status: str
    created_at: datetime
    totp_enabled: bool = False      # two-factor sign-in is on

    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    # The slug disambiguates users that share an email across organizations.
    org_slug: str
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginResult(BaseModel):
    """Either a session (access_token), or - with two-factor sign-in on - a
    short-lived mfa_token to exchange with a code at /auth/login/mfa."""
    access_token: Optional[str] = None
    token_type: str = "bearer"
    mfa_required: bool = False
    mfa_token: Optional[str] = None


class MfaLogin(BaseModel):
    mfa_token: str = Field(min_length=1, max_length=4000)
    code: str = Field(min_length=6, max_length=32)   # a 6-digit code or a recovery code




class MfaCode(BaseModel):
    code: str = Field(min_length=6, max_length=32)


class MfaDisable(BaseModel):
    password: str = Field(min_length=1, max_length=200)
    code: str = Field(min_length=6, max_length=32)


class MfaPolicy(BaseModel):
    mfa_required: Literal["none", "reviewers", "all"]
