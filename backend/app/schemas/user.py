import re
from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
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


