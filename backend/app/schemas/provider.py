from pydantic import BaseModel, field_validator
from datetime import datetime
from typing import Optional

from app.core.outbound import validate_url


def _check_base_url(v: Optional[str]) -> Optional[str]:
    """http(s), a host, no credentials, not a literal internal IP; the
    connect-time guard in core/outbound.py covers hostnames."""
    if v is None or not v.strip():
        return None
    return validate_url(v)


class ProviderBase(BaseModel):
    name: str
    type: str  # openai, anthropic, azure_openai, custom, ...
    status: str = "active"
    sla: Optional[str] = None
    risk_score: float = 0.0
    base_url: Optional[str] = None
    default_model: Optional[str] = None

    @field_validator("base_url")
    @classmethod
    def _base_url(cls, v: Optional[str]) -> Optional[str]:
        return _check_base_url(v)


class ProviderCreate(ProviderBase):
    api_key: Optional[str] = None  # write-only, never returned


class ProviderUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    status: Optional[str] = None
    sla: Optional[str] = None
    risk_score: Optional[float] = None
    base_url: Optional[str] = None
    default_model: Optional[str] = None
    api_key: Optional[str] = None  # write-only; omit to leave unchanged

    @field_validator("base_url")
    @classmethod
    def _base_url(cls, v: Optional[str]) -> Optional[str]:
        return _check_base_url(v)


class ProviderOut(BaseModel):
    id: int
    org_id: int
    name: str
    type: str
    status: str
    sla: Optional[str] = None
    risk_score: float
    base_url: Optional[str] = None
    default_model: Optional[str] = None
    has_credentials: bool = False
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
