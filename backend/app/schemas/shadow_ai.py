from pydantic import BaseModel, Field
from datetime import datetime
from typing import Any, Dict, Literal, Optional


class ShadowSightingCreate(BaseModel):
    tool_name: str
    domain: Optional[str] = None
    detected_via: str = "manual"  # manual, expense_report, network_proxy, browser_extension, other
    user_hint: Optional[str] = None
    notes: Optional[str] = None
    display_meta: Optional[Dict[str, Any]] = None


class ShadowSightingUpdate(BaseModel):
    """Review (admin or approver). "registered" is set only by /register."""
    status: Optional[Literal["new", "reviewing", "confirmed_shadow", "dismissed"]] = None
    notes: Optional[str] = Field(default=None, max_length=10000)


class ShadowSightingRegister(BaseModel):
    provider_type: str = "custom"
    provider_sla: Optional[str] = None


class ShadowSightingOut(BaseModel):
    id: int
    org_id: int
    tool_name: str
    domain: Optional[str]
    detected_via: str
    user_hint: Optional[str]
    notes: Optional[str]
    status: str
    reported_by: Optional[int]
    registered_provider_id: Optional[int]
    display_meta: Optional[Dict[str, Any]] = None
    seen_count: int = 1
    last_seen_at: Optional[datetime] = None
    created_at: datetime
    resolved_at: Optional[datetime]

    class Config:
        from_attributes = True


