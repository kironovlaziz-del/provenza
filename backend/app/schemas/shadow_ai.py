from pydantic import BaseModel, Field
from datetime import datetime
from typing import List, Any, Dict, Literal, Optional


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
    # a domain sighting: how many identified people visited it (browser
    # extension 2.1+ with userEmail), and browsers that did not say who
    people: Optional[int] = None
    unidentified_browsers: Optional[int] = None
    created_at: datetime
    resolved_at: Optional[datetime]

    class Config:
        from_attributes = True




class SightingPersonOut(BaseModel):
    user: str
    visits: int
    blocked: int
    last_seen_at: Optional[datetime]


class SightingPeopleOut(BaseModel):
    """Who visited a domain sighting's AI service, from the raw visits Provenza
    keeps (Settings -> Data retention). The user is what the browser reported:
    the organization sets it by policy, it is not a sign-in."""
    people: List[SightingPersonOut]
    unidentified_browsers: int
    unidentified_visits: int
