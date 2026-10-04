from pydantic import BaseModel, field_validator
from app.core.ssrf import validate_webhook_url, WebhookURLError
from datetime import datetime
from typing import List, Optional, Literal

EVENT_TYPES = [
    "incident_created",
    "approval_pending",
    "shadow_ai_reported",
    "shadow_ai_blocked_domain",
    "request_blocked",
    "agent_discovered",
]


class NotificationChannelCreate(BaseModel):
    channel_type: Literal["email", "webhook"]
    target: str
    events: List[str]
    enabled: bool = True

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str, info):
        channel_type = info.data.get("channel_type")
        v = v.strip()
        if not v:
            raise ValueError("target must not be empty")
        if channel_type == "email":
            # Basic structural check - enough to reject obvious typos.
            if "@" not in v or v.startswith("@") or v.endswith("@"):
                raise ValueError("invalid email address")
            # Normalize case so "Ops@Example.com" and "ops@example.com"
            # cannot coexist as two channels.
            v = v.lower()
        elif channel_type == "webhook":
            try:
                v = validate_webhook_url(v)
            except WebhookURLError as exc:
                raise ValueError(str(exc))
        return v


class NotificationChannelUpdate(BaseModel):
    target: Optional[str] = None
    events: Optional[List[str]] = None
    enabled: Optional[bool] = None

    @field_validator("target")
    @classmethod
    def _validate_update_target(cls, v):
        # An update can change a webhook target, so it must be re-checked -
        # otherwise a benign channel could be repointed at an internal
        # address. Only webhook-shaped values (http/https) are guarded
        # here; an email target is left as-is.
        if v is None:
            return v
        v = v.strip()
        if v.startswith("http://") or v.startswith("https://"):
            try:
                v = validate_webhook_url(v)
            except WebhookURLError as exc:
                raise ValueError(str(exc))
        return v


class NotificationChannelOut(BaseModel):
    id: int
    org_id: int
    channel_type: str
    target: str
    events_json: List[str]
    enabled: bool
    created_by: Optional[int]
    created_at: datetime

    class Config:
        from_attributes = True
