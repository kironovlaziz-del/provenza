from typing import Optional

from pydantic import BaseModel, Field


class QueueSettingsIn(BaseModel):
    queue_ttl_seconds: int = Field(ge=60, le=86400)
    approval_ttl_hours: int = Field(ge=1, le=720)
    raw_prompt_retention_days: Optional[int] = Field(default=None, ge=1, le=3650)
    # agent telemetry; omitted = unchanged, null = keep indefinitely
    agent_check_retention_days: Optional[int] = Field(default=None, ge=1, le=3650)
    agent_content_retention_days: Optional[int] = Field(default=None, ge=1, le=3650)
