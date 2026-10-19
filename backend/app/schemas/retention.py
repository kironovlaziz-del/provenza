from typing import Optional

from pydantic import BaseModel, Field


class RetentionSettingsIn(BaseModel):
    # omitted = unchanged, null = keep indefinitely
    agent_check_retention_days: Optional[int] = Field(default=None, ge=1, le=3650)
    agent_content_retention_days: Optional[int] = Field(default=None, ge=1, le=3650)
