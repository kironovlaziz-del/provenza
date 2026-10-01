from pydantic import BaseModel, Field


class AgentIdentitySettingsIn(BaseModel):
    require_agent_key: bool
    rotation_grace_minutes: int = Field(ge=0, le=1440)
