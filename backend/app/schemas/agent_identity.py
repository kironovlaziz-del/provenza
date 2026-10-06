from typing import Optional

from pydantic import BaseModel, Field


class AgentIdentitySettingsIn(BaseModel):
    require_agent_key: bool
    rotation_grace_minutes: int = Field(ge=0, le=1440)
    # None = keep the current value, so a client that predates the field
    # cannot switch the policy off just by saving the other settings.
    require_pq_signatures: Optional[bool] = None
    allow_keyless_agents: Optional[bool] = None
    allow_direct_registration: Optional[bool] = None
