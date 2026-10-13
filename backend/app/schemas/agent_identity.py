from typing import Optional

from pydantic import BaseModel, Field


class AgentIdentitySettingsIn(BaseModel):
    require_agent_key: bool
    rotation_grace_minutes: int = Field(ge=0, le=1440)
    # None = keep the current value, so a client that predates the field
    # cannot switch the policy off just by saving the other settings.
    require_pq_signatures: Optional[bool] = None
    allow_direct_registration: Optional[bool] = None
    require_confined_egress: Optional[bool] = None
    egress_check_max_age_hours: Optional[int] = Field(default=None, ge=1, le=720)
    # every agent must attest under this policy unless its role has one; 0 = none
    default_attestation_policy_id: Optional[int] = Field(default=None, ge=0)
