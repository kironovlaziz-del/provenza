from pydantic import BaseModel, field_validator
from datetime import datetime
from typing import Optional, Dict, Any

class PolicyBase(BaseModel):
    name: str
    description: Optional[str] = None

class PolicyCreate(PolicyBase):
    pass

class PolicyOut(PolicyBase):
    id: int
    org_id: int
    status: str
    created_at: datetime
    
    class Config:
        from_attributes = True

class PolicyVersionCreate(BaseModel):
    rules_json: Dict[str, Any]

    @field_validator("rules_json")
    @classmethod
    def _no_terms(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        # blocked terms of a policy are kept on the Blocked terms page (scope "policy")
        if v.get("blocked_terms"):
            raise ValueError("blocked terms are kept on the Blocked terms page (/blocked-terms), scope: policy")
        v = dict(v)
        v.pop("blocked_terms", None)
        return v

class PolicyVersionOut(BaseModel):
    id: int
    policy_id: int
    version: int
    rules_json: Dict[str, Any]
    created_by: Optional[int]
    created_at: datetime
    approved_by: Optional[int]
    approved_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class PolicyApprove(BaseModel):
    approved: bool = True

