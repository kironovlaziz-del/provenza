from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List, Dict, Any

class UseCaseBase(BaseModel):
    name: str
    owner_user_id: Optional[int] = None
    risk_level: str = "low"  # low, medium, high, critical
    allowed_providers_json: Optional[Dict[str, Any]] = None

class UseCaseCreate(UseCaseBase):
    pass

class UseCaseOut(UseCaseBase):
    id: int
    org_id: int
    status: str
    created_at: datetime
    
    class Config:
        from_attributes = True

class UseCaseUpdate(BaseModel):
    name: Optional[str] = None
    owner_user_id: Optional[int] = None
    risk_level: Optional[str] = None
    allowed_providers_json: Optional[Dict[str, Any]] = None
    status: Optional[str] = None

