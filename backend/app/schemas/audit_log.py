from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Dict, Any


class AuditLogOut(BaseModel):
    id: int
    org_id: int
    actor_user_id: Optional[int]
    entity_type: str
    entity_id: Optional[int]
    action: str
    metadata_json: Optional[Dict[str, Any]]
    created_at: datetime
    seq: Optional[int] = None
    prev_hash: Optional[str] = None
    record_hash: Optional[str] = None

    class Config:
        from_attributes = True
