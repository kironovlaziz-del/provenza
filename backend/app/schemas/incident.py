from pydantic import BaseModel, Field
from datetime import datetime
from typing import Literal, Optional

Severity = Literal["low", "medium", "high", "critical"]
IncidentStatus = Literal["open", "investigating", "resolved"]


class IncidentCreate(BaseModel):
    severity: Severity = "low"
    category: str = Field(min_length=1, max_length=100)
    summary: str = Field(min_length=1, max_length=10000)
    impact: Optional[str] = Field(default=None, max_length=10000)


class IncidentUpdate(BaseModel):
    """Triage (admin or approver): the values are fixed, so an incident cannot
    be put into a state no list or report knows about."""
    severity: Optional[Severity] = None
    category: Optional[str] = Field(default=None, min_length=1, max_length=100)
    summary: Optional[str] = Field(default=None, min_length=1, max_length=10000)
    impact: Optional[str] = Field(default=None, max_length=10000)
    root_cause: Optional[str] = Field(default=None, max_length=10000)
    status: Optional[IncidentStatus] = None

class IncidentOut(BaseModel):
    id: int
    org_id: int
    severity: str
    category: str
    summary: str
    impact: Optional[str]
    root_cause: Optional[str]
    status: str
    created_at: datetime
    resolved_at: Optional[datetime]
    
    class Config:
        from_attributes = True

