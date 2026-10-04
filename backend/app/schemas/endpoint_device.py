from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class SourceRef(BaseModel):
    id: int
    name: str
    source_type: str


class DeviceOut(BaseModel):
    id: int
    host_id: str
    source: SourceRef
    last_user: Optional[str] = None
    os: Optional[str] = None
    agent_version: Optional[str] = None
    first_seen_at: datetime
    last_seen_at: datetime
    event_count: int
    agents_found: int = 0
    agents_new: int = 0


class AgentRef(BaseModel):
    id: int
    name: str


class FoundAgentOut(BaseModel):
    id: int
    product: str
    name: str
    vendor: str
    category: str
    device_id: int
    device_host: str
    device_user: Optional[str] = None
    risk_score: Optional[float] = None
    evidence: Optional[dict] = None
    status: str
    registered_agent: Optional[AgentRef] = None
    decided_at: Optional[datetime] = None
    first_seen_at: datetime
    last_seen_at: datetime
    seen_count: int


class DeviceDetail(DeviceOut):
    agents: List[FoundAgentOut] = []


class FoundSummary(BaseModel):
    new: int = 0
    registered: int = 0
    ignored: int = 0
    devices: int = 0


class LinkAgentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: int = Field(ge=1)
