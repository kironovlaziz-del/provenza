from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, Dict, Any


# ---- Agents ----

class AgentCreate(BaseModel):
    name: str
    description: Optional[str] = None
    agent_type: Optional[str] = None  # crewai, langgraph, autogen, custom
    version: Optional[str] = None
    owner_team: Optional[str] = None
    capabilities: Optional[List[str]] = None
    allowed_tools: Optional[List[str]] = None
    allowed_models: Optional[List[str]] = None
    max_delegation_depth: int = 3


class AgentUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    owner_team: Optional[str] = None
    capabilities: Optional[List[str]] = None
    allowed_tools: Optional[List[str]] = None
    allowed_models: Optional[List[str]] = None
    max_delegation_depth: Optional[int] = None
    status: Optional[str] = None  # active, suspended, retired


class AgentOut(BaseModel):
    id: int
    org_id: int
    name: str
    description: Optional[str]
    agent_type: Optional[str]
    version: Optional[str]
    owner_user_id: Optional[int]
    owner_team: Optional[str]
    capabilities: Optional[List[str]]
    allowed_tools: Optional[List[str]]
    allowed_models: Optional[List[str]]
    max_delegation_depth: int
    status: str
    public_key: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class AgentCreated(AgentOut):
    # Secrets shown ONCE at registration; never returned again.
    api_key: str
    private_key: str


# ---- Kill switch ----

class AgentKillRequest(BaseModel):
    reason: Optional[str] = None
    cascade: bool = True


class AgentKillResponse(BaseModel):
    agents_stopped: List[int]
    chains_terminated: int


# ---- Delegation ----

class DelegateRequest(BaseModel):
    to_agent_id: int
    task: str
    delegated_capabilities: List[str] = Field(default_factory=list)
    chain_id: Optional[int] = None      # None = start a new chain (root delegation)
    signature: Optional[str] = None     # Ed25519 signature by the delegating agent
    expires_in: Optional[int] = None    # seconds
    # Replay protection - both are part of the signed payload
    nonce: Optional[str] = Field(default=None, min_length=16, max_length=128)
    issued_at: Optional[int] = None     # unix seconds, set by the signing agent


class DelegateResponse(BaseModel):
    chain_id: int
    hop_id: int
    depth: int
    max_depth_remaining: int
    verified: bool


class HopOut(BaseModel):
    id: int
    from_agent_id: int
    to_agent_id: int
    depth: int
    delegated_capabilities: Optional[List[str]]
    expires_at: Optional[datetime] = None
    task_description: Optional[str]
    verified: bool
    created_at: datetime

    class Config:
        from_attributes = True


class ChainOut(BaseModel):
    id: int
    org_id: int
    root_agent_id: int
    root_task: Optional[str]
    status: str
    total_hops: int
    max_depth_reached: int
    started_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


class ChainDetail(ChainOut):
    hops: List[HopOut] = Field(default_factory=list)


# ---- Actions ----

class ActionCheckRequest(BaseModel):
    agent_id: int
    chain_id: Optional[int] = None
    action_type: str = "tool_call"
    tool_name: str
    input: Dict[str, Any] = Field(default_factory=dict)
    action_capabilities: List[str] = Field(default_factory=list)


class ActionCheckResponse(BaseModel):
    decision: str  # allowed, denied, pending_approval
    reason: str
    incident_type: Optional[str] = None
    policy_id: Optional[int] = None
    check_id: Optional[str] = None        # single-use token for /actions/record
    expires_at: Optional[datetime] = None


class ActionRecordRequest(BaseModel):
    agent_id: int
    chain_id: Optional[int] = None
    action_type: str = "tool_call"
    tool_name: str
    input: Dict[str, Any] = Field(default_factory=dict)
    output: Optional[Dict[str, Any]] = None
    signature: Optional[str] = None
    duration_ms: Optional[int] = None
    check_id: Optional[str] = None        # from /actions/check (required for keyed agents)
    action_capabilities: List[str] = Field(default_factory=list)  # keyless path only


class ActionDenyRequest(BaseModel):
    reason: Optional[str] = None


class ActionOut(BaseModel):
    id: int
    org_id: int
    chain_id: Optional[int]
    agent_id: int
    action_type: Optional[str]
    tool_name: Optional[str]
    policy_check_result: Optional[str]
    reason: Optional[str]
    duration_ms: Optional[int]
    created_at: datetime
    check_id: Optional[int] = None
    signed_payload: Optional[Dict[str, Any]] = None
    signature: Optional[str] = None

    class Config:
        from_attributes = True


# ---- Agent policies ----

class AgentPolicyCreate(BaseModel):
    name: str
    agent_id: Optional[int] = None  # None = all agents in org
    rules: Dict[str, Any] = Field(default_factory=dict)
    priority: int = 100
    enabled: bool = True


class AgentPolicyOut(BaseModel):
    id: int
    org_id: int
    agent_id: Optional[int]
    name: str
    rules: Optional[Dict[str, Any]]
    priority: int
    enabled: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ---- Incidents ----

class AgentIncidentOut(BaseModel):
    id: int
    org_id: int
    chain_id: Optional[int]
    agent_id: Optional[int]
    incident_type: Optional[str]
    severity: Optional[str]
    details: Optional[Dict[str, Any]]
    resolved: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ---- Governance graph (live map) ----

class GraphNode(BaseModel):
    id: int
    name: str
    agent_type: Optional[str]
    status: str                    # active, suspended, retired
    has_violation: bool = False    # any unresolved incident on this agent
    action_count: int = 0          # recent actions (drives "activity" pulse)


class GraphEdge(BaseModel):
    id: int                        # hop id
    chain_id: int
    from_agent_id: int
    to_agent_id: int
    delegated_capabilities: List[str] = Field(default_factory=list)
    verified: bool = False         # signature present & verified at hop time
    chain_status: str              # active, completed, violated, terminated
    is_violation: bool = False     # this edge's chain is violated


class GovernanceGraph(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    generated_at: datetime
