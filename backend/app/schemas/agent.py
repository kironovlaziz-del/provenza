from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.agent_signing import (
    SCHEME_CLASSIC, SCHEME_HYBRID, key_fingerprint, normalize_pq_public_key, normalize_public_key,
)
from datetime import datetime
from typing import Optional, List, Dict, Any, Literal


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
    # The agent's own Ed25519 public key (base64 of the 32 raw bytes). Given,
    # the server never holds the private key and cannot sign as the agent.
    # Omitted, a keypair is generated here and the private key returned once.
    public_key: Optional[str] = None
    # Hybrid post-quantum key: the agent's ML-DSA-65 public key (base64 of the
    # 1952 raw bytes), registered together with public_key.
    pq_public_key: Optional[str] = None
    # Only when the server generates the keys: "hybrid" adds an ML-DSA-65 pair.
    key_scheme: Literal["ed25519", "hybrid"] = "ed25519"

    @field_validator("public_key")
    @classmethod
    def _public_key(cls, v: Optional[str]) -> Optional[str]:
        # None = generate one here; an empty string is a mistake, not a choice.
        return None if v is None else normalize_public_key(v)

    @field_validator("pq_public_key")
    @classmethod
    def _pq_public_key(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else normalize_pq_public_key(v)

    @model_validator(mode="after")
    def _pair(self):
        if self.pq_public_key and not self.public_key:
            raise ValueError("pq_public_key comes with public_key: a hybrid key is Ed25519 + ML-DSA-65")
        if self.public_key and self.key_scheme == "hybrid" and not self.pq_public_key:
            raise ValueError("key_scheme 'hybrid' with your own key needs pq_public_key (ML-DSA-65) as well")
        return self


class SigningKeyIn(BaseModel):
    """Register (or replace) the agent's own key: Ed25519, plus ML-DSA-65 for
    a hybrid (post-quantum) key."""
    public_key: str
    pq_public_key: Optional[str] = None

    @field_validator("public_key")
    @classmethod
    def _public_key(cls, v: str) -> str:
        return normalize_public_key(v)

    @field_validator("pq_public_key")
    @classmethod
    def _pq_public_key(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else normalize_pq_public_key(v)


class SigningKeyOut(BaseModel):
    id: int
    public_key: str
    pq_public_key: Optional[str] = None
    fingerprint: str
    origin: str
    scheme: str = SCHEME_CLASSIC
    created_by: Optional[int]
    created_at: datetime
    retired_at: Optional[datetime]

    @model_validator(mode="after")
    def _scheme(self):
        self.scheme = SCHEME_HYBRID if self.pq_public_key else SCHEME_CLASSIC
        return self

    class Config:
        from_attributes = True


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
    pq_public_key: Optional[str] = None   # ML-DSA-65 half of a hybrid key
    key_origin: Optional[str] = None      # agent | server
    key_fingerprint: Optional[str] = None  # "SHA256:..." over the key(s)
    signature_scheme: Optional[str] = None  # ed25519 | ed25519+ml-dsa-65
    created_at: datetime
    updated_at: Optional[datetime]

    @model_validator(mode="after")
    def _fingerprint(self):
        self.key_fingerprint = key_fingerprint(self.public_key, self.pq_public_key)
        if self.public_key:
            self.signature_scheme = SCHEME_HYBRID if self.pq_public_key else SCHEME_CLASSIC
        return self

    class Config:
        from_attributes = True


class AgentCreated(AgentOut):
    # Secrets shown ONCE at registration; never returned again.
    api_key: str
    # Only when the server generated the keypair; None for an agent-held key.
    private_key: Optional[str] = None
    # ML-DSA-65 seed (the private key), server-generated hybrid keys only.
    pq_private_key: Optional[str] = None


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
    # ML-DSA-65 signature over the same bytes - required for hybrid agents
    pq_signature: Optional[str] = Field(default=None, max_length=6000)
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
    breaker_tripped_at: Optional[datetime] = None
    breaker_reset_at: Optional[datetime] = None
    breaker_details: Optional[Dict[str, Any]] = None
    tainted_at: Optional[datetime] = None  # ASI01: injected tool output in this chain
    taint_details: Optional[Dict[str, Any]] = None

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
    # ASI04: reported by the agent's runtime, compared with the Tool Registry pins
    tool_version: Optional[str] = Field(default=None, max_length=100)
    tool_digest: Optional[str] = Field(default=None, max_length=100)


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
    pq_signature: Optional[str] = Field(default=None, max_length=6000)  # hybrid agents
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

    @field_validator("rules")
    @classmethod
    def _validate_argument_rules(cls, v):
        # catch broken regexes / unknown ops at save time, not during an agent's action
        from app.services.argument_rules import validate_argument_rules
        if isinstance(v, dict) and "argument_rules" in v:
            validate_argument_rules(v["argument_rules"])
        return v


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


class ApprovalDecision(BaseModel):
    """ASI09: the reviewer approves the exact arguments they saw."""
    input_sha256: str = Field(min_length=64, max_length=64)
    confirmation: Optional[str] = Field(default=None, max_length=255)
