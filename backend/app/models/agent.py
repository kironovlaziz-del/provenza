from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import JSONB
from app.core.database import Base


class Agent(Base):
    """
    A registered AI agent within an organization (CrewAI / LangGraph /
    AutoGen / custom). This is the identity and permission record for an
    autonomous agent that can call tools, invoke models, and delegate
    work to other agents.

    Authentication mirrors IngestionSource: a machine identity with a
    hashed API key (never a user JWT), plus - unique to agents - an
    Ed25519 public key used to verify the signatures the agent puts on
    its delegations and actions. The private key lives only with the
    agent (returned once at registration); the server stores only the
    public half.

    The permission fields (allowed_tools / allowed_models / capabilities)
    are the ground truth the policy engine checks every action against,
    and the ceiling that any delegation must stay within (a child can
    only ever receive a subset - see capability_validator).
    """

    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    agent_type = Column(String(50))  # crewai, langgraph, autogen, custom
    version = Column(String(50))
    owner_user_id = Column(Integer, ForeignKey("users.id"))
    owner_team = Column(String(100))

    capabilities = Column(JSONB)     # list of allowed high-level actions
    allowed_tools = Column(JSONB)    # e.g. ["openai.chat", "database.query"]
    allowed_models = Column(JSONB)   # e.g. ["gpt-4o", "claude-sonnet"]
    max_delegation_depth = Column(Integer, nullable=False, default=3)

    status = Column(String(20), nullable=False, default="active")  # active, suspended, retired
    api_key_hash = Column(String(64), nullable=False, unique=True, index=True)
    # agent identity: key lifecycle (rotation keeps the previous key valid for a grace period)
    previous_api_key_hash = Column(String(64), index=True)
    previous_key_expires_at = Column(DateTime(timezone=True))
    api_key_rotated_at = Column(DateTime(timezone=True))
    api_key_revoked_at = Column(DateTime(timezone=True))
    api_key_last_used_at = Column(DateTime(timezone=True))
    public_key = Column(Text)  # Ed25519 public key (base64), for signature verification

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class AgentPolicy(Base):
    """
    A policy scoped to agents. agent_id NULL means it applies to every
    agent in the org; a specific agent_id narrows it to that agent.
    Higher priority wins when several match; the rules JSON is evaluated
    by agent_policy_engine.
    """

    __tablename__ = "agent_policies"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"))  # NULL = all agents
    name = Column(String(255), nullable=False)
    rules = Column(JSONB)            # JSON rule set (see agent_policy_engine)
    priority = Column(Integer, nullable=False, default=100)
    enabled = Column(Boolean, nullable=False, default=True)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
