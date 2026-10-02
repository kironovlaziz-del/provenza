from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import JSONB
from app.core.database import Base


class AgentAction(Base):
    """
    A single action an agent performed (or attempted) - a tool call,
    model call, or API request - within a delegation chain. Records the
    policy engine's verdict (allowed / denied / pending_approval), the
    matched policy, and the agent's Ed25519 signature over the action, so
    the full action history is tamper-evident and offline-verifiable.

    Note: an action row is written for DENIED attempts too, not just
    allowed ones - the point of governance is to have a record of what an
    agent tried to do, especially when it was blocked.
    """

    __tablename__ = "agent_actions"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    chain_id = Column(Integer, ForeignKey("delegation_chains.id", ondelete="CASCADE"), index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False, index=True)
    action_type = Column(String(50))  # tool_call, model_call, api_request
    tool_name = Column(String(100))
    input_data = Column(JSONB)
    output_data = Column(JSONB)
    policy_check_result = Column(String(20))  # allowed, denied, pending_approval
    policy_id = Column(Integer, ForeignKey("agent_policies.id"))
    reason = Column(Text)
    signature = Column(Text)
    duration_ms = Column(Integer)
    # The /actions/check this action was recorded against, and the exact
    # payload the agent signed - makes the action verifiable offline.
    check_id = Column(Integer, ForeignKey("agent_action_checks.id"), index=True)
    signed_payload = Column(JSONB)
    signer_public_key = Column(Text)  # key that verified `signature` (survives key changes)
    pq_signature = Column(Text)          # ML-DSA-65 signature (hybrid signers)
    signer_pq_public_key = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)


class AgentIncident(Base):
    """
    An incident raised at the agent layer, distinct from the platform's
    human-facing AIIncident: these are automatic detections during agent
    execution - capability escalation, delegation depth exceeded, policy
    violation. Linked to the chain and agent that triggered it.
    """

    __tablename__ = "agent_incidents"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    chain_id = Column(Integer, ForeignKey("delegation_chains.id", ondelete="CASCADE"), index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), index=True)
    incident_type = Column(String(50))  # capability_escalation, depth_exceeded, policy_violation
    severity = Column(String(20))
    details = Column(JSONB)
    resolved = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ActionCheck(Base):
    """
    A policy verdict issued by /actions/check, bound to exactly one
    proposed action (agent, chain, tool, input hash, capabilities). The
    random token is handed to the agent and must be presented - once, and
    before expires_at - when the action is recorded. This is what makes
    "the recorded action is the action that was checked" provable.
    """

    __tablename__ = "agent_action_checks"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(64), nullable=False, unique=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False)
    chain_id = Column(Integer, ForeignKey("delegation_chains.id", ondelete="CASCADE"))
    action_type = Column(String(50))
    tool_name = Column(String(100))
    input_sha256 = Column(String(64), nullable=False)
    action_capabilities = Column(JSONB)
    decision = Column(String(20), nullable=False)
    reason = Column(Text)
    incident_type = Column(String(50))
    policy_id = Column(Integer, ForeignKey("agent_policies.id"))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
