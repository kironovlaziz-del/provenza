from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, func, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from app.core.database import Base


class DelegationChain(Base):
    """
    One end-to-end delegation flow: a root agent gets a task and may
    hand sub-tasks to other agents, which may hand them further. The
    chain groups every hop and every action that belongs to that
    original task, so the whole tree can be audited, visualized, and
    killed as a unit.

    max_depth_reached is tracked on the chain so the policy engine can
    reject a delegation that would exceed the delegating agent's
    max_delegation_depth without walking the whole hop list each time.
    """

    __tablename__ = "delegation_chains"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    root_agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False, index=True)
    root_task = Column(Text)  # description of the originating task
    status = Column(String(20), nullable=False, default="active")  # active, completed, violated, terminated
    total_hops = Column(Integer, nullable=False, default=0)
    max_depth_reached = Column(Integer, nullable=False, default=0)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True))
    # ASI08 circuit breaker: when/why the chain tripped, and when an admin resumed it
    breaker_tripped_at = Column(DateTime(timezone=True))
    breaker_reset_at = Column(DateTime(timezone=True))
    breaker_details = Column(JSONB)
    # ASI01: a tool output in this chain carried a prompt injection
    tainted_at = Column(DateTime(timezone=True))
    taint_details = Column(JSONB)


class DelegationHop(Base):
    """
    A single delegation step: from_agent hands a subset of its
    capabilities to to_agent, signed with from_agent's Ed25519 key. The
    signature is what makes the chain verifiable offline (an auditor can
    confirm each hop was authorized by the parent without trusting the
    server).

    delegated_capabilities MUST be a subset of what from_agent itself
    holds in the chain - capability_validator enforces this; a superset
    is a privilege-escalation incident.
    """

    __tablename__ = "delegation_hops"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    chain_id = Column(Integer, ForeignKey("delegation_chains.id", ondelete="CASCADE"), nullable=False, index=True)
    from_agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False)
    to_agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False)
    depth = Column(Integer, nullable=False, default=1)  # hop's depth in the chain (root delegation = 1)
    delegated_capabilities = Column(JSONB)  # subset of the parent's capabilities
    task_description = Column(Text)
    expires_at = Column(DateTime(timezone=True))
    signature = Column(Text)  # Ed25519 signature by from_agent
    # The exact canonical payload that was signed, stored so offline
    # verification (in the browser or by an auditor) reconstructs nothing
    # and cannot drift from what the signer actually signed. Without this,
    # a payload field like chain_id (null at root-signing time, a real id
    # afterwards) would make the signature impossible to re-verify.
    signed_payload = Column(JSONB)
    verified = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class DelegationNonce(Base):
    # Single-use nonces for signed delegations. The unique constraint makes a
    # replayed request fail at the database level, even under concurrency.
    __tablename__ = "delegation_nonces"
    __table_args__ = (
        UniqueConstraint("org_id", "from_agent_id", "nonce", name="uq_delegation_nonce"),
    )

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    from_agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    nonce = Column(String(128), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
