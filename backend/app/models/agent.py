from sqlalchemy import (Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func,
                        text)
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
    its delegations and actions. The server stores only public keys. With
    key_origin "agent" the agent generated the pair itself and the server
    never saw the private key; with "server" it was generated here and
    returned once (quick start). Every key the agent has used is kept in
    agent_signing_keys.

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
    owner_team = Column(String(100))  # the team's name, kept for display; team_id is what counts
    team_id = Column(Integer, ForeignKey("teams.id"), index=True)
    # rights from a role template (kept in step with it); NULL = set per agent
    role_id = Column(Integer, ForeignKey("role_templates.id"), index=True)

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
    public_key = Column(Text)  # current Ed25519 public key (base64), for signature verification
    key_origin = Column(String(10))  # "agent" (agent-held private key) | "server" (generated here)
    # ML-DSA-65 public key (base64). Set = hybrid agent: every signature must
    # be Ed25519 AND ML-DSA-65 over the same bytes (core/agent_signing.py).
    pq_public_key = Column(Text)
    # proof of possession for a key rotation: a fresh, single-use challenge
    key_challenge = Column(String(64))
    key_challenge_expires_at = Column(DateTime(timezone=True))
    # outstanding workload-attestation challenge (services/attestation.py)
    attest_challenge = Column(String(64))
    attest_challenge_expires_at = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class AgentSigningKey(Base):
    """Every Ed25519 public key an agent has signed with, and when it was
    current. Signed records carry their own signer_public_key, so this is
    the timeline an auditor reads ("which key was valid when"), not what
    verification depends on."""

    __tablename__ = "agent_signing_keys"
    __table_args__ = (
        # at most one current key per agent
        Index("uq_agent_signing_keys_current", "agent_id", unique=True, postgresql_where=text("retired_at IS NULL")),
    )

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    public_key = Column(Text, nullable=False)
    pq_public_key = Column(Text)  # ML-DSA-65 half of a hybrid key
    fingerprint = Column(String(60), nullable=False)
    origin = Column(String(10), nullable=False)  # agent | server
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    retired_at = Column(DateTime(timezone=True))
    # how the key was proven when it was registered: {"kind": "enrollment" |
    # "rekey" | "rotation", "statement": <signed text>, "signature": ...,
    # "pq_signature": ..., "old_signature": ..., ...} - None for keys
    # registered without proof of possession (legacy / direct registration)
    proof = Column(JSONB)


class AgentKeyRevocation(Base):
    """A revoked agent signing key - the revocation list. Append-only (database
    trigger) and every entry is also an audit record, so the list is covered
    by the signed audit checkpoints.

    untrusted_from: signatures made with the key from this moment on are not
    trusted. It is the revocation time, or earlier when the key is known to
    have been compromised before (compromised_since). Signatures made before
    it keep verifying - a key retired in an orderly way does not void its past.
    """

    __tablename__ = "agent_key_revocations"
    __table_args__ = (UniqueConstraint("org_id", "fingerprint", name="uq_agent_key_revocations_fp"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False, index=True)
    signing_key_id = Column(Integer, ForeignKey("agent_signing_keys.id"))
    fingerprint = Column(String(60), nullable=False)
    public_key = Column(Text, nullable=False)
    pq_public_key = Column(Text)
    revoked_at = Column(DateTime(timezone=True), nullable=False)
    untrusted_from = Column(DateTime(timezone=True), nullable=False)
    reason = Column(String(500), nullable=False)
    revoked_by = Column(Integer, ForeignKey("users.id"))
    # the audit record that carries it: entity_type "agent_key_revocation", entity_id = id


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


# append-only, like the audit log (same trigger function; see models/audit_log.py)
def _revocations_append_only():
    from sqlalchemy import DDL, event

    from app.models.audit_log import APPEND_ONLY_FUNCTION, append_only_triggers

    table = AgentKeyRevocation.__table__
    event.listen(table, "after_create", DDL(APPEND_ONLY_FUNCTION).execute_if(dialect="postgresql"))
    for stmt in append_only_triggers(table.name):
        event.listen(table, "after_create", DDL(stmt).execute_if(dialect="postgresql"))


_revocations_append_only()
