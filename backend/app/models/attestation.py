# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Workload attestation (services/attestation.py, docs/attestation.md)."""

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class AttestationPolicy(Base):
    """Where an agent must prove it runs. kind "k8s_sa": a Kubernetes
    ServiceAccount token from this cluster (issuer, its JWKS), for this
    audience, from an allowed namespace / service account, bound to a pod.
    A role template that requires attestation names one policy; its agents
    need a passing attestation made after the policy last changed and not
    older than validity_minutes."""

    __tablename__ = "attestation_policies"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_attestation_policies_org_name"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    kind = Column(String(20), nullable=False, server_default="k8s_sa")
    issuer = Column(String(500), nullable=False)       # the cluster's service-account issuer (iss)
    audience = Column(String(200), nullable=False, server_default="provenza")
    jwks = Column(JSONB)                               # pasted from `kubectl get --raw /openid/v1/jwks`
    jwks_url = Column(String(500))                     # or fetched (https); default: OIDC discovery on the issuer
    namespaces = Column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))        # patterns
    service_accounts = Column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))  # "ns/name" patterns
    require_pod_bound = Column(Boolean, nullable=False, server_default=text("true"))
    validity_minutes = Column(Integer, nullable=False, server_default="60")
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    # attestations made before this do not count; set by the service on every change
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class AgentAttestation(Base):
    """One attestation attempt that got as far as checking the evidence.
    ok: it passed the policy; it then counts until valid_until."""

    __tablename__ = "agent_attestations"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False, index=True)
    policy_id = Column(Integer, ForeignKey("attestation_policies.id", ondelete="SET NULL"), index=True)
    kind = Column(String(20), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    ok = Column(Boolean, nullable=False)
    reason = Column(String(80))
    detail = Column(String(500))
    identity = Column(JSONB)          # what the evidence says: namespace, service account, pod, node, ...
    evidence_sha256 = Column(String(64), index=True)
    # it counts only while the agent still has this key, and only under the
    # policy exactly as it stood (its updated_at) when the evidence was checked
    signer_fingerprint = Column(String(200))
    policy_version = Column(DateTime(timezone=True))
    valid_until = Column(DateTime(timezone=True))
