# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Signed policy (docs/pvp/edge.md, section 3): a release is the policy bundle
(everything that decides allow or deny) and the key manifest (who may sign,
which keys agents act with), frozen and signed by a quorum of
administrators with their passkeys. Never deleted: an old release is the
record of what was in force.
"""

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class PolicyRelease(Base):
    """status   draft        prepared from the working copy, collecting signatures
                 in_force     the quorum signed it: what decisions are checked against
                 superseded   a later release came into force
                 withdrawn    replaced by a newer draft before it was signed"""

    __tablename__ = "policy_releases"
    __table_args__ = (UniqueConstraint("org_id", "number", name="uq_policy_releases_number"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    number = Column(Integer, nullable=False)
    status = Column(String(12), nullable=False)
    bundle = Column(JSONB, nullable=False)
    bundle_sha256 = Column(String(64), nullable=False)
    manifest = Column(JSONB, nullable=False)
    manifest_sha256 = Column(String(64), nullable=False)
    # the release in force when this one was prepared: its manifest names who
    # may sign this one and how many must (NULL: the first release, signed by
    # the quorum of its own manifest)
    governed_by_id = Column(Integer, ForeignKey("policy_releases.id"))
    changes = Column(JSONB)                   # what differs from the release that governs it
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    in_force_at = Column(DateTime(timezone=True))
    ended_at = Column(DateTime(timezone=True))


class PolicyReleaseSignature(Base):
    """One administrator's passkey over the release statement."""

    __tablename__ = "policy_release_signatures"
    __table_args__ = (UniqueConstraint("release_id", "user_id", name="uq_policy_release_signer"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    release_id = Column(Integer, ForeignKey("policy_releases.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    credential_id = Column(String(1400), nullable=False)
    statement = Column(JSONB, nullable=False)
    assertion = Column(JSONB, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class PolicySigningSettings(Base):
    """The working copy of what the next release states about itself: the
    quorum and the egress proxy binaries (in its manifest), how long it is
    valid and how long an enforcement point may run without the server (in
    its bundle)."""

    __tablename__ = "policy_signing_settings"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True)
    quorum = Column(Integer, nullable=False, default=1)
    validity_days = Column(Integer, nullable=False, default=90)
    offline_seconds = Column(Integer, nullable=False, default=900)
    # SHA-256 of the egress proxy binaries a sensor lets out of a proxy host
    # (in the manifest, docs/pvp/edge.md section 5)
    proxy_binaries = Column(JSONB)
    # ... and of the configurations it may run with (the proxy reports the file's hash to the sensor)
    proxy_configs = Column(JSONB)
    # observe | enforce (in its bundle, docs/pvp/edge.md section 4): with enforce no
    # action runs without the agent's signature and an enforcement point's judgement
    enforcement = Column(String(10), nullable=False, default="observe", server_default="observe")
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
