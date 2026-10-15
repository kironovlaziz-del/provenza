# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class EgressSensor(Base):
    __tablename__ = "egress_sensors"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_egress_sensors_name"),
    )

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    hostname = Column(String(255))

    key_hash = Column(String(64), nullable=False, unique=True, index=True)
    key_prefix = Column(String(24), nullable=False)

    enabled = Column(Boolean, nullable=False, default=True)
    revoked_at = Column(DateTime(timezone=True))

    version = Column(String(100))
    kernel = Column(String(100))
    enforcing = Column(Boolean)
    hooks = Column(JSONB)
    warnings = Column(JSONB)
    errors = Column(JSONB)
    dropped_events = Column(Integer, nullable=False, default=0)
    config_version = Column(String(64))
    last_seen_at = Column(DateTime(timezone=True))
    # Set by the offline checker the first time we warned about this sensor;
    # cleared (set back) when it starts sending heartbeats again, so the
    # next silence produces a new warning.
    offline_notified_at = Column(DateTime(timezone=True))

    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class EgressWorkload(Base):
    __tablename__ = "egress_workloads"
    __table_args__ = (
        Index("ix_egress_workloads_active", "org_id", "deleted_at"),
        UniqueConstraint("org_id", "name", name="uq_egress_workloads_name"),
    )

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="SET NULL"), index=True)

    name = Column(String(255), nullable=False)
    description = Column(Text)

    cgroup_patterns = Column(JSONB, nullable=False, default=list)
    run_as_users = Column(JSONB, nullable=False, default=list)

    egress_allow = Column(JSONB, nullable=False, default=list)
    ingress_allow = Column(JSONB, nullable=False, default=list)

    dns = Column(String(10), nullable=False, default="off")
    mode = Column(String(10), nullable=False, default="observe")

    isolated = Column(Boolean, nullable=False, default=False)
    isolated_reason = Column(String(500))

    enabled = Column(Boolean, nullable=False, default=True)
    deleted_at = Column(DateTime(timezone=True), index=True)

    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class EgressPolicyRevision(Base):
    __tablename__ = "egress_policy_revisions"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True, index=True)
    revision = Column(Integer, nullable=False, default=1)
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())


class EgressViolation(Base):
    __tablename__ = "egress_violations"
    __table_args__ = (
        Index("ix_egress_violations_org_time", "org_id", "created_at"),
        Index("ix_egress_violations_workload_time", "workload_id", "created_at"),
    )

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    sensor_id = Column(Integer, ForeignKey("egress_sensors.id", ondelete="SET NULL"), index=True)
    workload_id = Column(Integer, ForeignKey("egress_workloads.id", ondelete="SET NULL"), index=True)

    action = Column(String(20), nullable=False)
    kind = Column(String(20), nullable=False)
    protocol = Column(String(10))

    dst_ip = Column(String(64))
    dst_port = Column(Integer)
    dst_name = Column(String(255))
    comm = Column(String(64))
    cgroup = Column(String(500))

    isolated = Column(Boolean, nullable=False, default=False)
    count = Column(Integer, nullable=False, default=1)

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
