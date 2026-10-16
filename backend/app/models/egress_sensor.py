# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import (BigInteger, Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text,
                        UniqueConstraint, func)
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


class EgressSensorWorkload(Base):
    """
    Per-workload snapshot the sensor reports on every heartbeat: how many
    cgroups on the host are governed under each workload, and the DNS proxy
    counters of that workload's listener.

    One row per (sensor, workload); the sensor overwrites it on every
    heartbeat. When the sensor stops reporting a workload (it was removed
    from the policy, or the sensor is gone), the row is deleted on the next
    heartbeat from the same sensor. Rows of silent sensors stay: the
    sensor card shows last_seen_at and the UI dims them.

    Keeping this in its own table (rather than as JSONB on the sensor)
    means a workload-level query - "which hosts govern this workload, and
    is DNS working there" - is a plain index scan, not a JSON traversal.
    """

    __tablename__ = "egress_sensor_workloads"
    __table_args__ = (
        UniqueConstraint("sensor_id", "workload_id", name="uq_egress_sensor_workloads"),
    )

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    sensor_id = Column(Integer, ForeignKey("egress_sensors.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    workload_id = Column(Integer, ForeignKey("egress_workloads.id", ondelete="CASCADE"),
                         nullable=False, index=True)

    # Counts of what the kernel currently governs on this sensor for the workload.
    cgroups = Column(Integer, nullable=False, default=0)
    processes = Column(Integer, nullable=False, default=0)
    # Process names running inside, reported by the sensor for visibility.
    privileged = Column(JSONB, nullable=False, default=list)

    # DNS proxy counters of the workload's listener, accumulated since the
    # sensor started. A counter reset to zero means the sensor restarted.
    dns_port = Column(Integer)
    dns_total = Column(BigInteger, nullable=False, default=0)
    dns_allowed = Column(BigInteger, nullable=False, default=0)
    dns_denied = Column(BigInteger, nullable=False, default=0)

    updated_at = Column(DateTime(timezone=True), nullable=False,
                        server_default=func.now(), onupdate=func.now())


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


class EgressPolicySettings(Base):
    """One row per organization, holding the policy settings the sensor
    reads on every fetch. A row is created lazily the first time it is
    read; the defaults are the values that used to be hardcoded.

    refresh_seconds and heartbeat_seconds drive the sensor's poll and
    heartbeat loops; a busy host with hundreds of sensors can raise them
    to cut API load, a small install can lower them for faster reaction.
    """

    __tablename__ = "egress_policy_settings"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True, index=True)

    refresh_seconds = Column(Integer, nullable=False, default=30)
    heartbeat_seconds = Column(Integer, nullable=False, default=30)

    # Defaults for new workloads; existing rows are never rewritten by a
    # change here - the settings only affect what "New workload" pre-fills.
    default_mode = Column(String(10), nullable=False, default="observe")
    default_dns = Column(String(10), nullable=False, default="off")

    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), nullable=False,
                        server_default=func.now(), onupdate=func.now())


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


class EgressSensorSigningKey(Base):
    """One Ed25519 keypair per organization, used to sign commands the
    control plane queues for its sensors.

    There is no automatic rotation: an admin would generate a new key and
    re-enroll every sensor, or the sensors of the old key would refuse the
    new signatures. The key is created lazily on first command or first
    GET /signing-key; its private half is stored encrypted with the same
    ENCRYPTION_KEY that wraps BYOK secrets.
    """

    __tablename__ = "egress_sensor_signing_keys"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True, index=True)

    public_key = Column(Text, nullable=False)          # base64, sent to sensors
    private_key_encrypted = Column(Text, nullable=False)  # Fernet(ENCRYPTION_KEY)
    fingerprint = Column(String(60), nullable=False)   # "SHA256:..." for display

    # During and after a rotation, the previous key stays valid on sensors
    # for a grace period. Commands signed before the rotation are still
    # verified; a sensor that misses the update command for a moment does
    # not silently drop every command.
    previous_public_key = Column(Text)
    previous_fingerprint = Column(String(60))
    previous_valid_until = Column(DateTime(timezone=True))

    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    rotated_at = Column(DateTime(timezone=True))       # when this key replaced an older one


class EgressSensorCommand(Base):
    """A command queued for one sensor.

    Created once by an admin; delivered at most once (heartbeat marks
    delivered_at); acked by the sensor (status moves to executing, then
    done or failed); expired if nothing happens within the TTL. There is
    no retry: the admin queues another command if the first timed out.

    The payload that was signed is kept verbatim: it is the sensor's job
    to canonicalize and verify; keeping it as-is makes the audit trail
    self-contained and a signature reproducible offline.
    """

    __tablename__ = "egress_sensor_commands"
    __table_args__ = (
        Index("ix_egress_sensor_commands_status_expires", "status", "expires_at"),
    )

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    sensor_id = Column(Integer, ForeignKey("egress_sensors.id", ondelete="CASCADE"),
                       nullable=False, index=True)

    kind = Column(String(20), nullable=False)          # detach | restart | dump-state
    payload = Column(JSONB, nullable=False)            # the canonical payload that was signed
    signature = Column(Text, nullable=False)           # Ed25519 over canonical_text(payload)

    issued_by = Column(Integer, ForeignKey("users.id"))
    issued_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    delivered_at = Column(DateTime(timezone=True))
    acked_at = Column(DateTime(timezone=True))

    status = Column(String(20), nullable=False, default="pending")
    # pending -> delivered -> executing -> done | failed
    #                                      or expired (no delivery within TTL)

    result = Column(JSONB)                             # dump-state: the sensor's full status
    error = Column(String(500))
