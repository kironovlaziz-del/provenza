# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Pydantic types for the egress sensor API.

The policy document (PolicyOut) is what the sensor fetches on every poll
and what it applies to the kernel. Its field names and the shape of every
nested object must stay in step with the Go structs in
sensor/internal/config/policy.go — the sensor rejects a document whose
schema is not exactly the number it understands, and refuses to apply a
policy that names an unknown dns / mode value.

HeartbeatIn and ViolationIn are the inputs the sensor POSTs; their field
names match sensor/internal/client/client.go.
"""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------- sensors

class SensorRegister(BaseModel):
    """Admin creates a sensor. The key is generated server-side and returned
    exactly once (SensorCreated.api_key); it is never stored in plaintext."""
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)


class SensorUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    enabled: Optional[bool] = None


class SensorOut(BaseModel):
    id: int
    org_id: int
    name: str
    hostname: Optional[str] = None
    key_prefix: str
    enabled: bool
    revoked_at: Optional[datetime] = None

    version: Optional[str] = None
    kernel: Optional[str] = None
    enforcing: Optional[bool] = None
    hooks: Optional[List[str]] = None
    warnings: Optional[List[str]] = None
    errors: Optional[List[str]] = None
    dropped_events: int = 0
    allowed_total: Optional[int] = None
    denied_total: Optional[int] = None
    observed_total: Optional[int] = None
    allowed_per_min: Optional[int] = None
    denied_per_min: Optional[int] = None
    observed_per_min: Optional[int] = None
    config_version: Optional[str] = None
    last_seen_at: Optional[datetime] = None

    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class SensorWorkloadOut(BaseModel):
    """One per-workload row of a sensor's latest heartbeat: what the sensor
    governs under the workload and how its DNS proxy is doing."""
    workload_id: int
    workload_name: str
    cgroups: int = 0
    processes: int = 0
    privileged: List[str] = Field(default_factory=list)
    dns_port: Optional[int] = None
    dns_total: int = 0
    dns_allowed: int = 0
    dns_denied: int = 0
    updated_at: datetime

    class Config:
        from_attributes = True


class SensorCreated(SensorOut):
    # Shown once at registration; never returned again.
    api_key: str


# ---------------------------------------------------------------- workloads

class AllowRule(BaseModel):
    """One allow entry. `dest` on egress, `source` on ingress — a CIDR, a
    single IP, or a host name (optionally "*.corp.internal"). Ports may be
    empty (any), and protocols may be empty (any)."""
    model_config = ConfigDict(extra="forbid")

    dest: Optional[str] = Field(default=None, max_length=255)
    source: Optional[str] = Field(default=None, max_length=255)
    ports: List[int] = Field(default_factory=list)
    protocols: List[str] = Field(default_factory=list)

    @field_validator("ports")
    @classmethod
    def _ports(cls, v: List[int]) -> List[int]:
        for p in v:
            if p < 0 or p > 65535:
                raise ValueError("port out of range")
        return v

    @field_validator("protocols")
    @classmethod
    def _protos(cls, v: List[str]) -> List[str]:
        allowed = {"tcp", "udp", "icmp", ""}
        for p in v:
            if p.lower() not in allowed:
                raise ValueError(f"unknown protocol: {p}")
        return [p.lower() for p in v]


class WorkloadIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    agent_id: Optional[int] = None

    cgroup_patterns: List[str] = Field(default_factory=list)
    run_as_users: List[str] = Field(default_factory=list)

    egress_allow: List[AllowRule] = Field(default_factory=list)
    ingress_allow: List[AllowRule] = Field(default_factory=list)

    dns: Literal["off", "listed", "any"] = "off"
    mode: Literal["observe", "alert", "enforce"] = "observe"

    isolated: bool = False
    isolated_reason: Optional[str] = Field(default=None, max_length=500)

    enabled: bool = True


class WorkloadUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None
    agent_id: Optional[int] = None

    cgroup_patterns: Optional[List[str]] = None
    run_as_users: Optional[List[str]] = None

    egress_allow: Optional[List[AllowRule]] = None
    ingress_allow: Optional[List[AllowRule]] = None

    dns: Optional[Literal["off", "listed", "any"]] = None
    mode: Optional[Literal["observe", "alert", "enforce"]] = None

    isolated: Optional[bool] = None
    isolated_reason: Optional[str] = Field(default=None, max_length=500)

    enabled: Optional[bool] = None


class WorkloadOut(BaseModel):
    id: int
    org_id: int
    agent_id: Optional[int] = None

    name: str
    description: Optional[str] = None

    cgroup_patterns: List[str] = Field(default_factory=list)
    run_as_users: List[str] = Field(default_factory=list)

    egress_allow: List[Dict[str, Any]] = Field(default_factory=list)
    ingress_allow: List[Dict[str, Any]] = Field(default_factory=list)

    dns: str = "off"
    mode: str = "observe"

    isolated: bool = False
    isolated_reason: Optional[str] = None

    enabled: bool = True
    deleted_at: Optional[datetime] = None

    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ---------------------------------------------------------------- commands

class CommandIn(BaseModel):
    """Admin input for POST /sensors/{id}/commands. Only the three known
    kinds are accepted: there is no generic channel."""
    model_config = ConfigDict(extra="forbid")

    kind: Literal["detach", "restart", "dump-state"]


class CommandForSensor(BaseModel):
    """One queued command as the sensor sees it in the heartbeat response.
    `payload` is what was signed; `signature` is the Ed25519 signature
    over the RFC 8785 canonical form of the payload."""
    id: int
    kind: str
    payload: Dict[str, Any]
    signature: str
    expires_at: datetime


class HeartbeatResponseOut(BaseModel):
    """The heartbeat response. An empty list is the normal case; a sensor
    that is not the target of any command sees just this."""
    commands: List[CommandForSensor] = Field(default_factory=list)


class CommandOut(BaseModel):
    """Admin view of a command and its fate. `result` carries the sensor's
    status for dump-state; `error` carries the message from a failed ack."""
    id: int
    sensor_id: int
    kind: str
    status: str
    issued_by: Optional[int] = None
    issued_at: datetime
    expires_at: datetime
    delivered_at: Optional[datetime] = None
    acked_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    class Config:
        from_attributes = True


class CommandAckIn(BaseModel):
    """The sensor's ack. `status` is `executing` while a command is in
    progress (used so a detach is recorded before the daemon exits),
    `done` when it completed, `failed` on error. `result` is only used
    for dump-state."""
    model_config = ConfigDict(extra="forbid")

    status: Literal["executing", "done", "failed"]
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = Field(default=None, max_length=500)


class SigningKeyOut(BaseModel):
    """The public half of the organization's command signing key and the
    id of the sensor asking for it. The sensor needs its own id to reject
    a command addressed to another sensor of the same organization (the
    signing key is per organization, so the id is what tells commands
    apart).

    previous_public_key is set during a rotation grace period. The sensor
    verifies a command against the current key first, then against the
    previous one; when both fail, the command is refused.
    """
    public_key: str
    fingerprint: str
    sensor_id: int
    previous_public_key: Optional[str] = None
    previous_fingerprint: Optional[str] = None
    previous_valid_until: Optional[datetime] = None


class SigningKeyRotationOut(BaseModel):
    """What a rotation or its finalization returns to the admin."""
    fingerprint: str
    previous_fingerprint: Optional[str] = None
    previous_valid_until: Optional[datetime] = None
    sensors_notified: int = 0
    rotated_at: Optional[datetime] = None


# ---------------------------------------------------------------- policy (sensor output)

class PolicyAllow(BaseModel):
    """Same as AllowRule but serialized without null keys the sensor does
    not expect: dest OR source, ports list, protocols list."""
    dest: Optional[str] = None
    source: Optional[str] = None
    ports: List[int] = Field(default_factory=list)
    protocols: List[str] = Field(default_factory=list)


class PolicyWorkload(BaseModel):
    id: int
    name: str
    agent_id: Optional[int] = None
    cgroup_patterns: List[str] = Field(default_factory=list)
    run_as_users: List[str] = Field(default_factory=list)
    egress_allow: List[PolicyAllow] = Field(default_factory=list)
    ingress_allow: List[PolicyAllow] = Field(default_factory=list)
    dns: str = "off"
    mode: str = "observe"
    isolated: bool = False
    isolated_reason: Optional[str] = None


class PolicyOut(BaseModel):
    schema_: int = Field(default=1, alias="schema")
    version: str
    refresh_seconds: int = 30
    heartbeat_seconds: int = 30
    workloads: List[PolicyWorkload] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True)


# ---------------------------------------------------------------- settings

class PolicySettingsOut(BaseModel):
    """The organization's policy settings, as returned by GET /settings and
    embedded in every policy the sensors fetch."""
    refresh_seconds: int
    heartbeat_seconds: int
    default_mode: Literal["observe", "alert", "enforce"]
    default_dns: Literal["off", "listed", "any"]
    activity_retention_days: int = 30
    violation_retention_days: int = 30
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PolicySettingsUpdate(BaseModel):
    """Admin input for PATCH /settings. All fields optional: only what is
    sent is changed, and each is range-checked so a bad value cannot take
    every sensor of the organization offline."""
    model_config = ConfigDict(extra="forbid")

    refresh_seconds: Optional[int] = Field(default=None, ge=10, le=600)
    heartbeat_seconds: Optional[int] = Field(default=None, ge=10, le=300)
    default_mode: Optional[Literal["observe", "alert", "enforce"]] = None
    default_dns: Optional[Literal["off", "listed", "any"]] = None
    # 0 disables pruning for this organization.
    activity_retention_days: Optional[int] = Field(default=None, ge=0, le=365)
    violation_retention_days: Optional[int] = Field(default=None, ge=0, le=365)


# ---------------------------------------------------------------- heartbeat (sensor input)

class WorkloadReportIn(BaseModel):
    """A per-workload snapshot the sensor sends on every heartbeat. The DNS
    fields are optional so a sensor older than the per-workload DNS proxy
    reports without them; a newer sensor fills them in."""
    model_config = ConfigDict(extra="ignore")

    id: int
    cgroups: int = 0
    processes: int = 0
    # A Go client whose slice is nil sends null; accept both.
    privileged: Optional[List[str]] = None

    dns_port: Optional[int] = Field(default=None, ge=0, le=65535)
    dns_total: int = Field(default=0, ge=0)
    dns_allowed: int = Field(default=0, ge=0)
    dns_denied: int = Field(default=0, ge=0)


class HeartbeatIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    hostname: Optional[str] = Field(default=None, max_length=255)
    version: Optional[str] = Field(default=None, max_length=100)
    kernel: Optional[str] = Field(default=None, max_length=100)
    config_version: Optional[str] = Field(default=None, max_length=64)
    enforcing: bool = False
    # A Go client whose slices are nil sends null, not []; accept both.
    hooks: Optional[List[str]] = None
    workloads: Optional[List[WorkloadReportIn]] = None
    warnings: Optional[List[str]] = None
    errors: Optional[List[str]] = None
    dropped_events: int = 0
    allowed_total: Optional[int] = None
    denied_total: Optional[int] = None
    observed_total: Optional[int] = None
    allowed_per_min: Optional[int] = None
    denied_per_min: Optional[int] = None
    observed_per_min: Optional[int] = None


# ---------------------------------------------------------------- violations (sensor input)

class ViolationIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    workload_id: int
    action: Literal["observed", "alerted", "blocked"]
    kind: str = Field(max_length=20)
    protocol: str = Field(default="", max_length=10)

    dst_ip: Optional[str] = Field(default=None, max_length=64)
    dst_port: Optional[int] = Field(default=None, ge=0, le=65535)
    dst_name: Optional[str] = Field(default=None, max_length=255)
    comm: Optional[str] = Field(default=None, max_length=64)
    cgroup: Optional[str] = Field(default=None, max_length=500)

    isolated: bool = False
    count: int = Field(default=1, ge=1)
    # Wall-clock timestamp from the sensor's kernel clock. Optional: an
    # older sensor does not send it, and the handler falls back to now().
    ts: Optional[datetime] = None


class ViolationsBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: List[ViolationIn] = Field(default_factory=list, max_length=500)


class ViolationOut(BaseModel):
    id: int
    sensor_id: Optional[int] = None
    workload_id: Optional[int] = None
    action: str
    kind: str
    protocol: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    dst_name: Optional[str] = None
    comm: Optional[str] = None
    cgroup: Optional[str] = None
    isolated: bool = False
    count: int = 1
    created_at: datetime

    class Config:
        from_attributes = True


class ActivityIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    workload_id: int
    action: Literal["allowed"] = "allowed"
    kind: str = Field(max_length=20)
    protocol: str = Field(default="", max_length=10)

    dst_ip: Optional[str] = Field(default=None, max_length=64)
    dst_port: Optional[int] = Field(default=None, ge=0, le=65535)
    dst_name: Optional[str] = Field(default=None, max_length=255)
    comm: Optional[str] = Field(default=None, max_length=64)
    cgroup: Optional[str] = Field(default=None, max_length=500)

    isolated: bool = False
    count: int = Field(default=1, ge=1)
    ts: Optional[datetime] = None


class ActivityBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: List[ActivityIn] = Field(default_factory=list, max_length=500)


class ActivityOut(BaseModel):
    id: int
    sensor_id: Optional[int] = None
    workload_id: Optional[int] = None
    action: str
    kind: str
    protocol: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    dst_name: Optional[str] = None
    comm: Optional[str] = None
    cgroup: Optional[str] = None
    isolated: bool = False
    count: int = 1
    created_at: datetime

    class Config:
        from_attributes = True


# ---------------------------------------------------------------- events
# Unified view over egress_violations and sensor_activity for SIEM/SOAR
# integrations. The two tables have the same shape (id, sensor_id,
# workload_id, action, kind, protocol, dst_*, comm, cgroup, isolated,
# count, created_at); the only extra is event_type, which tells the
# consumer which table the row came from. "kind" keeps its original
# meaning (BPF decision kind: connect / send / dns / family).

class EventOut(BaseModel):
    event_type: Literal["violation", "activity"]
    id: int
    sensor_id: Optional[int] = None
    workload_id: Optional[int] = None
    action: str
    kind: str
    protocol: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    dst_name: Optional[str] = None
    comm: Optional[str] = None
    cgroup: Optional[str] = None
    isolated: bool = False
    count: int = 1
    created_at: datetime


class EventList(BaseModel):
    events: list[EventOut]
    # Cursor for the next page, opaque to the caller. Absent when the
    # current page is the last one. Format is "<event_type>:<id>"; the
    # caller passes it back verbatim as ?cursor=... and the server rebuilds
    # the tuple comparison from it.
    next_cursor: Optional[str] = None
