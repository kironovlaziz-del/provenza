# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class RuntimeWorkload(Base):
    """
    A set of processes on hosts, named by their cgroup v2 paths, whose
    outbound connections the Provenza runtime daemon (daemon/, eBPF) governs:

      egress_allow   [{"cidr": "127.0.0.1/32", "ports": [8443]}, ...]; [] ports = any.
                     Typically the egress proxy and Provenza - so the workload
                     cannot go around the proxy.
      allow_dns      DNS to the host's own resolvers only (not to any server on
                     port 53, which would be a tunnel out)
      mode           observe (record), alert (record + notify) or enforce
                     (the kernel refuses the connection)

    A workload linked to an agent turns its violations into agent incidents.
    """

    __tablename__ = "runtime_workloads"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_runtime_workloads_name"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="SET NULL"))
    cgroup_patterns = Column(JSONB, nullable=False)     # e.g. ["system.slice/billing-agent.service"]
    egress_allow = Column(JSONB, nullable=False)        # [{"cidr", "ports"}]
    allow_dns = Column(Boolean, nullable=False, default=True)
    mode = Column(String(10), nullable=False, default="observe")
    enabled = Column(Boolean, nullable=False, default=True)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class RuntimeViolation(Base):
    """A connection a governed workload made, or tried, outside its policy -
    one row per distinct (host, workload, action, destination, process name),
    counted, so a retry loop does not flood the table."""

    __tablename__ = "runtime_violations"
    __table_args__ = (UniqueConstraint("org_id", "dedupe_key", name="uq_runtime_violations_dedupe"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    source_id = Column(Integer, ForeignKey("ingestion_sources.id", ondelete="SET NULL"))
    workload_id = Column(Integer, ForeignKey("runtime_workloads.id", ondelete="SET NULL"), index=True)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="SET NULL"))
    dedupe_key = Column(String(64), nullable=False)
    host = Column(String(255), nullable=False)
    action = Column(String(10), nullable=False)          # observed | alerted | blocked
    protocol = Column(String(4), nullable=False)         # tcp | udp
    dst_ip = Column(String(45), nullable=False)
    dst_port = Column(Integer, nullable=False)
    comm = Column(String(16))                            # the kernel's process name, not the command line
    cgroup = Column(String(500))
    count = Column(Integer, nullable=False, default=1)
    first_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
