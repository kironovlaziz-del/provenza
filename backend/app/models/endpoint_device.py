# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import (
    BigInteger, Column, DateTime, Float, ForeignKey, Integer, String, UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class EndpointDevice(Base):
    """
    A machine or browser that reports telemetry, as the collector identifies
    itself (host_id = the endpoint agent's agent_id, by default the hostname;
    a per-install id for the browser extension). Created and refreshed by the
    ingestion pipeline - nobody registers devices by hand.

    host_id is a claim made by whoever holds the ingestion key: it is unique
    per ingestion source, never trusted across sources.
    """

    __tablename__ = "endpoint_devices"
    __table_args__ = (
        UniqueConstraint("org_id", "ingestion_source_id", "host_id", name="uq_endpoint_devices_host"),
    )

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    ingestion_source_id = Column(Integer, ForeignKey("ingestion_sources.id", ondelete="CASCADE"), nullable=False)
    host_id = Column(String(255), nullable=False)
    last_user = Column(String(255))
    os = Column(String(30))
    agent_version = Column(String(30))
    first_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    event_count = Column(BigInteger, nullable=False, server_default="0")


class DiscoveredAgent(Base):
    """
    An AI agent product found running on a device (Claude Code, Cursor,
    CrewAI, ...), one row per (device, product). Comes from the endpoint
    agent's "agent_detected" events; the evidence holds how it matched,
    never the command line.

    status: new -> registered (linked to a governed Agent) | ignored.
    A registered or ignored finding stays so when it is seen again.
    """

    __tablename__ = "discovered_agents"
    __table_args__ = (
        UniqueConstraint("org_id", "device_id", "product", name="uq_discovered_agents_device_product"),
    )

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id = Column(Integer, ForeignKey("endpoint_devices.id", ondelete="CASCADE"), nullable=False, index=True)
    product = Column(String(60), nullable=False)
    risk_score = Column(Float)
    evidence = Column(JSONB)  # {process_name, matched_by}
    status = Column(String(20), nullable=False, server_default="new")
    registered_agent_id = Column(Integer, ForeignKey("agents.id", ondelete="SET NULL"), index=True)
    decided_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    decided_at = Column(DateTime(timezone=True))
    first_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    seen_count = Column(Integer, nullable=False, server_default="1")
