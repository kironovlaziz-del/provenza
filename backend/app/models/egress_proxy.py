# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class EgressRoute(Base):
    """
    An external API agents reach only through a Provenza egress proxy
    (proxy/, app/pvp/egress_proxy.py). The upstream comes from here and only
    from here - never from the agent's request - and so does the credential:

      credential_source "server"  the secret is stored encrypted here (BYOK
                                  aware) and handed to authenticated proxies,
                                  which keep it in memory only
      credential_source "local"   the proxy injects a secret from its own
                                  configuration; this server never sees it
      credential_source "none"    nothing is injected

    Agents need "proxy.<slug>" in their rights to use a route.
    """

    __tablename__ = "egress_routes"
    __table_args__ = (UniqueConstraint("org_id", "slug", name="uq_egress_routes_slug"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    slug = Column(String(40), nullable=False)            # the first path segment at the proxy
    name = Column(String(255), nullable=False)
    upstream_url = Column(String(500), nullable=False)
    methods = Column(JSONB, nullable=False)              # e.g. ["GET", "POST"]
    path_prefixes = Column(JSONB, nullable=False)        # e.g. ["/v1/charges"]; ["/"] = anything
    credential_source = Column(String(10), nullable=False, default="none")
    auth_header = Column(String(100), nullable=False, default="Authorization")
    secret_encrypted = Column(Text)                      # credential_source "server" only
    max_body_bytes = Column(Integer, nullable=False, default=8 * 1024 * 1024)
    enabled = Column(Boolean, nullable=False, default=True)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class EgressProxy(Base):
    """A deployed egress proxy and its key (only the hash is stored). A proxy
    redeems agents' checks and records what it forwarded; it can read the
    server-held secrets of its organization's routes - treat its key like
    those secrets."""

    __tablename__ = "egress_proxies"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    key_hash = Column(String(64), nullable=False, unique=True, index=True)
    key_prefix = Column(String(16), nullable=False)      # shown in the UI to tell keys apart
    enabled = Column(Boolean, nullable=False, default=True)
    last_seen_at = Column(DateTime(timezone=True))
    revoked_at = Column(DateTime(timezone=True))
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class EgressRedemption(Base):
    """A check a proxy redeemed: it is reserved (no one else can use it) from
    redeem to complete. One that is never completed means the proxy forwarded
    and did not report back - visible to admins as an open redemption."""

    __tablename__ = "egress_redemptions"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    check_id = Column(Integer, ForeignKey("agent_action_checks.id"), nullable=False, unique=True)
    proxy_id = Column(Integer, ForeignKey("egress_proxies.id"), nullable=False, index=True)
    route_id = Column(Integer, ForeignKey("egress_routes.id", ondelete="SET NULL"))
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False)
    descriptor = Column(JSONB, nullable=False)           # the request as the proxy saw it (hashes only)
    reserved_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    completed_at = Column(DateTime(timezone=True))
    action_id = Column(Integer, ForeignKey("agent_actions.id"))
