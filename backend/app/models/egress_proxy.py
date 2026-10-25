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

      credential_source "sealed"  entered in the browser and sealed there to
                                  each proxy's own key (app/pvp/sealed.py):
                                  this server stores envelopes it cannot open
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
    credential_source = Column(String(10), nullable=False, default="none")   # none, sealed, local
    auth_header = Column(String(100), nullable=False, default="Authorization")
    secret_encrypted = Column(Text)                      # before sealing only (seal-legacy erases it)
    max_body_bytes = Column(Integer, nullable=False, default=8 * 1024 * 1024)
    enabled = Column(Boolean, nullable=False, default=True)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class EgressProxy(Base):
    """A deployed egress proxy and its key (only the hash is stored). A proxy
    redeems agents' checks and records what it forwarded. The credentials of
    its organization's upstreams are sealed to its own encryption key, which
    never leaves its host: its API key alone opens none of them."""

    __tablename__ = "egress_proxies"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    key_hash = Column(String(64), nullable=False, unique=True, index=True)
    key_prefix = Column(String(16), nullable=False)      # shown in the UI to tell keys apart
    enabled = Column(Boolean, nullable=False, default=True)
    last_seen_at = Column(DateTime(timezone=True))
    revoked_at = Column(DateTime(timezone=True))
    # the proxy's own Ed25519 key, generated on its host (docs/pvp/edge.md, section 4):
    # it signs what it witnessed; registered once, never replaced (a new key is a new proxy)
    public_key = Column(Text)
    key_registered_at = Column(DateTime(timezone=True))
    # its X25519 key, for credentials sealed to it (app/pvp/sealed.py), and its
    # signing key's signature over it
    encryption_key = Column(Text)
    encryption_key_signature = Column(Text)
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
    # the request as the proxy saw it (hashes only), or the input of a gateway action it executes
    descriptor = Column(JSONB, nullable=False)
    reserved_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    completed_at = Column(DateTime(timezone=True))
    action_id = Column(Integer, ForeignKey("agent_actions.id"))


class ProxyKillSwitch(Base):
    """A proxy's local kill switch (docs/pvp/edge.md, sections 6-7): it stopped
    after the signed policy's offline time without this server and stays
    stopped until the quorum of the release it held before the outage signs
    its reconciliation report. The report and its receipt are the proxy's,
    signed with its own key."""

    __tablename__ = "proxy_kill_switches"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    proxy_id = Column(Integer, ForeignKey("egress_proxies.id", ondelete="CASCADE"), nullable=False, index=True)
    engaged_at = Column(DateTime(timezone=True), nullable=False)
    release_before = Column(Integer, nullable=False)     # the release whose quorum lifts it
    report = Column(JSONB, nullable=False)
    report_sha256 = Column(String(64), nullable=False)
    receipt = Column(JSONB, nullable=False)              # the proxy's signature over the report's hash
    status = Column(String(10), nullable=False, default="engaged")   # engaged | lifted
    lifted_at = Column(DateTime(timezone=True))
    lifted_by = Column(JSONB)                            # the administrators the proxy counted
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class ProxyKillSwitchSignature(Base):
    """One administrator's passkey over a reconciliation report: the report's
    hash and the differences they accept."""

    __tablename__ = "proxy_kill_switch_signatures"
    __table_args__ = (UniqueConstraint("kill_switch_id", "report_sha256", "user_id", name="uq_kill_switch_signature"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    kill_switch_id = Column(Integer, ForeignKey("proxy_kill_switches.id", ondelete="CASCADE"), nullable=False,
                            index=True)
    report_sha256 = Column(String(64), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    credential_id = Column(String(1400), nullable=False)
    statement = Column(JSONB, nullable=False)
    assertion = Column(JSONB, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
