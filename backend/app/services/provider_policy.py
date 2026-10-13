# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The organization's AI provider policy (organizations.ai_provider_policy):

  any           every connection may be used (the default)
  self_hosted   only providers on the organization's own network: prompts
                never leave for a cloud AI service

"Self-hosted" is decided where it cannot be talked around - at connect time:
inside `scope(True)` the provider adapters use an internal-only
client (core/outbound.py) that connects to non-global addresses only, after
resolving the name, every time. A base URL, a redirect or a DNS record
cannot send the prompt to the internet. The operator decides which internal
addresses are reachable at all (OUTBOUND_PRIVATE_ALLOWLIST).

`cloud_reason` is only the early, explainable refusal for the obvious cases
(no base URL = the vendor's cloud API; a public IP literal), so the user
gets "provider.self_hosted_only" instead of a network error.

Agents calling a provider directly (the SDK's egress actions, pvp/egress.py)
are refused for every host the AI domain catalog knows as an AI service.
"""

import ipaddress
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator, Optional
from urllib.parse import urlparse

from fastapi import status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import api_error
from app.models.organization import Organization

POLICIES = ("any", "self_hosted")
_POLICY_NAMES = {p: p for p in POLICIES}
INCIDENT = "ai_provider_not_self_hosted"

_self_hosted_only: ContextVar[bool] = ContextVar("provider_self_hosted_only", default=False)


def policy_name(value: Optional[str]) -> str:
    """The policy's canonical name (one of POLICIES) - what goes into the audit log."""
    return _POLICY_NAMES.get(value or "any", "any")


async def org_policy(db: AsyncSession, org_id: int) -> str:
    value = (await db.execute(select(Organization.ai_provider_policy).where(Organization.id == org_id))).scalar()
    return policy_name(value)


async def self_hosted_required(db: AsyncSession, org_id: int) -> bool:
    return await org_policy(db, org_id) == "self_hosted"


def self_hosted_only() -> bool:
    """Whether the provider call being made must stay on the internal network."""
    return _self_hosted_only.get()


def cloud_reason(provider_type: Optional[str], base_url: Optional[str]) -> Optional[str]:
    """Why a connection is certainly not self-hosted, or None when only the
    connect-time check can tell (a host name)."""
    if not (base_url or "").strip():
        return f"a {provider_type or 'provider'} connection without a base URL calls the vendor's cloud API"
    host = urlparse(base_url.strip()).hostname or ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    return "the base URL is a public address" if ip.is_global else None


async def enforce(db: AsyncSession, org_id: int, provider_type: Optional[str], base_url: Optional[str]) -> bool:
    """Refuse a connection that is obviously in the cloud while the policy is
    on (403 provider.self_hosted_only). Returns whether the policy is on - pass
    it to `scope` around the call itself."""
    on = await self_hosted_required(db, org_id)
    if on:
        reason = cloud_reason(provider_type, base_url)
        if reason:
            raise api_error(status.HTTP_403_FORBIDDEN, "provider.self_hosted_only", reason=reason)
    return on


@contextmanager
def scope(on: bool) -> Iterator[None]:
    """Provider calls made inside use the internal-only client when `on`."""
    token = _self_hosted_only.set(on)
    try:
        yield
    finally:
        _self_hosted_only.reset(token)
