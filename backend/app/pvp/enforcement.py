# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Enforce mode (docs/pvp/edge.md, section 4): no action runs without the
agent's own signature and an enforcement point's judgement under the signed
policy.

The mode is part of the signed policy (the bundle's "enforcement" section,
set under Policies -> Signed policy -> settings). It is in force when the
working copy or the release in force says "enforce": turning it on takes
effect at once, turning it off only once a quorum has signed it.

In enforce mode:

- this server's own gateways (LLM, MCP, A2A, HTTP tools) execute nothing:
  an egress proxy does, which holds the credentials and judges by the
  signed release itself;
- an egress proxy's call for a plan or a mediated check must carry the
  agent's signed request, verified here too; a check without it is not
  redeemed;
- the REST check-then-act path only observes: a check issues no permit, and
  what an agent records about itself is an observation;
- an action an egress proxy reports without its receipt naming the signed
  policy and the agent's verified signature raises a critical incident.
"""

import base64
import binascii
import json
from contextvars import ContextVar
from typing import Any, Dict, Optional

from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import api_error

MODE = "enforce"
REFUSAL = ("enforce mode: only an egress proxy executes actions, with the agent's signature and the signed "
           "policy (docs/pvp/edge.md, section 4)")
OBSERVATION = (" - enforce mode: this check authorizes nothing by itself; an enforcement point executes the "
               "action")


async def enforced(db: AsyncSession, org_id: Optional[int]) -> bool:
    if org_id is None:
        return False
    from app.models.policy_release import PolicySigningSettings
    from app.pvp import signed_policy
    from sqlalchemy import select

    mode = (await db.execute(select(PolicySigningSettings.enforcement).where(
        PolicySigningSettings.org_id == org_id))).scalar_one_or_none()
    if mode == MODE:
        return True
    sp = await signed_policy.in_force(db, org_id)
    return sp is not None and ((sp.bundle or {}).get("enforcement") or {}).get("mode") == MODE


# --------------------------------------------------------------- at the proxy

PROXY_MODE_HEADER = "X-Provenza-Proxy-Mode"
REQUEST_HEADER = "X-Provenza-Request"          # the agent's signed request, as the agent sent it
DESCRIPTOR_HEADER = "X-Provenza-Descriptor"    # base64url JSON: the request it signed, as the proxy received it
ADAPTER_ROUTES = {"http-tools": "_tools", "llm": "_llm", "mcp": "_mcp", "a2a": "_a2a"}

# set for this request once the agent's signed request verified (proxy_actions.reserve marks the check)
agent_signed: ContextVar[bool] = ContextVar("provenza_agent_signed", default=False)


def _b64json(value: str) -> Any:
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    return json.loads(raw)


def signed_request(header: Optional[str]) -> Optional[Dict[str, Any]]:
    """The header's {"payload", "signature", "pq_signature"?, ...}, or None."""
    if not header or len(header) > 90_000:
        return None
    try:
        sr = _b64json(header)
    except (ValueError, binascii.Error):
        return None
    if not isinstance(sr, dict) or not isinstance(sr.get("payload"), dict) or not isinstance(sr.get("signature"), str):
        return None
    return sr


async def proxy_gate(db: AsyncSession, proxy, request) -> bool:
    """Enforce mode at an egress proxy's endpoint: only a proxy that enforces
    the signed policy itself takes part (it says so: X-Provenza-Proxy-Mode).
    Returns whether the organization is in enforce mode."""
    if not await enforced(db, proxy.org_id):
        return False
    if request.headers.get(PROXY_MODE_HEADER) != MODE:
        raise api_error(status.HTTP_403_FORBIDDEN, "enforcement.proxy_not_enforcing")
    return True


async def verify_agent_request(db: AsyncSession, proxy, agent, request, kind: str) -> None:
    """Enforce mode, a gateway action at a proxy (/egress-proxy/<kind>/plan):
    the agent signed the HTTP request that carried it (as "proxy.<route>",
    route "_tools", "_llm", "_mcp" or "_a2a"), freshly and once - verified
    here with the agent's registered key, as the proxy verified it. The
    request's body hash is the proxy's word (this server does not see the body)."""
    from app.pvp.egress_proxy import DESCRIPTOR_KEYS
    from app.pvp.model import PVPActionRequest
    from app.pvp.orchestrator import PVPOrchestrator

    if not await proxy_gate(db, proxy, request):
        return
    sr = signed_request(request.headers.get(REQUEST_HEADER))
    try:
        desc = _b64json(request.headers.get(DESCRIPTOR_HEADER) or "")
    except (ValueError, binascii.Error):
        desc = None
    if sr is None or not isinstance(desc, dict) or set(desc) != set(DESCRIPTOR_KEYS):
        raise api_error(status.HTTP_401_UNAUTHORIZED, "enforcement.agent_signature_required")
    route = ADAPTER_ROUTES[kind]
    p = sr["payload"]
    if desc.get("route") != route or p.get("agent_id") != agent.id:
        raise api_error(status.HTTP_403_FORBIDDEN, "enforcement.not_the_signed_request")
    try:
        req = PVPActionRequest(agent_id=agent.id, chain_id=p.get("chain_id"), action_type="proxy",
                               tool_name="proxy." + route, input=desc, nonce=p.get("nonce"),
                               issued_at=p.get("issued_at"), signature=sr["signature"],
                               pq_signature=sr.get("pq_signature"))
    except ValueError:
        raise api_error(status.HTTP_401_UNAUTHORIZED, "enforcement.agent_signature_required")
    if req.signed_payload() != p:
        raise api_error(status.HTTP_403_FORBIDDEN, "enforcement.not_the_signed_request")
    await PVPOrchestrator(db).verify_signed_request(proxy.org_id, agent, req)
    agent_signed.set(True)


async def unenforced(db: AsyncSession, org_id: int, receipt: Optional[Dict[str, Any]]) -> Optional[str]:
    """Why a proxy's receipt does not show an enforced action (enforce mode),
    or None: it must name a signed policy release of this organization (one
    that came into force) and say the proxy verified the agent's signature."""
    from app.models.policy_release import PolicyRelease
    from sqlalchemy import select

    st = receipt.get("statement") if isinstance(receipt, dict) else None
    if not isinstance(st, dict):
        return "no receipt"
    if st.get("agent_signature") != "verified":
        return "the receipt does not say the agent's signature was verified"
    pol = st.get("policy")
    if not isinstance(pol, dict):
        return "the receipt names no signed policy"
    number, sha = pol.get("release"), pol.get("bundle_sha256")
    if isinstance(number, bool) or not isinstance(number, int) or not isinstance(sha, str):
        return "the receipt names no signed policy"
    signed = (await db.execute(select(PolicyRelease.id).where(
        PolicyRelease.org_id == org_id, PolicyRelease.number == number, PolicyRelease.bundle_sha256 == sha,
        PolicyRelease.status.in_(("in_force", "superseded"))))).first()
    if signed is None:
        return f"the receipt names release #{number}, which was never signed with that bundle"
    return None
