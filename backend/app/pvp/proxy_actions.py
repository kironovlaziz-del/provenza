# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Actions an egress proxy executes for the gateways (docs/pvp/edge.md,
section 4): HTTP tools, LLM calls, MCP tool calls and A2A messages whose
upstream takes a credential. This server holds no credential (app/pvp/
sealed.py), so it cannot execute them; it still decides and records them.

    agent ──► proxy /_tools, /_llm, /_mcp, /_a2a  (the agent's own protocol)
                │
                ├─► POST /egress-proxy/<kind>/plan   the agent's request (metadata, or
                │       the arguments where they are the recorded input), judged here
                │       exactly as the gateway judges it - a refusal is recorded at once
                │       and the check of an allowed one is reserved for this proxy
                ▼
         upstream, with the credential sealed to the proxy (only to its origin)
                │
                └─► POST /egress-proxy/complete     what it did - metadata and hashes,
                        never the content - with the proxy's signed receipt

The recorded action has executed_by "egress_proxy" and its input is what the
gateway would record; the output is what the proxy reports.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_signing import content_hash
from app.core.errors import api_error
from app.models.agent import Agent
from app.models.agent_action import ActionCheck
from app.models.egress_proxy import EgressProxy, EgressRedemption

EXECUTOR = "egress_proxy"


async def agent_for(db: AsyncSession, proxy: EgressProxy, agent_key: Optional[str]) -> Agent:
    """The agent whose key reached the proxy: of the proxy's organization,
    active, and attested where its role requires it - as for an agent
    calling Provenza itself."""
    from app.services.agent_identity import agent_by_key
    from app.services.attestation import refusal

    agent = await agent_by_key(db, agent_key) if agent_key else None
    if agent is None or agent.org_id != proxy.org_id:
        raise api_error(status.HTTP_401_UNAUTHORIZED, "egress.agent_key_invalid")
    if agent.status != "active":
        raise api_error(status.HTTP_403_FORBIDDEN, "egress.agent_inactive")
    code = await refusal(db, agent)
    if code:
        raise api_error(status.HTTP_403_FORBIDDEN, code)
    return agent


async def reserve(db: AsyncSession, proxy: EgressProxy, check_token: str, input_data: Dict[str, Any]) -> None:
    """An allowed check, for this proxy only: spent here (nobody else can use
    it), recorded when the proxy completes it (app/pvp/egress_proxy.complete)."""
    chk = (await db.execute(select(ActionCheck).where(ActionCheck.token == check_token,
                                                      ActionCheck.org_id == proxy.org_id)
                            .with_for_update())).scalar_one()
    if chk.used_at is not None or chk.input_sha256 != content_hash(input_data):
        raise api_error(status.HTTP_409_CONFLICT, "egress.check_used")
    now = datetime.now(timezone.utc)
    chk.used_at = now
    from app.pvp.enforcement import agent_signed

    if agent_signed.get():
        chk.agent_signed = True   # the agent's own signed request was verified for this call
    db.add(EgressRedemption(org_id=proxy.org_id, check_id=chk.id, proxy_id=proxy.id, route_id=None,
                            agent_id=chk.agent_id, descriptor=input_data, reserved_at=now))
    await db.commit()


async def allowed(db: AsyncSession, proxy: EgressProxy, check, input_data: Dict[str, Any]) -> Dict[str, Any]:
    """The check fields a proxy needs to judge the action itself under the
    signed policy and to sign its receipt."""
    from app.pvp import approvals

    return {"decision": "allowed", "reason": check.reason, "check_id": check.check_id,
            "agent_id": check.agent_id, "chain_id": check.chain_id, "action_type": check.action_type,
            "tool_name": check.tool_name, "input_sha256": content_hash(input_data),
            "approval": await approvals.proof_for_check(db, proxy.org_id, check.check_id)}
