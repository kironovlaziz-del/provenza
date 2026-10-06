# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
What an agent may do - computed by the server, never taken from the caller.

Rights of an agent:
  - outside any chain: what it was registered with (capabilities, allowed_tools);
  - inside a chain: what the hop that brought it in delegated, narrowed to
    what it was registered with. The chain's root acts with its own
    registration. An agent that is neither the root nor reached by a hop is
    NOT a member and has no rights in that chain.

Rights only shrink along a chain (monotonic delegation): every hop is
checked against the delegating agent's rights in the same chain, and every
agent is additionally capped by its own registration.

Tools: a hop may name the tools it hands over (a subset of the delegating
agent's tools). Once a hop on the way named tools, they only narrow from
there - a hop that names none inherits that list. Until then each agent uses
its own registered tools, so an orchestrator without tools can still
delegate to workers that have them; capabilities (required by tools through
the Tool Registry) remain the boundary.

What an action needs is derived from the Tool Registry: every entry that
matches the tool (its exact name and any glob) lists capabilities required
to call it (`required_capabilities`); the action needs all of them. Callers
no longer declare capabilities for their actions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.delegation import DelegationChain, DelegationHop


def _set(items: Optional[Iterable[str]]) -> set:
    return {str(x) for x in items} if items else set()


@dataclass
class Rights:
    member: bool
    capabilities: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    depth: int = 0                       # 0 = root / no chain
    expires_at: Optional[datetime] = None
    via_hop_id: Optional[int] = None
    # True once some hop on the way named its tools: from then on tools only
    # narrow. False = the agent uses its own registered tools.
    tools_narrowed: bool = False


def own_rights(agent: Agent) -> Rights:
    return Rights(member=True, capabilities=sorted(_set(agent.capabilities)),
                  tools=sorted(_set(agent.allowed_tools)), depth=0)


async def incoming_hop(db: AsyncSession, chain_id: int, agent_id: int) -> Optional[DelegationHop]:
    """The latest hop that brought the agent into the chain (its current grant)."""
    return (await db.execute(
        select(DelegationHop)
        .where(DelegationHop.chain_id == chain_id, DelegationHop.to_agent_id == agent_id)
        .order_by(DelegationHop.id.desc())
        .limit(1)
    )).scalar_one_or_none()


def hop_rights(agent: Agent, hop: DelegationHop) -> Rights:
    caps = _set(hop.delegated_capabilities) & _set(agent.capabilities)
    # None: no hop on the way named tools - the agent's own registered tools
    narrowed = hop.delegated_tools is not None
    tools = (_set(hop.delegated_tools) & _set(agent.allowed_tools)) if narrowed else _set(agent.allowed_tools)
    return Rights(member=True, capabilities=sorted(caps), tools=sorted(tools), depth=hop.depth,
                  expires_at=hop.expires_at, via_hop_id=hop.id, tools_narrowed=narrowed)


async def rights_in_chain(db: AsyncSession, agent: Agent, chain: Optional[DelegationChain]) -> Rights:
    if chain is None:
        return own_rights(agent)
    hop = await incoming_hop(db, chain.id, agent.id)
    if hop is not None:
        return hop_rights(agent, hop)
    if chain.root_agent_id == agent.id:
        return own_rights(agent)
    return Rights(member=False)


async def required_capabilities(db: AsyncSession, org_id: int, tool: Optional[str]) -> List[str]:
    """Capabilities the Tool Registry requires for calling `tool`: the union
    over EVERY matching entry - the exact name and all globs. (Taking only
    the most specific one would let an auto-discovered exact entry, which
    requires nothing, shadow a "stripe.*" entry that requires "payments".)"""
    if not tool:
        return []
    import fnmatch

    from app.models.tool_registry import ToolRegistryEntry

    entries = (await db.execute(
        select(ToolRegistryEntry.pattern, ToolRegistryEntry.required_capabilities)
        .where(ToolRegistryEntry.org_id == org_id, ToolRegistryEntry.required_capabilities.is_not(None))
    )).all()
    need: set = set()
    for pattern, caps in entries:
        if pattern == tool or fnmatch.fnmatchcase(tool, pattern):
            need |= _set(caps)
    return sorted(need)
