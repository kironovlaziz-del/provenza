# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
What a governed tool does when policy holds its call for a person - the one
place every integration takes it from.

    approval="refuse"   (the default) the call did not run; the refusal goes back
                        to the model like any other ("waiting for approval")
    approval="wait"     block until a person decides (agent.wait_for_approval),
                        then make exactly the same call again: approved, it runs
                        once; denied or expired, it is refused
    approval="interrupt"  LangGraph only (integrations/langgraph.py): the graph
                        pauses with interrupt() and resumes after the decision

Nothing here can make a call run without a person's approval: the repeat is
checked by the server like the first call, and only an approval signed for
exactly this agent, chain, tool and arguments lets it through, once
(backend app/pvp/approvals.py).
"""

import weakref
from typing import Any, Callable, Dict, Optional, Tuple

from provenza.crypto import content_hash
from provenza.errors import ProvenzaApprovalRequired, ProvenzaDenied

MODES = ("refuse", "wait", "interrupt")
WAIT_TIMEOUT = 600.0

# decisions a resume helper already waited for, per agent: a resumed tool reads
# its own instead of asking the server again (which would hold a second request)
_decided: "weakref.WeakKeyDictionary[Any, Dict[Tuple[str, str, Optional[int]], str]]" = weakref.WeakKeyDictionary()


def check_mode(approval: str, allowed: Tuple[str, ...] = ("refuse", "wait")) -> str:
    if approval not in allowed:
        raise ValueError(f"approval must be one of {', '.join(allowed)}, not {approval!r}")
    return approval


def current_chain() -> Optional[int]:
    from provenza.agent import _chain
    return _chain.get()


def note_decision(agent, tool: str, arguments: Dict[str, Any], chain_id: Optional[int], decision: str) -> None:
    _decided.setdefault(agent, {})[(tool, content_hash(arguments), chain_id)] = decision


def take_decision(agent, tool: str, arguments: Dict[str, Any]) -> Optional[str]:
    return _decided.get(agent, {}).pop((tool, content_hash(arguments), current_chain()), None)


def not_approved(tool: str, state: Dict[str, Any], held: ProvenzaApprovalRequired) -> ProvenzaDenied:
    """A held call that a person denied, that expired, or that is still waiting
    when the wait ends."""
    decision = state.get("decision") or "pending_approval"
    if decision == "pending_approval":
        return held
    return ProvenzaDenied(tool, f"the approval was {decision}", decision, check_id=held.check_id,
                          action_id=held.action_id)


def call(agent, tool: str, arguments: Dict[str, Any], fn: Callable[[], Any], approval: str = "refuse",
         timeout: float = WAIT_TIMEOUT) -> Any:
    try:
        return agent.call(tool, arguments, fn)
    except ProvenzaApprovalRequired as held:
        if approval != "wait" or held.action_id is None:
            raise
        state = agent.wait_for_approval(held.action_id, timeout=timeout)
        if state.get("decision") != "approved":
            raise not_approved(tool, state, held) from None
        return agent.call(tool, arguments, fn)


async def acall(agent, tool: str, arguments: Dict[str, Any], fn: Callable[[], Any], approval: str = "refuse",
                timeout: float = WAIT_TIMEOUT) -> Any:
    try:
        return await agent.acall(tool, arguments, fn)
    except ProvenzaApprovalRequired as held:
        if approval != "wait" or held.action_id is None:
            raise
        state = await agent.await_for_approval(held.action_id, timeout=timeout)
        if state.get("decision") != "approved":
            raise not_approved(tool, state, held) from None
        return await agent.acall(tool, arguments, fn)
