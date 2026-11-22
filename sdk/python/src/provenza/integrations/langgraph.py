# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Govern a LangGraph agent's tools (pip install 'provenza[langgraph]').

    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.prebuilt import create_react_agent        # or your own graph with a ToolNode
    from provenza.integrations.langgraph import govern_tools, resume_command

    graph = create_react_agent(model, govern_tools(agent, [send_payment, lookup]),
                               checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "order-1042"}}
    result = graph.invoke({"messages": [("user", "Refund order 1042")]}, config)

    while "__interrupt__" in result:                          # a call waits for a person
        command = resume_command(agent, result)               # waits for the decision
        if command is None:
            break                                             # still undecided: try again later
        result = graph.invoke(command, config)

The tools are the LangChain integration's (provenza.integrations.langchain),
with approval="interrupt" by default: when policy holds a call for a person,
the graph pauses with interrupt() - its state kept by the checkpointer, for
as long as the decision takes - instead of blocking a thread. Resume it with
resume_command() once decided: approved, the tool runs again and the server
lets exactly that call through, once; denied or expired, the model is told
so and nothing ran. A graph needs a checkpointer to be interrupted.

resume_command() notes the decision in this process. A graph resumed in
another process, or with a Command of your own, still never runs an
unapproved call: the repeat is checked again, and one that is still held is
refused (the new request waits in the Inbox).

Other approval modes (approval="refuse" | "wait") are the LangChain
integration's. Interrupting inside an async tool needs Python 3.11 or newer
(LangGraph's own requirement).
"""

import time
from typing import Any, Iterable, List, Sequence

from provenza.integrations import _approvals
from provenza.integrations.langchain import INTERRUPT_TYPE
from provenza.integrations.langchain import govern_tool as _govern_tool


def govern_tool(agent, tool, *, name: str = None, approval: str = "interrupt",
                approval_timeout: float = _approvals.WAIT_TIMEOUT):
    return _govern_tool(agent, tool, name=name, approval=approval, approval_timeout=approval_timeout)


def govern_tools(agent, tools: Sequence, *, prefix: str = "", approval: str = "interrupt",
                 approval_timeout: float = _approvals.WAIT_TIMEOUT) -> List:
    """Governed copies of LangChain tools for a LangGraph graph (ToolNode,
    create_react_agent); `prefix` namespaces their governed names."""
    return [govern_tool(agent, t, name=prefix + t.name, approval=approval, approval_timeout=approval_timeout)
            for t in tools]


def approvals(result: Any) -> List[Any]:
    """The Provenza approval interrupts in a graph's result (the dict invoke()
    returns), a StateSnapshot (graph.get_state(config)) or a list of Interrupt."""
    if isinstance(result, dict):
        items: Iterable = result.get("__interrupt__") or ()
    elif hasattr(result, "interrupts"):
        items = result.interrupts or ()
    else:
        items = result or ()
    return [i for i in items if isinstance(getattr(i, "value", None), dict) and i.value.get("type") == INTERRUPT_TYPE]


def _resume(agent, held: List[Any], states: List[dict]):
    from langgraph.types import Command

    if any(s.get("decision") == "pending_approval" for s in states):
        return None
    values = {}
    for intr, state in zip(held, states):
        v = intr.value
        _approvals.note_decision(agent, v["tool"], v["arguments"], v.get("chain_id"), state["decision"])
        values[intr.id] = {"action_id": v["action_id"], "decision": state["decision"]}
    return Command(resume=values)


def resume_command(agent, result: Any, *, timeout: float = _approvals.WAIT_TIMEOUT):
    """Wait until every held call in `result` is decided (or `timeout` seconds
    pass) and return the Command that resumes the graph - None if a decision
    is still pending. Interrupts of your own in `result` are left to you: the
    Command answers Provenza's only."""
    held = approvals(result)
    if not held:
        return None
    deadline = time.monotonic() + timeout       # one wait for all of them, not one each
    states = [agent.wait_for_approval(i.value["action_id"], timeout=max(0.0, deadline - time.monotonic()))
              for i in held]
    return _resume(agent, held, states)


async def aresume_command(agent, result: Any, *, timeout: float = _approvals.WAIT_TIMEOUT):
    held = approvals(result)
    if not held:
        return None
    deadline = time.monotonic() + timeout
    states = [await agent.await_for_approval(i.value["action_id"], timeout=max(0.0, deadline - time.monotonic()))
              for i in held]
    return _resume(agent, held, states)
