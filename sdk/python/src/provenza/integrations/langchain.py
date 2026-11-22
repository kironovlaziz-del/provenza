# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Govern LangChain tools (pip install 'provenza[langchain]', langchain-core >= 0.3).

    from provenza.integrations.langchain import govern_tools
    tools = govern_tools(agent, [search, read_file])     # hand these to your agent instead

Each tool keeps its name, description and argument schema - the model sees
no difference. Every call is checked, run only if allowed, and recorded. A
refusal comes back to the model as the tool's answer ("Refused by Provenza:
...", via LangChain's ToolException) instead of crashing the run, so the
model can adapt; nothing ran.

A call that policy holds for a person (approval=):
  "refuse"     (default) refused like any other, saying it waits for approval
  "wait"       blocks until a person decides, then repeats the call: approved,
               it runs once; denied or expired, it is refused
  "interrupt"  inside a LangGraph graph: the graph pauses (interrupt()) and is
               resumed after the decision - see provenza.integrations.langgraph

Why not a callback handler: LangChain callbacks observe, and swallow their
own errors unless told otherwise - they cannot stop a tool. Wrapping can.
"""

from typing import Any, List, Sequence

from provenza.errors import ProvenzaApprovalRequired, ProvenzaDenied, ProvenzaUnavailable
from provenza.integrations import _approvals

INTERRUPT_TYPE = "provenza.approval_required"


def _payload(tool: str, arguments: dict, held: ProvenzaApprovalRequired) -> dict:
    from provenza.agent import _json_value
    return {"type": INTERRUPT_TYPE, "tool": tool, "arguments": _json_value(arguments, "tool arguments"),
            "chain_id": _approvals.current_chain(), "action_id": held.action_id, "reason": held.reason}


def _decided_before(agent, tool: str, arguments: dict) -> None:
    """A resumed graph: the decision its resume waited for (langgraph.resume_command).
    Approved: the call is made again and the server lets it through once.
    Denied or expired: refused here, without holding a second request."""
    decision = _approvals.take_decision(agent, tool, arguments)
    if decision is not None and decision != "approved":
        raise ProvenzaDenied(tool, f"the approval was {decision}", decision)


def govern_tool(agent, tool, *, name: str = None, approval: str = "refuse",
                approval_timeout: float = _approvals.WAIT_TIMEOUT):
    """One governed copy of a LangChain BaseTool. `name` is what policies
    and the Tool Registry call it (default: the tool's own name)."""
    from langchain_core.tools import StructuredTool, ToolException

    _approvals.check_mode(approval, _approvals.MODES)
    governed_name = name or tool.name
    if approval == "interrupt":
        from langgraph.types import interrupt     # pip install langgraph

    def run(**kwargs: Any) -> Any:
        try:
            if approval != "interrupt":
                return _approvals.call(agent, governed_name, kwargs, lambda: tool.invoke(kwargs), approval,
                                       approval_timeout)
            _decided_before(agent, governed_name, kwargs)
            try:
                return agent.call(governed_name, kwargs, lambda: tool.invoke(kwargs))
            except ProvenzaApprovalRequired as held:
                if held.action_id is None:
                    raise
                interrupt(_payload(governed_name, kwargs, held))
                # resumed, and the repeat is held again (resumed before a decision,
                # or the approval could not be used): refused, the new request waits
                raise
        except (ProvenzaDenied, ProvenzaUnavailable) as exc:
            raise ToolException(f"Refused by Provenza: {exc}") from exc

    async def arun(**kwargs: Any) -> Any:
        try:
            if approval != "interrupt":
                return await _approvals.acall(agent, governed_name, kwargs, lambda: tool.ainvoke(kwargs), approval,
                                              approval_timeout)
            _decided_before(agent, governed_name, kwargs)
            try:
                return await agent.acall(governed_name, kwargs, lambda: tool.ainvoke(kwargs))
            except ProvenzaApprovalRequired as held:
                if held.action_id is None:
                    raise
                interrupt(_payload(governed_name, kwargs, held))
                raise
        except (ProvenzaDenied, ProvenzaUnavailable) as exc:
            raise ToolException(f"Refused by Provenza: {exc}") from exc

    return StructuredTool.from_function(
        func=run, coroutine=arun, name=tool.name, description=tool.description,
        args_schema=tool.args_schema or tool.get_input_schema(), return_direct=tool.return_direct,
        handle_tool_error=True,
    )


def govern_tools(agent, tools: Sequence, *, prefix: str = "", approval: str = "refuse",
                 approval_timeout: float = _approvals.WAIT_TIMEOUT) -> List:
    """Governed copies of LangChain tools; `prefix` namespaces their
    governed names (e.g. "search." -> "search.web")."""
    return [govern_tool(agent, t, name=prefix + t.name, approval=approval, approval_timeout=approval_timeout)
            for t in tools]
