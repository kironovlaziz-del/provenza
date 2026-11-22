# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The OpenAI Agents SDK (pip install 'provenza[openai-agents]', openai-agents >= 0.4).

    from agents import Agent as OpenAIAgent, Runner, function_tool
    from provenza.integrations.openai_agents import gateway_model, govern_tools

    assistant = OpenAIAgent(
        name="Support",
        instructions="...",
        model=gateway_model(agent, "gpt-4o-mini"),     # the model call through Provenza's LLM gateway
        tools=govern_tools(agent, [lookup_order, refund]),
    )
    result = await Runner.run(assistant, "Refund order 1042")

govern_tools: each function tool keeps its name, description, JSON schema
and every other setting (guardrails, needs_approval, timeouts); only how it
is invoked changes - checked, run only if allowed, recorded. A refusal is the
tool's result ("Refused by Provenza: ..."), so the model can adapt; nothing
ran. Hosted tools (web search, file search, computer use) run on OpenAI's
side, not in your process, and cannot be governed here: they are refused
with a TypeError rather than passed through ungoverned.

A call that policy holds for a person (approval=): "refuse" (default) or
"wait" - block until a person decides, then repeat the call once.

gateway_model: the model calls go through Provenza's OpenAI-compatible
gateway (provenza.integrations.openai) with the agent's own key - decided by
the server, the provider key never reaching the agent. The gateway speaks
Chat Completions and does not stream: use Runner.run / run_sync, not
run_streamed. The Agents SDK's tracing exports to OpenAI with
OPENAI_API_KEY; turn it off (agents.set_tracing_disabled(True)) or point it
elsewhere if that key should not be used.

Tools on MCP servers: connect the Agents SDK to Provenza's MCP gateway
(provenza.integrations.mcp.connection), which governs them on the server.
"""

import dataclasses
import json
from typing import Any, List, Optional, Sequence

from provenza.errors import ProvenzaDenied, ProvenzaUnavailable
from provenza.integrations import _approvals


def govern_tool(agent, tool, *, name: str = None, approval: str = "refuse",
                approval_timeout: float = _approvals.WAIT_TIMEOUT):
    """A governed copy of an Agents SDK FunctionTool (the original is left as
    it was). `name` is what policies and the Tool Registry call it (default:
    the tool's own name)."""
    from agents import FunctionTool

    if not isinstance(tool, FunctionTool):
        raise TypeError(f"{getattr(tool, 'name', type(tool).__name__)}: only function tools run in this process "
                        "and can be governed here; reach MCP tools through Provenza's MCP gateway")
    _approvals.check_mode(approval)
    governed_name = name or tool.name
    invoke = tool.on_invoke_tool

    async def governed(ctx: Any, input_json: str) -> Any:
        try:
            arguments = json.loads(input_json) if input_json else {}
        except ValueError:
            return "Refused by Provenza: the tool's arguments are not valid JSON"
        if not isinstance(arguments, dict):
            return "Refused by Provenza: the tool's arguments are not a JSON object"
        try:
            return await _approvals.acall(agent, governed_name, arguments, lambda: invoke(ctx, input_json),
                                          approval, approval_timeout)
        except (ProvenzaDenied, ProvenzaUnavailable) as exc:
            return f"Refused by Provenza: {exc}"

    return dataclasses.replace(tool, on_invoke_tool=governed)


def govern_tools(agent, tools: Sequence, *, prefix: str = "", approval: str = "refuse",
                 approval_timeout: float = _approvals.WAIT_TIMEOUT) -> List:
    """Governed copies of function tools; `prefix` namespaces their governed
    names (e.g. "shop." -> "shop.refund")."""
    return [govern_tool(agent, t, name=prefix + t.name, approval=approval, approval_timeout=approval_timeout)
            for t in tools]


def gateway_model(agent, model: str, chain_id: Optional[int] = None, **client_kwargs: Any):
    """An Agents SDK model whose calls go through Provenza's LLM gateway."""
    from agents import OpenAIChatCompletionsModel

    from provenza.integrations.openai import async_gateway_client

    return OpenAIChatCompletionsModel(model=model,
                                      openai_client=async_gateway_client(agent, chain_id, **client_kwargs))
