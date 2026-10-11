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

Why not a callback handler: LangChain callbacks observe, and swallow their
own errors unless told otherwise - they cannot stop a tool. Wrapping can.
"""

from typing import Any, List, Sequence

from provenza.errors import ProvenzaDenied, ProvenzaUnavailable


def govern_tool(agent, tool, *, name: str = None):
    """One governed copy of a LangChain BaseTool. `name` is what policies
    and the Tool Registry call it (default: the tool's own name)."""
    from langchain_core.tools import StructuredTool, ToolException

    governed_name = name or tool.name

    def run(**kwargs: Any) -> Any:
        try:
            return agent.call(governed_name, kwargs, lambda: tool.invoke(kwargs))
        except (ProvenzaDenied, ProvenzaUnavailable) as exc:
            raise ToolException(f"Refused by Provenza: {exc}") from exc

    async def arun(**kwargs: Any) -> Any:
        try:
            return await agent.acall(governed_name, kwargs, lambda: tool.ainvoke(kwargs))
        except (ProvenzaDenied, ProvenzaUnavailable) as exc:
            raise ToolException(f"Refused by Provenza: {exc}") from exc

    return StructuredTool.from_function(
        func=run, coroutine=arun, name=tool.name, description=tool.description,
        args_schema=tool.args_schema or tool.get_input_schema(), return_direct=tool.return_direct,
        handle_tool_error=True,
    )


def govern_tools(agent, tools: Sequence, *, prefix: str = "") -> List:
    """Governed copies of LangChain tools; `prefix` namespaces their
    governed names (e.g. "search." -> "search.web")."""
    return [govern_tool(agent, t, name=prefix + t.name) for t in tools]
