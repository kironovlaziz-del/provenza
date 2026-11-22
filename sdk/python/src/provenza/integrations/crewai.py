# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Govern CrewAI tools (pip install 'provenza[crewai]', crewai >= 1.0).

    from provenza.integrations.crewai import govern_tools
    researcher = Agent(role="...", goal="...", tools=govern_tools(agent, [search_tool]))

Each tool keeps its name, description and argument schema. A refused call
raises ProvenzaDenied inside the tool; CrewAI reports the failure to the
model; nothing ran.

A call that policy holds for a person (approval=): "refuse" (default) or
"wait" - block until a person decides, then repeat the call once.
"""

from typing import Any, List, Sequence

from provenza.integrations import _approvals


def govern_tool(agent, tool, *, name: str = None, approval: str = "refuse",
                approval_timeout: float = _approvals.WAIT_TIMEOUT):
    from crewai.tools import BaseTool

    _approvals.check_mode(approval)
    governed_name = name or tool.name

    class GovernedTool(BaseTool):
        def _run(self, **kwargs: Any) -> Any:
            return _approvals.call(agent, governed_name, kwargs, lambda: tool.run(**kwargs), approval,
                                   approval_timeout)

        async def _arun(self, **kwargs: Any) -> Any:
            return await _approvals.acall(agent, governed_name, kwargs, lambda: tool.arun(**kwargs), approval,
                                          approval_timeout)

    return GovernedTool(name=tool.name, description=tool.description, args_schema=tool.args_schema)


def govern_tools(agent, tools: Sequence, *, prefix: str = "", approval: str = "refuse",
                 approval_timeout: float = _approvals.WAIT_TIMEOUT) -> List:
    return [govern_tool(agent, t, name=prefix + t.name, approval=approval, approval_timeout=approval_timeout)
            for t in tools]
