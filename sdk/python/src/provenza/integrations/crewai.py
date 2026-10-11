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
"""

from typing import Any, List, Sequence


def govern_tool(agent, tool, *, name: str = None):
    from crewai.tools import BaseTool

    governed_name = name or tool.name

    class GovernedTool(BaseTool):
        def _run(self, **kwargs: Any) -> Any:
            return agent.call(governed_name, kwargs, lambda: tool.run(**kwargs))

        async def _arun(self, **kwargs: Any) -> Any:
            return await agent.acall(governed_name, kwargs, lambda: tool.arun(**kwargs))

    return GovernedTool(name=tool.name, description=tool.description, args_schema=tool.args_schema)


def govern_tools(agent, tools: Sequence, *, prefix: str = "") -> List:
    return [govern_tool(agent, t, name=prefix + t.name) for t in tools]
