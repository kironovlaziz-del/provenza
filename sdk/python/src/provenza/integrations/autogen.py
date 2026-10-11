# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Govern AutoGen tools (pip install 'provenza[autogen]', autogen-core >= 0.4).

    from provenza.integrations.autogen import govern_tools
    tools = govern_tools(agent, [FunctionTool(search, description="...")])
    AssistantAgent("assistant", model_client=..., tools=tools)

Each tool keeps its name, description and argument types (the same JSON
schema reaches the model). A refused call raises ProvenzaDenied inside the
tool, which AutoGen reports to the model as a failed tool call; nothing ran.
"""

from typing import Any, List, Sequence


def govern_tool(agent, tool, *, name: str = None):
    from autogen_core.tools import BaseTool

    governed_name = name or tool.name

    class GovernedTool(BaseTool):
        def __init__(self) -> None:
            super().__init__(tool.args_type(), tool.return_type(), tool.name, tool.description,
                             strict=getattr(tool, "_strict", False))

        async def run(self, args: Any, cancellation_token: Any) -> Any:
            return await agent.acall(governed_name, args.model_dump(mode="json"),
                                     lambda: tool.run(args, cancellation_token))

        def return_value_as_string(self, value: Any) -> str:
            return tool.return_value_as_string(value)

    return GovernedTool()


def govern_tools(agent, tools: Sequence, *, prefix: str = "") -> List:
    return [govern_tool(agent, t, name=prefix + t.name) for t in tools]
