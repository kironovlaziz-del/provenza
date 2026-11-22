# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Framework integrations. Each module imports its framework only when used,
and each framework is an extra, never a requirement of the SDK:

  openai      pip install 'provenza[openai]'     the LLM gateway, enforced server-side
  mcp         (no extra)                         connection settings for Provenza's MCP gateway
  langchain   pip install 'provenza[langchain]'  govern LangChain tools
  langgraph   pip install 'provenza[langgraph]'  govern a LangGraph agent's tools; held calls pause the graph
  openai_agents  pip install 'provenza[openai-agents]'  govern OpenAI Agents SDK tools; its model through the gateway
  autogen     pip install 'provenza[autogen]'    govern AutoGen (autogen-core) tools
  crewai      pip install 'provenza[crewai]'     govern CrewAI tools

Every tool wrapper takes approval= for a call that policy holds for a person:
"refuse" (default), "wait" (until a person decides, then repeat the call once),
and in LangGraph "interrupt" (pause the graph). See docs/integrations.md.

Two kinds, and the difference matters:
  gateways (openai, mcp, openai_agents.gateway_model)
                           the call goes THROUGH Provenza, which holds the
                           upstream credentials: enforced whatever the agent's code does
  tool wrappers (the rest) governed inside the agent's process: the agent's
                           record and cooperative enforcement
"""
