# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
AI agent products the endpoint agent recognizes (agent/collectors/
signatures.go reports their ids in "agent_detected" events).

category:
  coding_agent    edits code and runs commands in a developer's workspace
  agent_framework a framework / runtime that executes agents someone wrote
  agent_platform  a workflow tool that runs agents built in its UI
An unknown id (a newer agent version) is kept as-is and shown by its id.
"""

from typing import Dict, TypedDict


class AgentProduct(TypedDict):
    name: str
    vendor: str
    category: str


AGENT_PRODUCTS: Dict[str, AgentProduct] = {
    "claude_code": {"name": "Claude Code", "vendor": "Anthropic", "category": "coding_agent"},
    "codex_cli": {"name": "Codex CLI", "vendor": "OpenAI", "category": "coding_agent"},
    "gemini_cli": {"name": "Gemini CLI", "vendor": "Google", "category": "coding_agent"},
    "github_copilot": {"name": "GitHub Copilot", "vendor": "GitHub", "category": "coding_agent"},
    "cursor": {"name": "Cursor", "vendor": "Anysphere", "category": "coding_agent"},
    "windsurf": {"name": "Windsurf", "vendor": "Windsurf", "category": "coding_agent"},
    "aider": {"name": "Aider", "vendor": "open source", "category": "coding_agent"},
    "goose": {"name": "Goose", "vendor": "Block", "category": "coding_agent"},
    "opencode": {"name": "OpenCode", "vendor": "open source", "category": "coding_agent"},
    "amazon_q": {"name": "Amazon Q Developer", "vendor": "AWS", "category": "coding_agent"},
    "openhands": {"name": "OpenHands", "vendor": "open source", "category": "coding_agent"},
    "open_interpreter": {"name": "Open Interpreter", "vendor": "open source", "category": "coding_agent"},
    "crewai": {"name": "CrewAI", "vendor": "CrewAI", "category": "agent_framework"},
    "langgraph": {"name": "LangGraph", "vendor": "LangChain", "category": "agent_framework"},
    "autogen_studio": {"name": "AutoGen Studio", "vendor": "Microsoft", "category": "agent_framework"},
    "letta": {"name": "Letta", "vendor": "Letta", "category": "agent_framework"},
    "n8n": {"name": "n8n", "vendor": "n8n", "category": "agent_platform"},
    "flowise": {"name": "Flowise", "vendor": "open source", "category": "agent_platform"},
    "langflow": {"name": "Langflow", "vendor": "DataStax", "category": "agent_platform"},
}

CATEGORIES = ("coding_agent", "agent_framework", "agent_platform")


def describe(product: str) -> AgentProduct:
    """Catalog entry for a product id; unknown ids describe themselves."""
    return AGENT_PRODUCTS.get(product) or {"name": product, "vendor": "", "category": "unknown"}
