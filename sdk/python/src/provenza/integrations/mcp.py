# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Connection settings for Provenza's MCP gateway - point any MCP client there
instead of at the MCP servers themselves.

    from provenza.integrations.mcp import connection
    conn = connection(agent)          # {"url": ..., "headers": {...}}

    # e.g. the official SDK:  streamablehttp_client(conn["url"], headers=conn["headers"])
    # a client config file:   client_config(agent, "provenza")

The gateway serves only the tools an admin approved, in their approved
definition, checks and records every call, and holds the upstream servers'
credentials (docs/pvp/spec.md, section 5.1). Tool names are
"<server slug>.<tool>". Pass a delegation chain in a call's
_meta["provenza/chain_id"].
"""

from typing import Any, Dict

MCP_PATH = "/api/v1/mcp"


def connection(agent) -> Dict[str, Any]:
    c = agent.credentials()
    return {"url": c["server_url"] + MCP_PATH, "headers": {"Authorization": f"Bearer {c['api_key']}"}}


def client_config(agent, name: str = "provenza") -> Dict[str, Any]:
    """The "mcpServers" entry most MCP clients read (Streamable HTTP).
    It contains the agent's key: store it like the identity file."""
    conn = connection(agent)
    return {"mcpServers": {name: {"type": "http", "url": conn["url"], "headers": conn["headers"]}}}
