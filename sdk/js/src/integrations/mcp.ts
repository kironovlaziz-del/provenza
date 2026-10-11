// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

/**
 * Connection settings for Provenza's MCP gateway - point any MCP client there
 * instead of at the MCP servers themselves:
 *
 *   import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
 *   const { url, headers } = connection(agent);
 *   new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers } });
 *
 * Only approved tools, in their approved definition; every call checked and
 * recorded; upstream credentials stay in Provenza. Tool names are
 * "<server slug>.<tool>".
 */

import type { Agent } from "../agent.js";

export const MCP_PATH = "/api/v1/mcp";

export function connection(agent: Agent): { url: string; headers: Record<string, string> } {
  const c = agent.credentials();
  return { url: c.serverUrl + MCP_PATH, headers: { Authorization: `Bearer ${c.apiKey}` } };
}

/** The "mcpServers" entry most MCP clients read. It holds the agent's key: store it like the identity file. */
export function clientConfig(agent: Agent, name = "provenza") {
  const { url, headers } = connection(agent);
  return { mcpServers: { [name]: { type: "http", url, headers } } };
}
