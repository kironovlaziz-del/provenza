// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

import type { GatewayTool } from "./agent_api";

/**
 * The names in an agent's "Allowed tools" that its gateways will not show it:
 * `unknown` - no MCP server or HTTP tool has that name (a typo, or a tool the
 * agent runs itself, which needs no gateway); `notApproved` - a synced MCP tool
 * not approved yet, or whose definition changed since. Exact names: rights are
 * a list, not patterns.
 */
export function toolNameProblems(names: string[], known: GatewayTool[] | null): { unknown: string[]; notApproved: string[] } {
  if (!known) return { unknown: [], notApproved: [] };
  const byName = new Map(known.map((t) => [t.name, t]));
  const unknown: string[] = [];
  const notApproved: string[] = [];
  for (const raw of names) {
    const name = raw.trim();
    if (!name) continue;
    const tool = byName.get(name);
    if (!tool) unknown.push(name);
    else if (!tool.usable) notApproved.push(name);
  }
  return { unknown, notApproved };
}

/** "a, b ,, c" -> ["a", "b", "c"] */
export function splitNames(s: string): string[] {
  return s.split(",").map((x) => x.trim()).filter(Boolean);
}
