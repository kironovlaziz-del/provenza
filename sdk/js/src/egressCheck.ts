// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

/**
 * The agent host's egress self-check: is this host confined to the Provenza
 * egress proxy? The server names targets on the internet and a beacon on
 * itself; this host tries each directly (TCP connect; an HTTP GET for the
 * beacon) and reports what it reached, signed. "confined" = nothing reached
 * and the server did not see the beacon. See docs/egress-lockdown.md.
 */

import { connect as netConnect } from "node:net";

export function splitTarget(target: string): [string, number] {
  const i = target.lastIndexOf(":");
  return [target.slice(0, i).replace(/^\[|\]$/g, ""), Number(target.slice(i + 1))];
}

export function connect(target: string, timeoutMs: number): Promise<boolean> {
  const [host, port] = splitTarget(target);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) return Promise.resolve(false);
  return new Promise((resolve) => {
    const socket = netConnect({ host, port });
    const done = (ok: boolean) => { socket.destroy(); resolve(ok); };
    socket.setTimeout(timeoutMs, () => done(false));
    socket.once("connect", () => done(true));
    socket.once("error", () => done(false));
  });
}

export async function beacon(url: string, timeoutMs: number, fetchFn: typeof fetch = globalThis.fetch): Promise<boolean> {
  try {
    const r = await fetchFn(url, { redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
    return r.status === 204;
  } catch {
    return false;
  }
}

/** What the server verifies: the results sorted by target. */
export function egressPayload(agentId: number, checkId: number, results: { target: string; reachable: boolean }[],
                              beaconReached: boolean) {
  return {
    type: "egress.report", agent_id: agentId, check_id: checkId,
    results: [...results].map((r) => ({ target: r.target, reachable: !!r.reachable }))
      .sort((a, b) => (a.target < b.target ? -1 : a.target > b.target ? 1 : 0)),
    beacon_reached: !!beaconReached,
  };
}
