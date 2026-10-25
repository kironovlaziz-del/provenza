// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

/**
 * Requests through the Provenza egress proxy in SDK mode (docs/pvp/spec.md, 5.5):
 * the agent checks the request itself and sends the check id; the proxy redeems
 * it and refuses anything other than exactly the checked request.
 *
 *   const chk = await agent.proxyCheck("stripe", "POST", "/v1/charges", { body });
 *   await fetch("http://127.0.0.1:8443/stripe/v1/charges", { method: "POST", body, headers: proxyHeaders(chk) });
 *
 * `path` and `query` are exactly what goes on the wire (percent-encoding kept),
 * `body` the exact bytes: the proxy hashes what it receives. The headers carry the
 * agent's signed request too: a proxy that enforces the signed policy verifies the
 * agent's signature itself (docs/pvp/edge.md, section 4).
 */

import { createHash } from "node:crypto";

export const PROXY_ACTION_TYPE = "proxy";
export const PROXY_HEADER = "X-Provenza-Check-Id";
/** The agent's signed action.request, for a proxy that enforces the signed policy. */
export const PROXY_REQUEST_HEADER = "X-Provenza-Request";

export type RawBytes = string | Uint8Array | null | undefined;

export interface ProxyDescriptor {
  route: string;
  method: string;
  path: string;
  query_sha256: string | null;
  body_sha256: string | null;
  body_bytes: number;
}

function raw(value: RawBytes): Buffer {
  if (value === null || value === undefined) return Buffer.alloc(0);
  return typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value);
}

function sha(b: Buffer): string | null {
  return b.length ? createHash("sha256").update(b).digest("hex") : null;
}

/** The checked input of a proxy request - hashes only, as the proxy computes it. */
export function proxyDescriptor(route: string, method: string, path: string,
                                opts: { query?: RawBytes; body?: RawBytes } = {}): ProxyDescriptor {
  if (!path.startsWith("/")) throw new TypeError("path must start with /");
  if (path.includes("?")) throw new TypeError("pass the query string as query, not in path");
  const body = raw(opts.body);
  return { route, method: method.toUpperCase(), path, query_sha256: sha(raw(opts.query)), body_sha256: sha(body),
           body_bytes: body.length };
}

/** The check id the egress proxy redeems, and the agent's signed request, which
 *  a proxy enforcing the signed policy verifies with the key the signed manifest names. */
export function proxyHeaders(check: { checkId: string; request?: unknown }): Record<string, string> {
  const headers: Record<string, string> = { [PROXY_HEADER]: check.checkId };
  if (check.request) {
    headers[PROXY_REQUEST_HEADER] = Buffer.from(JSON.stringify(check.request), "utf8").toString("base64url");
  }
  return headers;
}
