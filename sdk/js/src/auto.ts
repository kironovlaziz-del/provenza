// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

/**
 * Auto-instrumentation: govern every direct call this process makes to an AI
 * provider through the global fetch - the OpenAI, Anthropic and Google SDKs,
 * LangChain.js provider clients, plain fetch - without changing that code.
 *
 *   import { instrument } from "provenza/auto";
 *   await instrument(agent);
 *
 * The same rules as the Python SDK's provenza.auto (docs/pvp/spec.md, 5.4): a
 * request whose host is an AI provider in the organization's AI domain catalog
 * becomes an "egress" action that the SERVER decides (blocked in the catalog
 * -> refused; allowed / not classified -> sent unless a policy refuses it).
 * Recorded: host, method, path (no query string), SHA-256 and size of the
 * body - never the prompt - and the response's status and size.
 *
 * A refusal is a Response, not a thrown error: 403 with an OpenAI-style error
 * body and "x-should-retry: false", so provider SDKs raise their permission
 * error with Provenza's reason and do not retry. Server unreachable: 503, not
 * sent. Other hosts and calls to Provenza itself are untouched.
 *
 * Not covered: clients that do not use the global fetch (node:http, axios,
 * got). The egress proxy (next stage) covers every client.
 */

import { createHash } from "node:crypto";

import type { Agent } from "./agent.js";
import { ProvenzaDenied, ProvenzaRequestError, ProvenzaUnavailable } from "./errors.js";

export const ACTION_TYPE = "egress";
export const PREFIX = "egress.";
export const DEFAULT_DOMAINS = [
  "openai.com", "anthropic.com", "claude.ai", "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
  "openai.azure.com", "bedrock-runtime.amazonaws.com", "mistral.ai", "cohere.com", "cohere.ai", "deepseek.com",
  "x.ai", "groq.com", "openrouter.ai", "together.xyz", "fireworks.ai", "perplexity.ai", "replicate.com",
  "huggingface.co", "stability.ai", "elevenlabs.io",
];

/** The most specific catalog domain covering host (exact or a dot-bounded suffix). */
export function match(host: string, domains: Iterable<string>): string | null {
  host = host.toLowerCase().replace(/\.$/, "");
  let best: string | null = null;
  for (const d of domains) {
    if ((host === d || host.endsWith("." + d)) && (best === null || d.length > best.length)) best = d;
  }
  return best;
}

export class Instrumentation {
  domains = new Map<string, string>(DEFAULT_DOMAINS.map((d) => [d, "unknown"]));
  private fetchedAt = 0;
  private readonly serverHost: string | null;

  constructor(readonly agent: Agent, private readonly refreshMs: number) {
    this.serverHost = agent.serverUrl ? new URL(agent.serverUrl).hostname.toLowerCase() : null;
  }

  async refresh(): Promise<void> {
    if (this.agent.mode !== "connected") return;
    this.fetchedAt = Date.now();
    try {
      const catalog = await this.agent.egressCatalog();
      const next = new Map<string, string>();
      for (const d of catalog.domains ?? []) if (d?.domain) next.set(String(d.domain).toLowerCase(), d.status ?? "unknown");
      if (next.size) this.domains = next;
    } catch (exc) {
      if (!(exc instanceof ProvenzaUnavailable || exc instanceof ProvenzaRequestError)) throw exc;
    }
  }

  governs(host: string): boolean {
    host = host.toLowerCase();
    if (!host || host === this.serverHost) return false;
    if (Date.now() - this.fetchedAt > this.refreshMs) void this.refresh();
    return match(host, this.domains.keys()) !== null;
  }
}

const REFUSAL_HEADERS = { "content-type": "application/json", "x-should-retry": "false", "x-provenza-refused": "1" };

function refusal(exc: ProvenzaDenied | ProvenzaUnavailable): Response {
  const denied = exc instanceof ProvenzaDenied;
  const code = denied ? "provenza_denied" : "provenza_unavailable";
  const message = denied ? `Refused by Provenza: ${exc.reason}` : `Provenza is unreachable; the request was not sent (${exc.message})`;
  return new Response(JSON.stringify({ error: { message, type: code, code } }), { status: denied ? 403 : 503,
                                                                                    headers: REFUSAL_HEADERS });
}

let state: Instrumentation | null = null;
let original: typeof fetch | null = null;

/** Start governing this process's direct calls to AI providers; calling it again switches the agent. */
export async function instrument(agent: Agent, opts: { refreshMs?: number } = {}): Promise<Instrumentation> {
  const inst = new Instrumentation(agent, opts.refreshMs ?? 300_000);
  await inst.refresh();
  state = inst;
  if (original) return inst;
  const orig = globalThis.fetch;
  original = orig;
  globalThis.fetch = async function governedFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const current = state;
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (!current || !current.governs(url.hostname)) return orig(request);
    const body = request.body ? Buffer.from(await request.clone().arrayBuffer()) : null;
    const args = {
      host: url.hostname.toLowerCase(), method: request.method.toUpperCase(), path: url.pathname || "/",
      body_sha256: body ? createHash("sha256").update(body).digest("hex") : null, body_bytes: body ? body.length : null,
    };
    try {
      return await current.agent.call(PREFIX + args.host, args, () => orig(request), {
        actionType: ACTION_TYPE,
        outputOf: (r: Response) => ({ status: r.status, bytes: Number(r.headers.get("content-length")) || null }),
      });
    } catch (exc) {
      if (exc instanceof ProvenzaDenied || exc instanceof ProvenzaUnavailable) return refusal(exc);
      throw exc;
    }
  };
  return inst;
}

/** Put the global fetch back as it was. */
export function uninstrument(): void {
  if (original) globalThis.fetch = original;
  original = null;
  state = null;
}
