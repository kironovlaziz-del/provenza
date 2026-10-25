// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

/**
 * OpenAI-compatible clients through Provenza's LLM gateway - no openai
 * dependency here, just the options:
 *
 *   import OpenAI from "openai";
 *   import { gatewayOptions } from "provenza/integrations/openai";
 *   const client = new OpenAI(gatewayOptions(agent));
 *
 * Every call is then a PVP action of the agent ("model_call" on
 * "llm.<model>"), decided by the server like any other action (allowed models
 * and providers, agent policies, the delegation chain, quarantine, the breaker,
 * limits), and the provider key never reaches the agent. Calls made inside a
 * delegation chain: gatewayOptions(agent, { chainId }). Any provider the organization routed is reached through this
 * one endpoint. The gateway does not stream yet.
 */

import type { Agent } from "../agent.js";

export const GATEWAY_PATH = "/api/v1/gateway/v1";
export const CHAIN_HEADER = "X-Provenza-Chain-Id";

export interface GatewayOptions {
  baseURL: string;
  apiKey: string;
  defaultHeaders?: Record<string, string>;
}

export function gatewayOptions(agent: Agent, opts: { chainId?: number } = {}): GatewayOptions {
  const c = agent.credentials();
  const out: GatewayOptions = { baseURL: c.serverUrl + GATEWAY_PATH, apiKey: c.apiKey };
  if (opts.chainId !== undefined) {
    if (!Number.isSafeInteger(opts.chainId) || opts.chainId < 1) throw new RangeError("chainId must be a positive integer");
    out.defaultHeaders = { [CHAIN_HEADER]: String(opts.chainId) };
  }
  return out;
}
