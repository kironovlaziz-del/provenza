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
 * Every call is then checked by the server (allowed models and providers,
 * policies, limits), and the provider key never reaches
 * the agent. Any provider the organization routed is reached through this
 * one endpoint. The gateway does not stream yet.
 */

import type { Agent } from "../agent.js";

export const GATEWAY_PATH = "/api/v1/gateway/v1";

export function gatewayOptions(agent: Agent): { baseURL: string; apiKey: string } {
  const c = agent.credentials();
  return { baseURL: c.serverUrl + GATEWAY_PATH, apiKey: c.apiKey };
}
