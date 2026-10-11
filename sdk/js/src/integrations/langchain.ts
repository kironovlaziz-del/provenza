// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

/**
 * Govern LangChain.js tools (npm install @langchain/core).
 *
 *   import { governTools } from "provenza/integrations/langchain";
 *   const tools = governTools(agent, [search, readFile]);      // hand these to your agent instead
 *
 * Each tool keeps its name, description and schema - the model sees no
 * difference. Every call is checked, run only if allowed, and recorded. A
 * refusal comes back to the model as the tool's answer ("Refused by Provenza:
 * ...") so it can adapt; nothing ran. Pass { refusal: "error" } to throw instead.
 */

import { DynamicStructuredTool, type StructuredToolInterface } from "@langchain/core/tools";

import type { Agent } from "../agent.js";
import { ProvenzaDenied, ProvenzaUnavailable } from "../errors.js";

export interface GovernOptions {
  /** What policies and the Tool Registry call it (default: the tool's own name). */
  name?: string;
  refusal?: "message" | "error";
}

export function governTool(agent: Agent, tool: StructuredToolInterface, opts: GovernOptions = {}): DynamicStructuredTool {
  const governedName = opts.name ?? tool.name;
  const refusal = opts.refusal ?? "message";
  return new DynamicStructuredTool({
    name: tool.name,
    description: tool.description,
    schema: tool.schema as any,
    returnDirect: tool.returnDirect,
    func: async (input: any, _runManager?: unknown, config?: any) => {
      // policies inspect an arguments object; a string-input tool is wrapped as { input }
      const args = input !== null && typeof input === "object" && !Array.isArray(input) ? input : { input };
      try {
        return await agent.call(governedName, args, () => tool.invoke(input, config));
      } catch (exc) {
        if (refusal === "message" && (exc instanceof ProvenzaDenied || exc instanceof ProvenzaUnavailable)) {
          return `Refused by Provenza: ${exc.message}`;
        }
        throw exc;
      }
    },
  });
}

export function governTools(agent: Agent, tools: StructuredToolInterface[],
                            opts: { prefix?: string; refusal?: "message" | "error" } = {}): DynamicStructuredTool[] {
  return tools.map((t) => governTool(agent, t, { name: (opts.prefix ?? "") + t.name, refusal: opts.refusal }));
}
