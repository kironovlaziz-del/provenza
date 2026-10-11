// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";

import { tool } from "@langchain/core/tools";
import { z } from "zod";

import { Agent, ProvenzaDenied } from "../dist/index.js";
import { governTool, governTools } from "../dist/integrations/langchain.js";
import { FakeProvenza, SERVER } from "./fake-server.mjs";

async function setup() {
  const server = new FakeProvenza();
  const agent = await Agent.create({ serverUrl: SERVER, enrollmentToken: "pvz_enr_" + "x".repeat(20),
                                     identityPath: join(mkdtempSync(join(tmpdir(), "pvz-lc-")), "id.json"), fetch: server.fetch });
  const ran = [];
  const search = tool(async ({ query, limit = 3 }) => { ran.push(query); return `${limit} results for ${query}`; },
                      { name: "search", description: "Search the knowledge base.",
                        schema: z.object({ query: z.string(), limit: z.number().optional() }) });
  return { server, agent, search, ran };
}

describe("LangChain.js", () => {
  test("same interface, governed call", async () => {
    const { server, agent, search, ran } = await setup();
    const governed = governTool(agent, search, { name: "kb.search" });
    assert.deepEqual([governed.name, governed.description], [search.name, search.description]);
    assert.equal(governed.schema, search.schema);
    assert.equal(await governed.invoke({ query: "refunds" }), "3 results for refunds");
    assert.deepEqual(ran, ["refunds"]);
    const [chk] = server.checks.values();
    assert.deepEqual([chk.tool_name, chk.input], ["kb.search", { query: "refunds" }]);
    assert.deepEqual(server.records[0].output, { result: "3 results for refunds" });
  });

  test("a refusal reaches the model as the answer; nothing runs", async () => {
    const { server, agent, search, ran } = await setup();
    server.verdicts.set("kb.search", "denied");
    const [governed] = governTools(agent, [search], { prefix: "kb." });
    assert.match(await governed.invoke({ query: "salaries" }), /^Refused by Provenza/);
    assert.deepEqual(ran, []);
  });

  test("refusal: 'error' throws instead", async () => {
    const { server, agent, search } = await setup();
    server.verdicts.set("search", "denied");
    await assert.rejects(governTool(agent, search, { refusal: "error" }).invoke({ query: "x" }), ProvenzaDenied);
  });
});
