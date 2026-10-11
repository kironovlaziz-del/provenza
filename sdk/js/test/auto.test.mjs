// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

// provenza/auto: direct fetch calls to AI providers become governed egress actions.

import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, test } from "node:test";

import { Agent } from "../dist/index.js";
import { instrument, match, uninstrument } from "../dist/auto.js";
import { FakeProvenza, SERVER } from "./fake-server.mjs";

const PROMPT = "patient John Smith, diagnosis ...";
const realFetch = globalThis.fetch;
let provider, server, agent;

beforeEach(async () => {
  provider = [];
  // what "the internet" answers - installed before instrument(), so it is what the patch forwards to
  globalThis.fetch = async (input) => {
    provider.push(new Request(input).url);
    return new Response(JSON.stringify({ id: "x", object: "chat.completion", created: 1, model: "m", choices: [
      { index: 0, finish_reason: "stop", message: { role: "assistant", content: "ok" } }] }),
      { status: 200, headers: { "content-type": "application/json" } });
  };
  server = new FakeProvenza();
  agent = await Agent.create({ serverUrl: SERVER, enrollmentToken: "pvz_enr_" + "x".repeat(20),
                               identityPath: join(mkdtempSync(join(tmpdir(), "pvz-auto-")), "id.json"), fetch: server.fetch });
  await instrument(agent);
});

afterEach(() => {
  uninstrument();
  globalThis.fetch = realFetch;
});

const egress = () => [...server.checks.values()].filter((c) => c.action_type === "egress");

describe("provenza/auto", () => {
  test("domain matching is dot-bounded", () => {
    assert.equal(match("api.openai.com", ["openai.com"]), "openai.com");
    assert.equal(match("evilopenai.com", ["openai.com"]), null);
    assert.equal(match("openai.com.evil.io", ["openai.com"]), null);
  });

  test("an AI call is checked, sent and recorded - without the prompt or the query", async () => {
    const r = await fetch("https://api.openai.com/v1/chat/completions?key=abc",
                          { method: "POST", body: JSON.stringify({ prompt: PROMPT }) });
    assert.equal(r.status, 200);
    assert.equal(provider.length, 1);
    const [chk] = egress();
    assert.equal(chk.tool_name, "egress.api.openai.com");
    assert.deepEqual([chk.input.method, chk.input.path], ["POST", "/v1/chat/completions"]);
    assert.equal(chk.input.body_sha256.length, 64);
    const all = JSON.stringify([...server.checks.values(), ...server.records]);
    assert.ok(!all.includes(PROMPT) && !all.includes("abc"));
    assert.equal(server.records.at(-1).output.status, 200);
  });

  test("other hosts are untouched", async () => {
    await fetch("https://example.com/");
    await fetch("https://evilopenai.com/");
    assert.deepEqual(egress(), []);
    assert.equal(provider.length, 2);
  });

  test("a refusal is a 403 that is not retried; nothing is sent", async () => {
    server.verdicts.set("egress.api.blocked-ai.com", "denied");
    const r = await fetch("https://api.blocked-ai.com/v1/x", { method: "POST", body: "{}" });
    assert.equal(r.status, 403);
    assert.equal(r.headers.get("x-should-retry"), "false");
    assert.equal((await r.json()).error.code, "provenza_denied");
    assert.deepEqual(provider, []);
    assert.equal(server.records.at(-1).output, null);    // the refused attempt is on record
  });

  test("fail-closed: 503 and nothing is sent", async () => {
    server.down.add("/agents/actions/check");
    const r = await fetch("https://api.openai.com/v1/x", { method: "POST", body: "{}" });
    assert.equal(r.status, 503);
    assert.deepEqual(provider, []);
  });

  test("the OpenAI SDK raises its permission error and does not retry", async () => {
    const { default: OpenAI, PermissionDeniedError } = await import("openai");
    server.verdicts.set("egress.api.openai.com", "denied");
    const client = new OpenAI({ apiKey: "sk-direct" });
    await assert.rejects(client.chat.completions.create({ model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] }),
                         (e) => e instanceof PermissionDeniedError && /Refused by Provenza/.test(e.message));
    assert.deepEqual(provider, []);
    assert.equal(egress().length, 1);                     // one check, no retries
  });

  test("uninstrument restores fetch", async () => {
    uninstrument();
    await fetch("https://api.openai.com/v1/models");
    assert.deepEqual(egress(), []);
    assert.equal(provider.length, 1);
  });
});
