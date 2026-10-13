// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test, describe } from "node:test";

import { Agent, canonical, contentHash, ProvenzaApprovalRequired, ProvenzaConfigError, ProvenzaDenied,
         ProvenzaUnavailable, proxyDescriptor, proxyHeaders, verifyAuditLog } from "../dist/index.js";
import { RECORD_RETRIES_MS } from "../dist/agent.js";
import { connection } from "../dist/integrations/mcp.js";
import { gatewayOptions } from "../dist/integrations/openai.js";
import { FakeProvenza, SERVER } from "./fake-server.mjs";

const vectors = JSON.parse(readFileSync(new URL("../../testdata/canonical-vectors.json", import.meta.url), "utf8"));
const tmp = () => mkdtempSync(join(tmpdir(), "provenza-js-"));

async function connected(server, extra = {}) {
  const dir = tmp();
  const agent = await Agent.create({ name: "billing-bot", serverUrl: SERVER, enrollmentToken: "pvz_enr_" + "x".repeat(20),
                                     identityPath: join(dir, "id.json"), fetch: server.fetch, ...extra });
  return { agent, dir };
}

describe("canonical form = the server's", () => {
  for (const v of vectors) {
    test(v.json.slice(0, 40), () => {
      const value = JSON.parse(v.json);
      assert.equal(canonical(value), v.canonical);
      assert.equal(contentHash(value), v.sha256);
    });
  }
  test("refuses what the server could not receive", () => {
    assert.throws(() => canonical({ x: NaN }), TypeError);
    assert.throws(() => canonical({ x: 1n }), TypeError);
  });
});

describe("identity", () => {
  test("enrolls once; owner-only file in the shared format", async () => {
    const server = new FakeProvenza();
    const { agent, dir } = await connected(server);
    assert.equal(agent.agentId, 42);
    const path = join(dir, "id.json");
    if (process.platform !== "win32") assert.equal(statSync(path).mode & 0o777, 0o600);
    const data = JSON.parse(readFileSync(path, "utf8"));
    for (const k of ["server", "agent_id", "api_key", "private_key", "public_key", "pq_private_key", "pq_public_key", "key_fingerprint"]) {
      assert.ok(k in data, k);
    }
    const again = await Agent.create({ name: "billing-bot", serverUrl: SERVER, identityPath: path, fetch: server.fetch });
    assert.equal(again.fingerprint, agent.fingerprint);
  });

  test("never sends the identity to another server", async () => {
    const server = new FakeProvenza();
    const { dir } = await connected(server);
    await assert.rejects(Agent.create({ serverUrl: "https://evil.test", identityPath: join(dir, "id.json"), fetch: server.fetch }),
                         /belongs to/);
  });

  test("not enrolled without a token; a world-readable identity is refused", async () => {
    await assert.rejects(Agent.create({ serverUrl: SERVER, identityPath: join(tmp(), "none.json") }), ProvenzaConfigError);
    if (process.platform === "win32") return;
    const { dir } = await connected(new FakeProvenza());
    chmodSync(join(dir, "id.json"), 0o644);
    await assert.rejects(Agent.create({ serverUrl: SERVER, identityPath: join(dir, "id.json") }), /readable by other users/);
  });
});

describe("governed tools", () => {
  test("allowed: runs, recorded and signed", async () => {
    const server = new FakeProvenza();
    const { agent } = await connected(server);
    const ran = [];
    const read = agent.tool("db.read", async ({ query, limit = 10 }) => { ran.push(query); return { rows: 3, limit }; });
    assert.deepEqual(await read({ query: "select 1" }), { rows: 3, limit: 10 });
    assert.deepEqual(ran, ["select 1"]);
    const [chk] = server.checks.values();
    assert.deepEqual([chk.tool_name, chk.input], ["db.read", { query: "select 1" }]);
    assert.deepEqual(server.records[0].output, { rows: 3, limit: 10 });   // the fake verified the signature
  });

  test("denied: does not run, the attempt is recorded", async () => {
    const server = new FakeProvenza();
    server.verdicts.set("stripe.charge", "denied");
    const { agent } = await connected(server);
    const ran = [];
    const charge = agent.tool("stripe.charge", async (args) => { ran.push(args); });
    await assert.rejects(charge({ amount: 100 }), (e) => e instanceof ProvenzaDenied && e.actionId === 1);
    assert.deepEqual(ran, []);
    assert.equal(server.records[0].output, null);
  });

  test("pending approval has its own error", async () => {
    const server = new FakeProvenza();
    server.verdicts.set("email.send", "pending_approval");
    const { agent } = await connected(server);
    await assert.rejects(agent.tool("email.send", () => { throw new Error("must not run"); })({ to: "a" }),
                         ProvenzaApprovalRequired);
  });

  test("a failing tool is recorded by its error name only", async () => {
    const server = new FakeProvenza();
    const { agent } = await connected(server);
    await assert.rejects(agent.tool("db.read", () => { throw new RangeError("secret dsn"); })({}), RangeError);
    assert.deepEqual(server.records[0].output, { error: "RangeError" });
  });

  test("fail-closed, and failOpen logs locally", async () => {
    const server = new FakeProvenza();
    server.down.add("/agents/actions/check");
    const { agent } = await connected(server);
    const ran = [];
    await assert.rejects(agent.tool("db.read", () => ran.push(1))({}), ProvenzaUnavailable);
    assert.deepEqual(ran, []);
    const open = await Agent.create({ serverUrl: SERVER, identityPath: agent.identityPath, fetch: server.fetch, failOpen: true });
    assert.equal(await open.tool("db.read", () => 7)({}), 7);
    assert.equal(open.auditLog.entries().at(-1).status, "unchecked");
  });

  test("record retries; a lasting failure is a signed gap and the result stands", async () => {
    RECORD_RETRIES_MS.splice(0, RECORD_RETRIES_MS.length, 0, 0);
    const server = new FakeProvenza();
    const { agent } = await connected(server);
    const read = agent.tool("db.read", () => ({ ok: true }));
    server.recordFailures = 2;
    assert.deepEqual(await read({}), { ok: true });
    assert.equal(server.records.length, 1);
    server.recordFailures = 3;
    assert.deepEqual(await read({}), { ok: true });
    const gap = agent.auditLog.entries().at(-1);
    assert.equal(gap.status, "unrecorded");
    assert.deepEqual(verifyAuditLog(agent.auditLog.path, agent.identity.keys.publicKey), []);
  });

  test("arguments must be a JSON object", async () => {
    const server = new FakeProvenza();
    const { agent } = await connected(server);
    const t = agent.tool("db.read", () => { throw new Error("must not run"); });
    await assert.rejects(t({ x: NaN }), TypeError);
    await assert.rejects(t({ x: 1n }), TypeError);
    await assert.rejects(t([1, 2]), TypeError);
    assert.equal(server.checks.size, 0);
  });

  test("chains, delegation, background records", async () => {
    const server = new FakeProvenza();
    const { agent } = await connected(server, { recordMode: "background" });
    const read = agent.tool("db.read", ({ i }) => ({ i }));
    await agent.withChain(9, () => read({ i: 1 }));
    await read({ i: 2 });
    await agent.flush();
    assert.deepEqual([...server.checks.values()].map((c) => c.chain_id), [9, null]);
    assert.deepEqual(server.records.map((r) => r.output), [{ i: 1 }, { i: 2 }]);
    assert.equal((await agent.delegate(7, "summarize", ["read"], { tools: ["db.read", "db.read"], expiresIn: 600 })).verified, true);
  });

  test("gateway and MCP settings", async () => {
    const { agent } = await connected(new FakeProvenza());
    assert.deepEqual(gatewayOptions(agent), { baseURL: SERVER + "/api/v1/gateway/v1", apiKey: "pvz_agent_key" });
    assert.deepEqual(connection(agent), { url: SERVER + "/api/v1/mcp", headers: { Authorization: "Bearer pvz_agent_key" } });
  });
});

describe("standalone", () => {
  test("runs without a server; signed log; tampering found", async () => {
    const dir = tmp();
    const agent = await Agent.create({ name: "solo", identityPath: join(dir, "solo.json"), allowedTools: ["calc.add"] });
    assert.equal(agent.mode, "standalone");
    const add = agent.tool("calc.add", ({ x, y }) => x + y);
    assert.equal(await add({ x: 1, y: 2 }), 3);
    await assert.rejects(agent.tool("shell.run", () => 0)({ cmd: "rm -rf /" }), ProvenzaDenied);
    assert.deepEqual(agent.auditLog.entries().map((e) => e.status), ["recorded", "denied"]);
    assert.ok(!readFileSync(agent.auditLog.path, "utf8").includes("rm -rf"));
    assert.deepEqual(verifyAuditLog(agent.auditLog.path, agent.identity.keys.publicKey), []);
    const lines = readFileSync(agent.auditLog.path, "utf8").trim().split("\n");
    const edited = JSON.parse(lines[0]); edited.tool = "calc.sub";
    writeFileSync(agent.auditLog.path, [JSON.stringify(edited), lines[1]].join("\n") + "\n");
    assert.ok(verifyAuditLog(agent.auditLog.path, agent.identity.keys.publicKey).some((p) => p.startsWith("line 1")));
  });
});

test("VERSION is the package's version", async () => {
  const { VERSION } = await import("../dist/index.js");
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(VERSION, pkg.version);
});

test("trimming is linear: no regex backtracking on long runs (CodeQL js/polynomial-redos)", async () => {
  const { trim, trimEnd } = await import("../dist/text.js");
  const evil = "/".repeat(200_000) + "x";
  const started = performance.now();
  assert.equal(trimEnd(evil, "/"), evil);
  assert.equal(trim("-".repeat(200_000) + "a" + "-".repeat(200_000), "-"), "a");
  assert.ok(performance.now() - started < 1000);
  assert.equal(trimEnd("https://p.test///", "/"), "https://p.test");
});

const proxyVectors = JSON.parse(readFileSync(new URL("../../testdata/proxy-descriptor-vectors.json", import.meta.url),
                                             "utf8")).vectors;

describe("egress proxy, SDK mode", () => {
  for (const v of proxyVectors) {
    test(`descriptor = the proxy's: ${v.method} ${v.path}`, () => {
      assert.deepEqual(proxyDescriptor(v.route, v.method, v.path, { query: v.query, body: v.body }), v.descriptor);
      assert.deepEqual(proxyDescriptor(v.route, v.method, v.path,
                                       { query: Buffer.from(v.query), body: new TextEncoder().encode(v.body) }),
                       v.descriptor);
    });
  }

  test("refuses what the proxy would not see", () => {
    assert.throws(() => proxyDescriptor("stripe", "GET", "v1/charges"), TypeError);
    assert.throws(() => proxyDescriptor("stripe", "GET", "/v1/charges?limit=3"), TypeError);
  });

  test("proxyCheck asks the server and hands out the header", async () => {
    const server = new FakeProvenza();
    const { agent } = await connected(server);
    const body = '{"amount":1000}';
    const chk = await agent.proxyCheck("stripe", "post", "/v1/charges", { body });
    const sent = server.checks.get(chk.checkId);
    assert.equal(sent.action_type, "proxy");
    assert.equal(sent.tool_name, "proxy.stripe");
    assert.deepEqual(sent.input, proxyDescriptor("stripe", "POST", "/v1/charges", { body }));
    assert.equal(chk.decision, "allowed");
    assert.deepEqual(proxyHeaders(chk), { "X-Provenza-Check-Id": chk.checkId });
  });
});

describe("HTTP tools through Provenza", () => {
  test("invoke: one signed request, the server calls and records", async () => {
    const server = new FakeProvenza();
    const { agent } = await connected(server);
    const out = await agent.invoke("crm.set_tier", { id: "42", tier: "gold" });
    assert.equal(out.status, 200);
    assert.deepEqual(out.body, { echo: { id: "42", tier: "gold" } });
    assert.equal(server.invoked[0].action_type, "tool_call");
    server.verdicts.set("crm.delete", "denied");
    await assert.rejects(agent.invoke("crm.delete", { id: "42" }), (e) => e instanceof ProvenzaDenied && e.actionId === 10);
    server.verdicts.set("crm.wipe", "pending_approval");
    await assert.rejects(agent.invoke("crm.wipe", {}), ProvenzaApprovalRequired);
  });
});
