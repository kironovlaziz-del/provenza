// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

import assert from "node:assert/strict";
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
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

  test("waits for a person's decision", async () => {
    const server = new FakeProvenza();
    const { agent } = await connected(server);
    server.decisions.set(7, ["pending_approval", "approved"]);
    assert.equal((await agent.waitForApproval(7, { intervalMs: 1 })).decision, "approved");
    assert.equal((await agent.waitForApproval(8, { timeoutMs: 0 })).decision, "pending_approval");
    await assert.rejects(() => agent.approval(0), RangeError);
  });

  test("gateway and MCP settings", async () => {
    const { agent } = await connected(new FakeProvenza());
    assert.deepEqual(gatewayOptions(agent), { baseURL: SERVER + "/api/v1/gateway/v1", apiKey: "pvz_agent_key" });
    assert.deepEqual(gatewayOptions(agent, { chainId: 9 }).defaultHeaders, { "X-Provenza-Chain-Id": "9" });
    assert.throws(() => gatewayOptions(agent, { chainId: 0 }), RangeError);
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
    const headers = proxyHeaders(chk);
    assert.equal(headers["X-Provenza-Check-Id"], chk.checkId);
    // the agent's signed request, which a proxy enforcing the signed policy verifies itself
    const req = JSON.parse(Buffer.from(headers["X-Provenza-Request"], "base64url").toString("utf8"));
    assert.equal(req.payload.type, "action.request");
    assert.equal(req.payload.tool_name, "proxy.stripe");
    assert.equal(req.payload.nonce, sent.nonce);
    assert.equal(req.payload.input_sha256, contentHash(sent.input));
    assert.equal(req.signature, sent.signature);
    const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"),
                                                      Buffer.from(req.public_key, "base64")]), format: "der", type: "spki" });
    assert.ok(cryptoVerify(null, Buffer.from(canonical(req.payload)), key, Buffer.from(req.signature, "base64")));
  });
});

describe("the egress proxy while Provenza is unreachable", () => {
  test("proxyRequestHeaders: a check online, the signed request alone offline", async () => {
    const server = new FakeProvenza();
    const { agent } = await connected(server);
    const online = await agent.proxyRequestHeaders("stripe", "POST", "/v1/charges", { body: "x" });
    assert.deepEqual(Object.keys(online).sort(), ["X-Provenza-Check-Id", "X-Provenza-Request"]);
    server.down.add("/agents/actions/check");
    const offline = await agent.proxyRequestHeaders("stripe", "POST", "/v1/charges", { body: "x" });
    assert.deepEqual(Object.keys(offline), ["X-Provenza-Request"]);
    const req = JSON.parse(Buffer.from(offline["X-Provenza-Request"], "base64url").toString("utf8"));
    assert.equal(req.payload.tool_name, "proxy.stripe");
    assert.equal(req.payload.action_type, "proxy");
    assert.equal(req.payload.input_sha256, contentHash(proxyDescriptor("stripe", "POST", "/v1/charges", { body: "x" })));
    const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"),
                                                      Buffer.from(req.public_key, "base64")]), format: "der", type: "spki" });
    assert.ok(cryptoVerify(null, Buffer.from(canonical(req.payload)), key, Buffer.from(req.signature, "base64")));
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

  test("invoke goes to the egress proxy when one is set (it holds the tools' credentials)", async () => {
    const server = new FakeProvenza();
    const sent = [];
    const fetchBoth = async (url, init) => {
      if (String(url).startsWith("http://proxy.local:8443/")) {
        sent.push({ url: String(url), key: init.headers["x-agent-key"], body: JSON.parse(init.body),
                    raw: init.body, signed: init.headers["X-Provenza-Request"] });
        return new Response(JSON.stringify({ decision: "allowed", action_id: 3, status: 200, body: { ok: 1 } }),
                            { status: 200, headers: { "content-type": "application/json" } });
      }
      return server.fetch(url, init);
    };
    const { agent } = await connected(server, { fetch: fetchBoth, egressProxy: "http://proxy.local:8443" });
    const out = await agent.invoke("crm.set_tier", { id: "c/42" });
    assert.deepEqual(out.body, { ok: 1 });
    assert.equal(sent[0].url, "http://proxy.local:8443/_tools/call");
    assert.equal(sent[0].key, "pvz_agent_key");
    assert.equal(sent[0].body.tool_name, "crm.set_tier");
    assert.deepEqual(sent[0].body.input, { id: "c/42" });
    assert.ok(sent[0].body.signature && sent[0].body.nonce);
    assert.equal((server.invoked ?? []).length, 0);   // nothing went to the server's gateway
    // the HTTP request itself, signed: what a proxy in enforce mode requires on every path
    const req = JSON.parse(Buffer.from(sent[0].signed, "base64url").toString("utf8"));
    assert.equal(req.payload.tool_name, "proxy._tools");
    assert.equal(req.payload.action_type, "proxy");
    const desc = proxyDescriptor("_tools", "POST", "/call", { body: Buffer.from(sent[0].raw, "utf8") });
    assert.equal(req.payload.input_sha256, contentHash(desc));
    assert.ok(cryptoVerify(null, Buffer.from(canonical(req.payload)), {
      key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(req.public_key, "base64")]),
      format: "der", type: "spki" }, Buffer.from(req.signature, "base64")));
  });
});

describe("egress self-check", () => {
  test("a closed target is confined, a reachable one is open, the report is signed", async () => {
    const { createServer } = await import("node:net");
    const server = new FakeProvenza();
    const { agent } = await connected(server);
    const noBeacon = async () => { throw new Error("unreachable"); };
    const closed = await agent.egressSelfcheck({ timeoutMs: 1000, beaconFetch: noBeacon });
    assert.equal(closed.verdict, "confined");
    const listener = createServer().listen(0, "127.0.0.1");
    await new Promise((r) => listener.once("listening", r));
    try {
      server.egressTargets = [`127.0.0.1:${listener.address().port}`, "127.0.0.1:9"];
      assert.equal((await agent.egressSelfcheck({ timeoutMs: 1000, beaconFetch: noBeacon })).verdict, "open");
      server.egressTargets = ["127.0.0.1:9"];
      const beaconSeen = async () => new Response(null, { status: 204 });
      assert.equal((await agent.egressSelfcheck({ timeoutMs: 1000, beaconFetch: beaconSeen })).verdict, "open");
    } finally {
      listener.close();
    }
  });
});

describe("attestation", () => {
  test("attest signs the token's hash over the server's challenge", async () => {
    const server = new FakeProvenza();
    const { agent } = await connected(server);
    const res = await agent.attest("  eyJ.workload.token\n");
    assert.equal(res.ok, true);
    assert.equal(server.attested.evidence, "eyJ.workload.token");
    assert.equal(server.attested.kind, "oidc");
  });
});
