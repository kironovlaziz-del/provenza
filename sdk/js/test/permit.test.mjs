// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

// permit.ts: a tool runs only with a valid permit for exactly this call.

import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { Readable } from "node:stream";
import { describe, test } from "node:test";

import { canonical, contentHash, PERMIT_HEADER, PermitError, PermitVerifier, permitHeaders, permitMiddleware,
         withPermit } from "../dist/index.js";

const SERVER = "https://provenza.test";
const INPUT = { customer: 42, fields: { tier: "gold" } };
const b64 = (s) => Buffer.from(s).toString("base64url");

class FakeProvenza {
  keys = new Map();
  redeemed = new Set();
  jwksCalls = 0;
  down = false;

  constructor(org = "acme") {
    this.org = org;
    this.rotate();
  }

  rotate() {
    this.kid = "pk_" + randomBytes(4).toString("hex");
    this.keys.set(this.kid, generateKeyPairSync("ed25519"));
  }

  permit({ tool = "crm.update", input = INPUT, expIn = 300, iss, ...over } = {}) {
    const now = Math.floor(Date.now() / 1000);
    const claims = { iss: iss ?? `provenza:org:${this.org}`, sub: "agent:7", aud: tool, jti: randomBytes(8).toString("hex"),
                     iat: now, nbf: now, exp: now + expIn, act: "tool_call", chain: null, ish: contentHash(input), ...over };
    const header = { alg: "EdDSA", typ: "provenza-permit+jwt", kid: this.kid };
    const si = `${b64(canonical(header))}.${b64(canonical(claims))}`;
    return si + "." + sign(null, Buffer.from(si), this.keys.get(this.kid).privateKey).toString("base64url");
  }

  fetch = async (url, init = {}) => {
    if (this.down) throw new Error("connect ECONNREFUSED");
    const path = new URL(url).pathname;
    if (path === `/api/v1/pvp/permits/${this.org}/jwks.json`) {
      this.jwksCalls++;
      const keys = [...this.keys].map(([kid, k]) => ({ ...k.publicKey.export({ format: "jwk" }), kid, use: "sig", alg: "EdDSA" }));
      return Response.json({ keys });
    }
    if (path === "/api/v1/pvp/permits/redeem") {
      const { permit } = JSON.parse(init.body);
      const { jti } = JSON.parse(Buffer.from(permit.split(".")[1], "base64url").toString());
      if (this.redeemed.has(jti)) return Response.json({ detail: "permit.redeemed" }, { status: 409 });
      this.redeemed.add(jti);
      return Response.json({ redeemed: true, jti });
    }
    return new Response("", { status: 404 });
  };
}

const verifierFor = (fake, opts = {}) => new PermitVerifier(SERVER, fake.org, { fetch: fake.fetch, ...opts });
const codeOf = async (p) => { try { await p; } catch (e) { assert.ok(e instanceof PermitError); return e.code; } return null; };

describe("PermitVerifier", () => {
  test("a valid permit runs once", async () => {
    const fake = new FakeProvenza();
    const v = verifierFor(fake);
    const token = fake.permit();
    const p = await v.verify(token, { tool: "crm.update", input: INPUT });
    assert.equal(p.agentId, 7);
    assert.equal(p.redeemed, true);
    assert.equal(await codeOf(v.verify(token, { tool: "crm.update", input: INPUT })), "permit.redeemed");
    assert.equal(fake.jwksCalls, 1);
  });

  test("another tool, another input, expired, foreign, forged: refused and unused", async () => {
    const fake = new FakeProvenza();
    const v = verifierFor(fake);
    assert.equal(await codeOf(v.verify(fake.permit(), { tool: "crm.delete", input: INPUT })), "permit.mismatch");
    assert.equal(await codeOf(v.verify(fake.permit(), { tool: "crm.update", input: { ...INPUT, customer: 1 } })),
                 "permit.mismatch");
    assert.equal(await codeOf(v.verify(fake.permit({ expIn: -120 }), { tool: "crm.update", input: INPUT })), "permit.expired");
    assert.equal(await codeOf(v.verify(fake.permit({ iss: "provenza:org:other" }), { tool: "crm.update", input: INPUT })),
                 "permit.invalid");
    assert.equal(await codeOf(v.verify(fake.permit().slice(0, -6) + "AAAAAA", { tool: "crm.update", input: INPUT })),
                 "permit.invalid");
    assert.equal(await codeOf(v.verify(new FakeProvenza().permit(), { tool: "crm.update", input: INPUT })), "permit.invalid");
    assert.equal(await codeOf(v.verify(undefined, { tool: "crm.update", input: INPUT })), "permit.missing");
    assert.equal(fake.redeemed.size, 0);
  });

  test("a rotated key is fetched when it appears", async () => {
    const fake = new FakeProvenza();
    const v = verifierFor(fake);
    await v.verify(fake.permit(), { tool: "crm.update", input: INPUT });
    fake.rotate();
    assert.equal((await v.verify(fake.permit(), { tool: "crm.update", input: INPUT })).redeemed, true);
    assert.equal(fake.jwksCalls, 2);
  });

  test("fails closed when Provenza cannot be reached; offline mode remembers", async () => {
    const fake = new FakeProvenza();
    const v = verifierFor(fake);
    await v.verify(fake.permit(), { tool: "crm.update", input: INPUT });   // keys cached
    fake.down = true;
    assert.equal(await codeOf(v.verify(fake.permit(), { tool: "crm.update", input: INPUT })), "permit.unverifiable");
    fake.down = false;
    const offline = verifierFor(fake, { redeem: false });
    const token = fake.permit();
    assert.equal((await offline.verify(token, { tool: "crm.update", input: INPUT })).redeemed, false);
    assert.equal(await codeOf(offline.verify(token, { tool: "crm.update", input: INPUT })), "permit.redeemed");
  });
});

function call(mw, { body, headers = {}, parsed }) {
  const req = parsed !== undefined ? { headers, body: parsed } : Object.assign(Readable.from([Buffer.from(body)]), { headers });
  const res = { statusCode: 200, headers: {}, body: null, setHeader(k, v) { this.headers[k] = v; }, end(b) { this.body = b; } };
  return new Promise((resolve) => {
    mw(req, res, (err) => resolve({ req, res, next: true, err })).then(() => { if (res.body !== null) resolve({ req, res }); });
  });
}

describe("middleware", () => {
  test("Express / Connect", async () => {
    const fake = new FakeProvenza();
    const mw = permitMiddleware(verifierFor(fake), { tool: "crm.update" });
    let out = await call(mw, { body: JSON.stringify(INPUT), headers: { [PERMIT_HEADER.toLowerCase()]: fake.permit() } });
    assert.ok(out.next && !out.err);
    assert.equal(out.req.permit.agentId, 7);
    assert.deepEqual(out.req.body, INPUT);
    out = await call(mw, { parsed: INPUT, headers: { [PERMIT_HEADER.toLowerCase()]: fake.permit() } });   // after express.json()
    assert.ok(out.next);
    out = await call(mw, { body: JSON.stringify(INPUT) });
    assert.equal(out.res.statusCode, 403);
    assert.deepEqual(JSON.parse(out.res.body), { error: "permit.missing" });
    out = await call(mw, { body: "{not json", headers: { [PERMIT_HEADER.toLowerCase()]: fake.permit() } });
    assert.equal(out.res.statusCode, 400);
  });

  test("fetch-style handler", async () => {
    const fake = new FakeProvenza();
    const handler = withPermit(verifierFor(fake), "crm.update", (_req, permit, input) => Response.json({ agent: permit.agentId, input }));
    const ok = await handler(new Request("http://tool/update", { method: "POST", body: JSON.stringify(INPUT),
                                                                 headers: { [PERMIT_HEADER]: fake.permit() } }));
    assert.equal(ok.status, 200);
    assert.deepEqual(await ok.json(), { agent: 7, input: INPUT });
    const refused = await handler(new Request("http://tool/update", { method: "POST", body: JSON.stringify(INPUT) }));
    assert.equal(refused.status, 403);
  });

  test("the agent sends the permit with the call", () => {
    assert.deepEqual(permitHeaders({ permit: "h.c.s" }), { [PERMIT_HEADER]: "h.c.s" });
    assert.deepEqual(permitHeaders({ permit: null }), {});
  });
});
