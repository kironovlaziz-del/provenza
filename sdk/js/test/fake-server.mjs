// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

// An in-memory Provenza behind a fetch function - it verifies signatures for real.

import { createPublicKey, verify } from "node:crypto";

import { canonical, contentHash, fingerprint } from "../dist/index.js";

export const SERVER = "https://provenza.test";

const ok = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

function verifyEd25519(publicKey, signature, payload) {
  const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(publicKey, "base64").toString("base64url") },
                                format: "jwk" });
  if (!verify(null, Buffer.from(canonical(payload), "ascii"), key, Buffer.from(signature, "base64"))) {
    throw new Error("bad signature");
  }
}

export class FakeProvenza {
  verdicts = new Map();   // tool -> decision
  checks = new Map();
  records = [];
  down = new Set();       // paths answering 503
  recordFailures = 0;
  publicKey = null;
  nonces = new Set();
  n = 0;

  fetch = async (url, init = {}) => {
    const path = new URL(url).pathname.replace(/^\/api\/v1/, "");
    if (this.down.has(path)) return ok(503, { detail: "down" });
    const body = init.body ? JSON.parse(init.body) : {};
    const key = (init.headers ?? {})["x-agent-key"];
    if (path === "/agent-enrollment/challenge") {
      return ok(200, { challenge: "c".repeat(32), org_id: 1, enrollment_id: 7, name: null, require_hybrid: false });
    }
    if (path === "/agent-enrollment/enroll") {
      verifyEd25519(body.public_key, body.signature, {
        type: "provenza.agent.enroll", v: 1, challenge: "c".repeat(32), org_id: 1, enrollment_id: 7,
        public_key: body.public_key, pq_public_key: null, name: body.name ?? "" });
      this.publicKey = body.public_key;
      return ok(200, { agent_id: 42, api_key: "pvz_agent_key", name: body.name, key_fingerprint: fingerprint(body.public_key) });
    }
    if (key !== "pvz_agent_key") return ok(401, { detail: "agent_identity.invalid_key" });
    if (path === "/pvp/egress-catalog") {
      return ok(200, { action_type: "egress", tool_prefix: "egress.", domains: [
        { domain: "openai.com", status: "allowed" }, { domain: "blocked-ai.com", status: "blocked" }] });
    }
    if (path === "/agents/actions/check") {
      // what the server verifies: the agent's signature over the request, a fresh nonce
      verifyEd25519(this.publicKey, body.signature, {
        type: "action.request", agent_id: body.agent_id, chain_id: body.chain_id, action_type: body.action_type,
        tool_name: body.tool_name, input_sha256: contentHash(body.input), tool_version: body.tool_version ?? null,
        tool_digest: body.tool_digest ?? null, nonce: body.nonce, issued_at: body.issued_at,
      });
      if (this.nonces.has(body.nonce)) throw new Error("nonce reused");
      this.nonces.add(body.nonce);
      const token = `chk_${String(++this.n).padStart(40, "0")}`;
      const decision = this.verdicts.get(body.tool_name) ?? "allowed";
      this.checks.set(token, { ...body, decision });
      return ok(200, { decision, reason: `policy says ${decision}`, check_id: token, incident_type: null, policy_id: null });
    }
    if (path === "/http-tools/call") {
      // the HTTP tool gateway: the same signed request; it checks, calls and records itself
      verifyEd25519(this.publicKey, body.signature, {
        type: "action.request", agent_id: body.agent_id, chain_id: body.chain_id, action_type: body.action_type,
        tool_name: body.tool_name, input_sha256: contentHash(body.input), tool_version: null, tool_digest: null,
        nonce: body.nonce, issued_at: body.issued_at,
      });
      const decision = this.verdicts.get(body.tool_name) ?? "allowed";
      this.invoked = [...(this.invoked ?? []), body];
      return ok(200, decision === "allowed"
        ? { decision, reason: "", action_id: 9, status: 200, body: { echo: body.input } }
        : { decision, reason: `policy says ${decision}`, action_id: 10, incident_type: null });
    }
    if (path === "/agents/actions/record") {
      if (this.recordFailures > 0) { this.recordFailures--; return ok(503, { detail: "down" }); }
      const chk = this.checks.get(body.check_id);
      if (!chk) return ok(404, { detail: "Unknown check_id" });
      if (chk.used) return ok(409, { detail: "check_id already used" });
      verifyEd25519(this.publicKey, body.signature, {
        check_id: body.check_id, agent_id: body.agent_id, chain_id: body.chain_id, action_type: body.action_type,
        tool_name: body.tool_name, input_sha256: contentHash(body.input), output_sha256: contentHash(body.output) });
      if (contentHash(body.input) !== contentHash(chk.input)) return ok(400, { detail: "action_mismatch" });
      chk.used = true;
      this.records.push(body);
      return ok(200, { id: this.records.length, policy_check_result: chk.decision });
    }
    if (path.endsWith("/delegate")) {
      const payload = { from_agent_id: 42, to_agent_id: body.to_agent_id, task: body.task,
                        delegated_capabilities: [...body.delegated_capabilities].sort(), chain_id: body.chain_id,
                        nonce: body.nonce, issued_at: body.issued_at, expires_in: body.expires_in };
      if (body.delegated_tools !== null) payload.delegated_tools = [...new Set(body.delegated_tools)].sort();
      verifyEd25519(this.publicKey, body.signature, payload);
      return ok(200, { chain_id: 5, hop_id: 1, verified: true });
    }
    return ok(404, { detail: "not found" });
  };
}
