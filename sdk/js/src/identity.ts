// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

/**
 * An agent's identity: agent id and API key, and the keys it signs with -
 * generated here, on the agent's side; the server only receives public keys.
 *
 * Stored in ~/.config/provenza/agents/<name>.json (mode 600, directory 700,
 * written atomically) in the format of the Python SDK and
 * tools/provenza_sign.py: an agent enrolled by either runs with the other.
 * A file other users can read is refused. (No OS keychain in Node's standard
 * library: keep the file on an encrypted volume, or use the Python SDK's
 * keychain store.)
 */

import { chmodSync, closeSync, mkdirSync, openSync, readFileSync, renameSync, statSync, writeSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import { Client } from "./client.js";
import { Keys } from "./crypto.js";
import { ProvenzaConfigError } from "./errors.js";
import { trim } from "./text.js";

export interface Identity {
  keys: Keys;
  server: string | null;   // null: a standalone (local-only) identity
  agentId: number | null;
  apiKey: string | null;
  name: string | null;
}

export function configDir(): string {
  return join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "provenza", "agents");
}

export function defaultPath(name: string): string {
  // a character class without anchors is linear; the ends are trimmed without a regex
  const slug = trim(name.replace(/[^A-Za-z0-9_.-]+/g, "-"), "-.") || "agent";
  return join(configDir(), `${slug}.json`);
}

export function save(identity: Identity, path: string): void {
  const k = identity.keys;
  const data = {
    server: identity.server, agent_id: identity.agentId, api_key: identity.apiKey, name: identity.name,
    private_key: k.privateKey, public_key: k.publicKey, pq_private_key: k.pqPrivateKey, pq_public_key: k.pqPublicKey,
    key_fingerprint: k.fingerprint,
  };
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = join(dirname(path), `.tmp-${randomBytes(6).toString("hex")}`);
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, JSON.stringify(data, null, 2));
  } finally {
    closeSync(fd);
  }
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);   // atomic: never half a key file
}

/** The identity at path, or null when there is none. */
export function load(path: string): Identity | null {
  let st;
  try {
    st = statSync(path);
  } catch (exc) {
    if ((exc as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new ProvenzaConfigError(`cannot read the identity at ${path}: ${(exc as Error).message}`);
  }
  if (process.platform !== "win32" && (st.mode & 0o077) !== 0) {
    throw new ProvenzaConfigError(`${path} is readable by other users; chmod 600 it (it holds private keys)`);
  }
  let d: any;
  try {
    d = JSON.parse(readFileSync(path, "utf8"));
  } catch (exc) {
    throw new ProvenzaConfigError(`cannot read the identity at ${path}: ${(exc as Error).message}`);
  }
  if (d.secrets === "keychain") {
    throw new ProvenzaConfigError(`${path} keeps its keys in an OS keychain (Python SDK); the JS SDK cannot read it`);
  }
  if (!d.private_key || !d.public_key) throw new ProvenzaConfigError(`${path} lacks the agent's keys`);
  return {
    keys: new Keys(d.private_key, d.public_key, d.pq_private_key ?? null, d.pq_public_key ?? null),
    server: d.server ?? null, agentId: d.agent_id ?? null, apiKey: d.api_key ?? null, name: d.name ?? null,
  };
}

/** Join with a one-time enrollment token (provenza.agent.enroll v1). */
export async function enroll(client: Client, token: string, name: string | null, hybrid: boolean): Promise<Identity> {
  const ch = await client.post("/agent-enrollment/challenge", { token }, false);
  const keys = Keys.generate(hybrid || Boolean(ch.require_hybrid));
  const final = String(ch.name || name || "").trim();
  const statement = {
    type: "provenza.agent.enroll", v: 1, challenge: ch.challenge, org_id: ch.org_id, enrollment_id: ch.enrollment_id,
    public_key: keys.publicKey, pq_public_key: keys.pqPublicKey, name: final,
  };
  const [signature, pqSignature] = keys.sign(statement);
  const res = await client.post("/agent-enrollment/enroll", {
    token, challenge: ch.challenge, public_key: keys.publicKey, pq_public_key: keys.pqPublicKey,
    name: final || null, signature, pq_signature: pqSignature,
  }, false);
  if (res.key_fingerprint && res.key_fingerprint !== keys.fingerprint) {
    throw new ProvenzaConfigError("the server registered another key than the one generated here");
  }
  return { keys, server: client.serverUrl, agentId: res.agent_id, apiKey: res.api_key ?? null, name: res.name || final || null };
}
