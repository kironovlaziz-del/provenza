// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

/**
 * The local, signed, hash-chained audit log (JSON Lines) - standalone mode,
 * and gaps (an action that ran but the server did not record). The same
 * format as the Python SDK (provenza.audit_log), so either one verifies the
 * other's logs. Only hashes of inputs and outputs are written, never content.
 *
 * Appends are serialized within the process; several processes writing one
 * log should each use their own file (Node has no portable file lock).
 */

import { closeSync, existsSync, fstatSync, fsyncSync, mkdirSync, openSync, readFileSync, readSync, writeSync } from "node:fs";
import { verify as nodeVerify, createPublicKey } from "node:crypto";
import { dirname } from "node:path";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import { canonical } from "./canonical.js";
import { contentHash, Keys } from "./crypto.js";

export const GENESIS = "0".repeat(64);
const SIGNATURE_FIELDS = new Set(["signature", "pq_signature", "hash"]);

type Entry = Record<string, any>;

const signedPart = (e: Entry): Entry => Object.fromEntries(Object.entries(e).filter(([k]) => !SIGNATURE_FIELDS.has(k)));
const entryHash = (e: Entry): string => contentHash(Object.fromEntries(Object.entries(e).filter(([k]) => k !== "hash")));

function lastEntry(fd: number): Entry {
  const size = fstatSync(fd).size;
  let pos = size, buf = Buffer.alloc(0);
  while (pos > 0) {
    const step = Math.min(4096, pos);
    pos -= step;
    const chunk = Buffer.alloc(step);
    readSync(fd, chunk, 0, step, pos);
    buf = Buffer.concat([chunk, buf]);
    const lines = buf.toString("utf8").split("\n").filter((l) => l.trim());
    if (lines.length > 1 || (lines.length && pos === 0)) return JSON.parse(lines[lines.length - 1] as string);
  }
  return { seq: 0, hash: GENESIS };
}

export class AuditLog {
  constructor(readonly path: string, private readonly keys: Keys, private readonly agent: string) {}

  append(fields: Entry): Entry {
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    const fd = openSync(this.path, "a+", 0o600);
    try {
      const prev = lastEntry(fd);
      const entry: Entry = { v: 1, seq: prev.seq + 1, prev_hash: prev.hash, ts: Math.floor(Date.now() / 1000),
                             agent: this.agent, ...fields };
      const [sig, pq] = this.keys.sign(signedPart(entry));
      entry.signature = sig;
      if (pq) entry.pq_signature = pq;
      entry.hash = entryHash(entry);
      writeSync(fd, canonical(entry) + "\n");
      fsyncSync(fd);
      return entry;
    } finally {
      closeSync(fd);
    }
  }

  entries(): Entry[] {
    if (!existsSync(this.path)) return [];
    return readFileSync(this.path, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
  }
}

/** Problems found in a log, by line; empty when every entry is signed by this key and the chain is unbroken. */
export function verify(path: string, publicKey: string, pqPublicKey?: string | null): string[] {
  const problems: string[] = [];
  const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(publicKey, "base64").toString("base64url") },
                                format: "jwk" });
  let prevHash = GENESIS, prevSeq = 0;
  readFileSync(path, "utf8").split("\n").forEach((line, i) => {
    if (!line.trim()) return;
    const n = i + 1;
    let e: Entry;
    try { e = JSON.parse(line); } catch { problems.push(`line ${n}: not JSON`); return; }
    if (e.seq !== prevSeq + 1 || e.prev_hash !== prevHash) {
      problems.push(`line ${n}: chain broken (an entry was removed, inserted or reordered)`);
    }
    if (e.hash !== entryHash(e)) problems.push(`line ${n}: hash does not match the entry (altered)`);
    const msg = Buffer.from(canonical(signedPart(e)), "ascii");
    let ok = false;
    try { ok = nodeVerify(null, msg, pub, Buffer.from(e.signature ?? "", "base64")); } catch { ok = false; }
    if (!ok) problems.push(`line ${n}: signature does not verify`);
    if (pqPublicKey) {
      let pqOk = false;
      try {
        pqOk = ml_dsa65.verify(Buffer.from(e.pq_signature ?? "", "base64"), msg, Buffer.from(pqPublicKey, "base64"));
      } catch { pqOk = false; }
      if (!pqOk) problems.push(`line ${n}: ML-DSA-65 signature does not verify`);
    }
    prevHash = e.hash ?? "";
    prevSeq = typeof e.seq === "number" ? e.seq : prevSeq + 1;
  });
  return problems;
}
