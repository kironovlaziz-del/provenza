// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

/**
 * Keys, hashes and signatures - the server's rules (docs/agent-signing.md):
 *
 *   content hash  SHA-256 hex of the canonical form (canonical.ts)
 *   fingerprint   "SHA256:" + unpadded base64 of SHA-256 over the raw Ed25519
 *                 key, followed by the raw ML-DSA-65 key for a hybrid key
 *   hybrid        Ed25519 AND ML-DSA-65 over the same bytes. The ML-DSA private
 *                 key is its 32-byte FIPS 204 seed - the same form the Python SDK
 *                 and tools/provenza_sign.py store, so identity files are shared.
 *
 * Ed25519 is node:crypto; ML-DSA-65 is @noble/post-quantum (audited, no other
 * dependencies than noble's own).
 */

import { createHash, createPrivateKey, generateKeyPairSync, randomBytes, sign as nodeSign } from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import { canonical } from "./canonical.js";
import { trimEnd } from "./text.js";

const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64");
const unb64 = (text: string): Buffer => Buffer.from(text, "base64");
const b64url = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");

export function contentHash(value: unknown): string {
  return createHash("sha256").update(canonical(value), "ascii").digest("hex");
}

export function fingerprint(publicKey: string, pqPublicKey?: string | null): string {
  const raw = pqPublicKey ? Buffer.concat([unb64(publicKey), unb64(pqPublicKey)]) : unb64(publicKey);
  return "SHA256:" + trimEnd(createHash("sha256").update(raw).digest("base64"), "=");
}

export interface KeyMaterial {
  privateKey: string;           // base64 of the raw 32-byte Ed25519 private key
  publicKey: string;            // base64 of the raw 32-byte Ed25519 public key
  pqPrivateKey?: string | null; // base64 of the 32-byte ML-DSA-65 seed
  pqPublicKey?: string | null;  // base64 of the 1952-byte ML-DSA-65 public key
}

export class Keys implements KeyMaterial {
  constructor(
    readonly privateKey: string,
    readonly publicKey: string,
    readonly pqPrivateKey: string | null = null,
    readonly pqPublicKey: string | null = null,
  ) {}

  static generate(hybrid = false): Keys {
    const { privateKey } = generateKeyPairSync("ed25519");
    const jwk = privateKey.export({ format: "jwk" }) as { d: string; x: string };
    let pqPriv: string | null = null, pqPub: string | null = null;
    if (hybrid) {
      const seed = randomBytes(32);
      pqPriv = b64(seed);
      pqPub = b64(ml_dsa65.keygen(seed).publicKey);
    }
    return new Keys(b64(Buffer.from(jwk.d, "base64url")), b64(Buffer.from(jwk.x, "base64url")), pqPriv, pqPub);
  }

  get hybrid(): boolean {
    return this.pqPublicKey !== null;
  }

  get fingerprint(): string {
    return fingerprint(this.publicKey, this.pqPublicKey);
  }

  /** [Ed25519 signature, ML-DSA-65 signature or null], base64, over the canonical form. */
  sign(payload: unknown): [string, string | null] {
    const msg = Buffer.from(canonical(payload), "ascii");
    const key = createPrivateKey({
      key: { kty: "OKP", crv: "Ed25519", d: b64url(unb64(this.privateKey)), x: b64url(unb64(this.publicKey)) },
      format: "jwk",
    });
    const sig = b64(nodeSign(null, msg, key));
    let pq: string | null = null;
    if (this.pqPrivateKey) {
      pq = b64(ml_dsa65.sign(msg, ml_dsa65.keygen(unb64(this.pqPrivateKey)).secretKey));
    }
    return [sig, pq];
  }
}
