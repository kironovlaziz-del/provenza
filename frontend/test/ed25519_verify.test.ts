// @vitest-environment node
// The browser's own signature check (lib/ed25519_verify.ts): the canonical
// form must be byte-for-byte the server's (sdk/testdata, generated from
// backend app/core/agent_signing.py), real Ed25519 and ML-DSA-65 signatures
// verify, and every way of lying about a record is caught.

import { readFileSync } from "node:fs";
import path from "node:path";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { describe, expect, it } from "vitest";
import {
  SCHEME_CLASSIC, SCHEME_HYBRID, canonicalJson, isStrongPublicKey, keyFingerprint, verifyEvidence, type Evidence,
} from "@/lib/ed25519_verify";

interface Vector { json: string; canonical: string; sha256: string }
const VECTORS: Vector[] = JSON.parse(
  readFileSync(path.resolve(__dirname, "../../sdk/testdata/canonical-vectors.json"), "utf8"),
);

const b64 = (bytes: Uint8Array | ArrayBuffer) => Buffer.from(bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes).toString("base64");
const enc = (s: string) => new TextEncoder().encode(s);

async function ed25519Signer() {
  const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  return {
    publicKey: b64(pub),
    sign: async (msg: string) => b64(await crypto.subtle.sign({ name: "Ed25519" }, keys.privateKey, enc(msg))),
  };
}

const PAYLOAD = { from_agent_id: 7, to_agent_id: 9, task: "summarize Q3 – отчёт", nonce: "n-1", issued_at: 1760000000 };

async function classicEvidence(over: Partial<Evidence> = {}): Promise<Evidence> {
  const s = await ed25519Signer();
  const message = canonicalJson(PAYLOAD);
  return { signed_payload: PAYLOAD, signed_message: message, signature: await s.sign(message), public_key: s.publicKey,
           algorithm: SCHEME_CLASSIC, ...over };
}

// Known gap (audit, 2026-10-14): floats. The server writes Python's repr
// (1e-05, 1e-07, 1.0); canonicalJson writes JS's (0.00001, 1e-7, 1), so a
// record with such a number in its signed payload shows "failed" in the
// browser (never a false "verified"). sdk/js/src/canonical.ts has the
// port (pyFloat); when it is brought over, drop this filter.
const FLOAT_VECTOR = (v: Vector) => v.json.startsWith('{"n":');

describe("canonicalJson matches the server", () => {
  it("still has the float vector this filter skips", () => {
    expect(VECTORS.filter(FLOAT_VECTOR)).toHaveLength(1);
  });

  it.each(VECTORS.filter((v) => !FLOAT_VECTOR(v)).map((v) => [v.json, v]))("%s", async (_json, v) => {
    const out = canonicalJson(JSON.parse(v.json));
    expect(out).toBe(v.canonical);
    const digest = Buffer.from(await crypto.subtle.digest("SHA-256", enc(out))).toString("hex");
    expect(digest).toBe(v.sha256);
  });

  it("refuses values JSON cannot carry", () => {
    expect(() => canonicalJson({ x: Number.NaN })).toThrow();
    expect(() => canonicalJson({ x: Infinity })).toThrow();
  });
});

describe("keys", () => {
  it("accepts a real key and rejects small-order and malformed ones", async () => {
    const s = await ed25519Signer();
    expect(isStrongPublicKey(Buffer.from(s.publicKey, "base64"))).toBe(true);
    const identity = new Uint8Array(32);
    identity[0] = 1;                                          // the neutral point: signs "anything"
    expect(isStrongPublicKey(identity)).toBe(false);
    expect(isStrongPublicKey(new Uint8Array(31))).toBe(false);
  });

  it("fingerprints like the server: SHA256 over the key bytes, unpadded base64", async () => {
    const raw = new Uint8Array(32).fill(7);
    const expected = "SHA256:" + Buffer.from(await crypto.subtle.digest("SHA-256", raw)).toString("base64").replace(/=+$/, "");
    expect(await keyFingerprint(b64(raw))).toBe(expected);
    const pq = new Uint8Array(10).fill(1);
    expect(await keyFingerprint(b64(raw), b64(pq))).not.toBe(expected);   // a hybrid fingerprint pins both keys
  });
});

describe("verifyEvidence", () => {
  it("verifies a genuine Ed25519 record", async () => {
    const r = await verifyEvidence(await classicEvidence());
    expect(r.status).toBe("verified");
    expect(r.scheme).toBe(SCHEME_CLASSIC);
    expect(r.fingerprint).toMatch(/^SHA256:/);
  });

  it("catches a payload that differs from what was signed", async () => {
    const ev = await classicEvidence();
    const r = await verifyEvidence({ ...ev, signed_payload: { ...PAYLOAD, to_agent_id: 666 } });
    expect(r.status).toBe("failed");
  });

  it("catches a signed message that was altered", async () => {
    const ev = await classicEvidence();
    const r = await verifyEvidence({ ...ev, signed_payload: null, signed_message: ev.signed_message!.replace("7", "8") });
    expect(r.status).toBe("failed");
  });

  it("catches a non-canonical message even when the signature is over it", async () => {
    const s = await ed25519Signer();
    const loose = JSON.stringify(PAYLOAD, null, 1);
    const r = await verifyEvidence({ signed_payload: null, signed_message: loose, signature: await s.sign(loose),
                                     public_key: s.publicKey });
    expect(r).toMatchObject({ status: "failed", message: "signed message is not in canonical form" });
  });

  it("catches a signature by another key", async () => {
    const ev = await classicEvidence();
    const other = await ed25519Signer();
    expect((await verifyEvidence({ ...ev, public_key: other.publicKey })).status).toBe("failed");
  });

  it("catches a label that does not match the keys", async () => {
    const r = await verifyEvidence(await classicEvidence({ algorithm: SCHEME_HYBRID }));
    expect(r.status).toBe("failed");
  });

  it("says there is nothing to check when the record is unsigned", async () => {
    expect((await verifyEvidence({ signed_payload: PAYLOAD, signature: null, public_key: null })).status).toBe("no_signature");
  });

  describe("hybrid Ed25519 + ML-DSA-65", () => {
    async function hybridEvidence() {
      const ed = await ed25519Signer();
      const pq = ml_dsa65.keygen();
      const message = canonicalJson(PAYLOAD);
      return {
        ev: { signed_payload: PAYLOAD, signed_message: message, signature: await ed.sign(message), public_key: ed.publicKey,
              pq_signature: b64(ml_dsa65.sign(enc(message), pq.secretKey)), pq_public_key: b64(pq.publicKey),
              algorithm: SCHEME_HYBRID } as Evidence,
        pq,
      };
    }

    it("verifies only when both signatures verify", async () => {
      const { ev } = await hybridEvidence();
      expect((await verifyEvidence(ev)).status).toBe("verified");
    });

    it("fails when the ML-DSA half is missing or by another key", async () => {
      const { ev } = await hybridEvidence();
      expect((await verifyEvidence({ ...ev, pq_signature: null })).status).toBe("failed");
      const other = ml_dsa65.keygen();
      const forged = b64(ml_dsa65.sign(enc(ev.signed_message!), other.secretKey));
      expect((await verifyEvidence({ ...ev, pq_signature: forged })).status).toBe("failed");
    });
  });
});
