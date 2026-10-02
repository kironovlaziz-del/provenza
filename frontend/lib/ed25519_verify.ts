// Signature verification in the browser, independent of the server's own
// claims: Ed25519 via WebCrypto and, for hybrid agents, ML-DSA-65 (FIPS 204)
// via the bundled @noble/post-quantum library - no CDN, nothing fetched at
// verify time. A hybrid signature is valid only if BOTH halves verify.
//
// What the browser checks itself:
//   1. the signature over the exact signed bytes (`signed_message`, the
//      canonical JSON the agent signed - not a re-serialization);
//   2. that `signed_message` is the canonical form of the payload shown, so
//      what you read is what was signed;
//   3. the SHA-256 fingerprint of the signer's public key, computed here
//      (for a hybrid key: over the Ed25519 key followed by the ML-DSA key).
//
// What it cannot know: whose key that is. The server delivers the key too,
// so "verified" alone proves integrity. Independence from the server comes
// from comparing the fingerprint with the one the agent's owner holds
// (docs/agent-signing.md); tools/provenza_sign.py does the same offline.
//
// Canonical form - MUST match backend app/core/agent_signing.py:
// json.dumps(payload, sort_keys=True, separators=(",", ":")) - keys sorted at
// every level, no whitespace, non-ASCII escaped as \uXXXX, integers only.

export type VerifyStatus = "verified" | "failed" | "unsupported" | "no_signature" | "error";

export interface Evidence {
  signed_payload: Record<string, unknown> | null;
  signed_message?: string | null;
  signature: string | null;
  public_key: string | null;
  /** Present only for hybrid (Ed25519 + ML-DSA-65) signers. */
  pq_signature?: string | null;
  pq_public_key?: string | null;
  algorithm?: string | null;
  key_origin?: string | null;
}

export const SCHEME_CLASSIC = "ed25519";
export const SCHEME_HYBRID = "ed25519+ml-dsa-65";
const MLDSA65_PUBLIC_KEY_BYTES = 1952;
const MLDSA65_SIGNATURE_BYTES = 3309;

export interface VerifyResult {
  status: VerifyStatus;
  /** "SHA256:..." computed in this browser from the public key. */
  fingerprint?: string;
  /** "ed25519" or "ed25519+ml-dsa-65" - what this browser actually checked. */
  scheme?: string;
  message?: string;
}

/** Python json.dumps(..., sort_keys=True, separators=(",", ":")) with the default ensure_ascii. */
export function canonicalJson(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number in signed payload");
    return String(value);
  }
  if (typeof value === "string") {
    // JSON.stringify escapes quotes, backslashes and control characters the
    // same way Python does; Python additionally escapes everything above
    // 0x7E (including DEL) as \uXXXX, per UTF-16 code unit.
    return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    // Python sorts keys by code point; JS sort() compares UTF-16 units.
    const keys = Object.keys(obj).sort(byCodePoint);
    return "{" + keys.map((k) => canonicalJson(k) + ":" + canonicalJson(obj[k])).join(",") + "}";
  }
  throw new Error("unsupported value in signed payload");
}

function byCodePoint(a: string, b: string): number {
  const x = Array.from(a, (c) => c.codePointAt(0) ?? 0);
  const y = Array.from(b, (c) => c.codePointAt(0) ?? 0);
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}

// ---- Ed25519 point validation (RFC 8032), mirrors backend normalize_public_key.
// A small-order public key makes a fixed "signature" verify for every
// message, and WebCrypto does not reject such keys - so check it here.
// BigInt via BigInt() rather than 1n-style literals: tsconfig targets ES2017.
const N0 = BigInt(0), N1 = BigInt(1), N2 = BigInt(2), N3 = BigInt(3), N8 = BigInt(8), N19 = BigInt(19);
const N121665 = BigInt(121665), N121666 = BigInt(121666), N252 = BigInt(252), N255 = BigInt(255);
const P = N2 ** N255 - N19;
const L = N2 ** N252 + BigInt("27742317777372353535851937790883648493");
const mod = (a: bigint) => ((a % P) + P) % P;
function powMod(b: bigint, e: bigint): bigint {
  let r = N1;
  b = mod(b);
  while (e > N0) {
    if (e & N1) r = (r * b) % P;
    b = (b * b) % P;
    e >>= N1;
  }
  return r;
}
const D = mod(-N121665 * powMod(N121666, P - N2));
const SQRT_M1 = powMod(N2, (P - N1) / BigInt("4"));
type Pt = [bigint, bigint, bigint, bigint];

function decodePoint(raw: Uint8Array): Pt | null {
  if (raw.length !== 32) return null;
  let y = N0;
  for (let i = 31; i >= 0; i--) y = (y << N8) | BigInt(i === 31 ? raw[i] & 0x7f : raw[i]);
  const sign = BigInt(raw[31] >> 7);
  if (y >= P) return null;
  const u = mod(y * y - N1);
  const v = mod(D * y * y + N1);
  const x2 = mod(u * powMod(v, P - N2));
  let x = powMod(x2, (P + N3) / N8);
  if (mod(x * x - x2) !== N0) x = mod(x * SQRT_M1);
  if (mod(x * x - x2) !== N0) return null;
  if (x === N0 && sign === N1) return null;
  if ((x & N1) !== sign) x = P - x;
  return [x, y, N1, mod(x * y)];
}

function addPt(p: Pt, q: Pt): Pt {
  const a = mod((p[1] - p[0]) * (q[1] - q[0]));
  const b = mod((p[1] + p[0]) * (q[1] + q[0]));
  const c = mod(N2 * D * p[3] * q[3]);
  const d = mod(N2 * p[2] * q[2]);
  const e = b - a, f = d - c, g = d + c, h = b + a;
  return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
}

function mulPt(k: bigint, p: Pt): Pt {
  let q: Pt = [N0, N1, N1, N0];
  while (k > N0) {
    if (k & N1) q = addPt(q, p);
    p = addPt(p, p);
    k >>= N1;
  }
  return q;
}

const isIdentity = (p: Pt) => mod(p[0]) === N0 && mod(p[1] - p[2]) === N0;

/** True for a canonical Ed25519 point of prime order (what a real key is). */
export function isStrongPublicKey(raw: Uint8Array): boolean {
  const pt = decodePoint(raw);
  return !!pt && !isIdentity(mulPt(N8, pt)) && isIdentity(mulPt(L, pt));
}

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64(bytes: Uint8Array): string {
  let s = "";
  bytes.forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s);
}

// A fresh ArrayBuffer so TS sees a concrete BufferSource for crypto.subtle.
function toBuf(bytes: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buf).set(bytes);
  return buf;
}

/**
 * "SHA256:" + unpadded base64 of SHA-256 over the raw key bytes (OpenSSH
 * style). Hybrid keys: over the 32-byte Ed25519 key followed by the ML-DSA-65
 * key, so one fingerprint pins both halves. Matches backend key_fingerprint.
 */
export async function keyFingerprint(publicKeyB64: string, pqPublicKeyB64?: string | null): Promise<string> {
  let raw = b64ToBytes(publicKeyB64);
  if (pqPublicKeyB64) {
    const pq = b64ToBytes(pqPublicKeyB64);
    const both = new Uint8Array(raw.length + pq.length);
    both.set(raw);
    both.set(pq, raw.length);
    raw = both;
  }
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", toBuf(raw)));
  return "SHA256:" + bytesToB64(digest).replace(/=+$/, "");
}

async function verifyMlDsa(message: Uint8Array, sigB64: string, pubB64: string): Promise<boolean> {
  const pub = b64ToBytes(pubB64);
  const sig = b64ToBytes(sigB64);
  if (pub.length !== MLDSA65_PUBLIC_KEY_BYTES || sig.length !== MLDSA65_SIGNATURE_BYTES) return false;
  // Bundled with the app (its own chunk, loaded on first hybrid check) - never from a CDN.
  const { ml_dsa65 } = await import("@noble/post-quantum/ml-dsa.js");
  try {
    // Pure ML-DSA, empty context - same as the backend (cryptography).
    return ml_dsa65.verify(sig, message, pub);
  } catch {
    return false;
  }
}

export async function verifyEvidence(ev: Evidence): Promise<VerifyResult> {
  if (!ev.signature || !ev.public_key || (!ev.signed_message && !ev.signed_payload)) {
    return { status: "no_signature" };
  }
  if (!globalThis.crypto?.subtle) return { status: "unsupported" };
  const hybrid = !!ev.pq_public_key;
  const scheme = hybrid ? SCHEME_HYBRID : SCHEME_CLASSIC;
  try {
    const fingerprint = await keyFingerprint(ev.public_key, ev.pq_public_key);
    // The server's label must agree with what the keys say.
    if (ev.algorithm && ev.algorithm !== scheme) {
      return { status: "failed", fingerprint, scheme, message: `algorithm "${ev.algorithm}" does not match the keys (${scheme})` };
    }
    if (!isStrongPublicKey(b64ToBytes(ev.public_key))) {
      return { status: "failed", fingerprint, scheme, message: "weak (small-order) public key - its signatures prove nothing" };
    }
    if (hybrid && !ev.pq_signature) {
      return { status: "failed", fingerprint, scheme, message: "hybrid key but the ML-DSA-65 signature is missing" };
    }
    const message = ev.signed_message ?? canonicalJson(ev.signed_payload);
    // The text shown to the user must be exactly what was signed.
    if (canonicalJson(JSON.parse(message)) !== message) {
      return { status: "failed", fingerprint, scheme, message: "signed message is not in canonical form" };
    }
    if (ev.signed_payload && canonicalJson(ev.signed_payload) !== message) {
      return { status: "failed", fingerprint, scheme, message: "displayed payload differs from the signed message" };
    }
    const bytes = new TextEncoder().encode(message);
    let key: CryptoKey;
    try {
      key = await crypto.subtle.importKey("raw", toBuf(b64ToBytes(ev.public_key)), { name: "Ed25519" }, false, ["verify"]);
    } catch {
      return { status: "unsupported", fingerprint, scheme };
    }
    const edOk = await crypto.subtle.verify({ name: "Ed25519" }, key, toBuf(b64ToBytes(ev.signature)), toBuf(bytes));
    if (!edOk) return { status: "failed", fingerprint, scheme, message: "Ed25519 signature does not verify" };
    if (hybrid && !(await verifyMlDsa(bytes, ev.pq_signature as string, ev.pq_public_key as string))) {
      return { status: "failed", fingerprint, scheme, message: "ML-DSA-65 signature does not verify" };
    }
    return { status: "verified", fingerprint, scheme };
  } catch (e) {
    return { status: "error", scheme, message: e instanceof Error ? e.message : String(e) };
  }
}

/** Download the evidence as JSON for offline checking (tools/provenza_sign.py verify). */
export function downloadEvidence(ev: object, filename: string) {
  const blob = new Blob([JSON.stringify(ev, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
