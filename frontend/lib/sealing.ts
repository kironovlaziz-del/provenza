// Credentials sealed in the browser to the egress proxies (backend
// app/pvp/sealed.py, proxy/internal/egress/sealed.go). The credential an
// administrator types never goes to the server: it is sealed here, once per
// proxy, to the proxy's own X25519 key, and only the envelopes are sent.
//
//   shared = X25519(ephemeral private, proxy public)
//   key    = HKDF-SHA256(shared, salt = epk || proxy public,
//                        info = "provenza sealed credential v1" || canonical(context))
//   ct     = AES-256-GCM(key, nonce, credential, aad = canonical(context))
//
// The proxy's encryption key is accepted only with a valid signature by the
// proxy's own signing key; both fingerprints are shown so they can be
// compared with what the proxy logs on its host. What this cannot defend
// against: a server that serves another version of this code (docs/pvp/edge.md).

import { api } from "./api";
import { canonicalJson, keyFingerprint } from "./ed25519_verify";
import { signWithSessionKey } from "./signing";

export type CredentialObject = "route" | "provider" | "mcp_server" | "a2a_peer" | "http_tool";

export interface ProxyKey {
  proxy_id: number;
  org_id: number;
  name: string;
  public_key: string;
  key_fingerprint: string;
  encryption_key: string;
  encryption_key_signature: string;
  encryption_key_fingerprint: string;
}

export interface CredentialState {
  source: "none" | "sealed" | "local";
  /** the origin the credential may be sent to - bound into every envelope */
  upstream: string | null;
  sealed_for: number[];
  missing: number[];
  /** proxies holding an envelope for another origin (the object's address changed) */
  stale: number[];
  /** proxies whose envelope no administrator signed (sealed by the server from a credential it held) */
  unsigned: number[];
  awaiting_sealing: boolean;
}

const ALG = "X25519-HKDF-SHA256-A256GCM";
const INFO = "provenza sealed credential v1";
const enc = new TextEncoder();

function b64(bytes: Uint8Array): string {
  let s = "";
  bytes.forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s);
}

function unb64(text: string): Uint8Array {
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function buf(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(out).set(bytes);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
}

// ---------------------------------------------------------------- X25519 (RFC 7748)
// Plain BigInt: the private key is ephemeral (used once, for one envelope).

// BigInt via BigInt() rather than 1n-style literals: tsconfig targets ES2017.
const B0 = BigInt(0), B1 = BigInt(1), B2 = BigInt(2), B8 = BigInt(8), B19 = BigInt(19), B255 = BigInt(255), B121665 = BigInt(121665);
const P = B2 ** B255 - B19;
const A24 = B121665;
const mod = (a: bigint) => ((a % P) + P) % P;

function pow(b: bigint, e: bigint): bigint {
  let r = B1;
  b = mod(b);
  while (e > B0) {
    if (e & B1) r = mod(r * b);
    b = mod(b * b);
    e >>= B1;
  }
  return r;
}

function leToBig(bytes: Uint8Array): bigint {
  let n = B0;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << B8) | BigInt(bytes[i]);
  return n;
}

function bigToLe(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(n & B255);
    n >>= B8;
  }
  return out;
}

export function x25519(scalar: Uint8Array, u: Uint8Array): Uint8Array {
  const k = Uint8Array.from(scalar);
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;
  const uu = Uint8Array.from(u);
  uu[31] &= 127;
  const x1 = mod(leToBig(uu));
  let [x2, z2, x3, z3] = [B1, B0, x1, B1];
  let swap = B0;
  const kn = leToBig(k);
  for (let t = 254; t >= 0; t--) {
    const bit = (kn >> BigInt(t)) & B1;
    if (swap ^ bit) [x2, x3, z2, z3] = [x3, x2, z3, z2];
    swap = bit;
    const a = mod(x2 + z2), aa = mod(a * a), b = mod(x2 - z2), bb = mod(b * b), e = mod(aa - bb);
    const c = mod(x3 + z3), d = mod(x3 - z3), da = mod(d * a), cb = mod(c * b);
    x3 = mod((da + cb) ** B2);
    z3 = mod(x1 * mod((da - cb) ** B2));
    x2 = mod(aa * bb);
    z2 = mod(e * mod(aa + A24 * e));
  }
  if (swap) [x2, x3, z2, z3] = [x3, x2, z3, z2];
  return bigToLe(mod(x2 * pow(z2, P - B2)));
}

const BASE = (() => {
  const u = new Uint8Array(32);
  u[0] = 9;
  return u;
})();

// ---------------------------------------------------------------- sealing

/** What an envelope is bound to: the object, the proxy, and the only origin it may be sent to. */
export function sealContext(orgId: number, object: CredentialObject, objectId: number, proxyId: number,
                            upstream: string) {
  return { org_id: orgId, object, object_id: objectId, proxy_id: proxyId, upstream };
}

async function hkdf(shared: Uint8Array, salt: Uint8Array, info: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", buf(shared), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: buf(salt), info: buf(info) }, base,
    { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
}

/** One envelope: the credential sealed to one proxy's encryption key, for one context. */
export async function seal(credential: string, proxyPublicB64: string, ctx: ReturnType<typeof sealContext>,
                           ephemeral?: Uint8Array, nonceIn?: Uint8Array) {
  const proxyPub = unb64(proxyPublicB64);
  if (proxyPub.length !== 32) throw new Error("not an X25519 key");
  const eph = ephemeral ?? crypto.getRandomValues(new Uint8Array(32));
  const epk = x25519(eph, BASE);
  const shared = x25519(eph, proxyPub);
  if (shared.every((b) => b === 0)) throw new Error("not a usable X25519 key");
  const aad = enc.encode(canonicalJson(ctx));
  const key = await hkdf(shared, concat(epk, proxyPub), concat(enc.encode(INFO), aad));
  const nonce = nonceIn ?? crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: buf(nonce), additionalData: buf(aad) },
    key, buf(enc.encode(credential))));
  return { v: 1, alg: ALG, proxy_id: ctx.proxy_id, key_fingerprint: await keyFingerprint(proxyPublicB64),
           context: ctx, epk: b64(epk), nonce: b64(nonce), ct: b64(ct) };
}

/** The proxy's encryption key, signed by its own signing key - else it is not used. */
export async function proxyKeyHolds(k: ProxyKey): Promise<boolean> {
  try {
    const statement = canonicalJson({ type: "provenza.proxy.encryption_key", v: 1, key: k.encryption_key });
    const pub = await crypto.subtle.importKey("raw", buf(unb64(k.public_key)), { name: "Ed25519" }, false, ["verify"]);
    const ok = await crypto.subtle.verify({ name: "Ed25519" }, pub, buf(unb64(k.encryption_key_signature)),
      buf(enc.encode(statement)));
    return ok && (await keyFingerprint(k.public_key)) === k.key_fingerprint &&
      (await keyFingerprint(k.encryption_key)) === k.encryption_key_fingerprint;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- API

export async function getProxyKeys(): Promise<ProxyKey[]> {
  return (await api.get<ProxyKey[]>("/egress/proxy-keys")).data;
}

export async function getCredential(obj: CredentialObject, id: number): Promise<CredentialState> {
  return (await api.get<CredentialState>(`/egress/credentials/${obj}/${id}`)).data;
}

async function sha256Hex(text: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", buf(enc.encode(text))));
  return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}

function apiError(detail: string) {
  // shaped like an API error, so errorMessage() shows errors.<detail>
  return Object.assign(new Error(detail), { response: { data: { detail } } });
}

async function signStatement(statement: Record<string, unknown>): Promise<string> {
  try {
    return await signWithSessionKey(String(statement.session_id), statement);
  } catch {
    throw apiError("session.no_key"); // the key is not in this browser (cleared storage, another browser)
  }
}

/** The administrator vouches for the envelopes with this session's key
 *  (provenza.credential.sealed): an enforcing proxy opens no others. The
 *  statement is checked here against the envelopes this browser made. */
async function signedEnvelopes(obj: CredentialObject, id: number, upstream: string,
                               envelopes: Awaited<ReturnType<typeof seal>>[]) {
  const { data } = await api.post<{ statement: Record<string, unknown> }>(`/egress/credentials/${obj}/${id}/statement`,
    { envelopes });
  const st = data.statement;
  const mine: Record<string, string> = {};
  for (const e of envelopes) mine[String(e.proxy_id)] = await sha256Hex(canonicalJson(e));
  if (st.type !== "provenza.credential.sealed" || st.object !== obj || st.object_id !== id || st.upstream !== upstream ||
      canonicalJson(st.envelopes as object) !== canonicalJson(mine)) {
    throw apiError("credential.statement_mismatch");
  }
  return { envelopes, statement: st, signature: await signStatement(st) };
}

/** Seal a credential to every proxy whose key holds, and store the envelopes. */
export async function sealCredential(obj: CredentialObject, id: number, credential: string): Promise<CredentialState> {
  const { upstream } = await getCredential(obj, id);
  if (!upstream) {
    throw apiError("credential.no_upstream");
  }
  const keys = await getProxyKeys();
  const good: ProxyKey[] = [];
  for (const k of keys) if (await proxyKeyHolds(k)) good.push(k);
  if (!good.length) {
    throw apiError("credential.no_proxy_keys");
  }
  const envelopes = await Promise.all(good.map((k) =>
    seal(credential, k.encryption_key, sealContext(k.org_id, obj, id, k.proxy_id, upstream))));
  return (await api.put<CredentialState>(`/egress/credentials/${obj}/${id}`,
    await signedEnvelopes(obj, id, upstream, envelopes))).data;
}

/** Vouch for the envelopes stored for an object - those the server sealed
 *  from a credential it held before (this browser cannot see what they hold). */
export async function countersignCredential(obj: CredentialObject, id: number): Promise<CredentialState> {
  const { data } = await api.post<{ statement: Record<string, unknown> }>(`/egress/credentials/${obj}/${id}/statement`, {});
  const st = data.statement;
  if (st.type !== "provenza.credential.sealed" || st.object !== obj || st.object_id !== id) {
    throw apiError("credential.statement_mismatch");
  }
  return (await api.post<CredentialState>(`/egress/credentials/${obj}/${id}/countersign`,
    { statement: st, signature: await signStatement(st) })).data;
}

export async function setCredentialSource(obj: CredentialObject, id: number, source: "local" | "none"): Promise<CredentialState> {
  return (await api.post<CredentialState>(`/egress/credentials/${obj}/${id}/source`, { source })).data;
}

export async function getLegacyCredentials(): Promise<{ count: number; proxies_with_keys: number }> {
  return (await api.get("/egress/credentials/legacy")).data;
}

/** Seal the credentials the server held to the proxies, then vouch for each
 *  object's envelopes with this session's key. */
export async function sealLegacyCredentials(): Promise<{ sealed: Record<string, number>; proxies: number[];
                                                         failed: { object: string; object_id: number }[] }> {
  const out = (await api.post("/egress/credentials/seal-legacy")).data;
  for (const o of (out.objects ?? []) as { object: CredentialObject; object_id: number }[]) {
    await countersignCredential(o.object, o.object_id);
  }
  return out;
}
