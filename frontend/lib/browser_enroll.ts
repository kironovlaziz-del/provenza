// Enrollment from the browser: the agent's keys are generated HERE, the
// challenge is signed here, and the private keys go only into a file the
// user downloads (provenza-agent.json) - never to the server. Same
// statement and file format as tools/provenza_sign.py enroll, so the file
// works with `provenza_sign.py rotate` afterwards.
//
// Ed25519: WebCrypto (Chrome 113+, Firefox 129+, Safari 17+).
// ML-DSA-65: the bundled @noble/post-quantum; the stored private key is the
// 32-byte FIPS 204 seed, as in the Python tool.
import { api } from "./api";
import { canonicalJson, keyFingerprint } from "./ed25519_verify";

export interface AgentKeysFile {
  server: string;
  agent_id: number;
  api_key: string | null;
  private_key: string;
  public_key: string;
  pq_private_key: string | null;
  pq_public_key: string | null;
  key_fingerprint: string;
}

const b64 = (u: Uint8Array) => {
  let s = "";
  u.forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s);
};

function buf(u: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(u.byteLength);
  new Uint8Array(out).set(u);
  return out;
}

export function browserCanEnroll(): boolean {
  return !!globalThis.crypto?.subtle && typeof globalThis.crypto.getRandomValues === "function";
}

interface Keys {
  edPrivate: CryptoKey;
  private_key: string;
  public_key: string;
  pqSecret: Uint8Array | null;
  pq_private_key: string | null;
  pq_public_key: string | null;
}

async function newKeys(hybrid: boolean): Promise<Keys> {
  let kp: CryptoKeyPair;
  try {
    kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  } catch {
    throw new Error("enroll.browser_no_ed25519");
  }
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  const keys: Keys = {
    edPrivate: kp.privateKey,
    private_key: b64(pkcs8.slice(pkcs8.length - 32)), // the raw 32-byte seed, as the Python tool stores it
    public_key: b64(pub),
    pqSecret: null,
    pq_private_key: null,
    pq_public_key: null,
  };
  if (hybrid) {
    const { ml_dsa65 } = await import("@noble/post-quantum/ml-dsa.js");
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const pq = ml_dsa65.keygen(seed);
    keys.pqSecret = pq.secretKey;
    keys.pq_private_key = b64(seed);
    keys.pq_public_key = b64(pq.publicKey);
  }
  return keys;
}

async function sign(keys: Keys, statement: Record<string, unknown>): Promise<{ signature: string; pq_signature: string | null }> {
  const msg = new TextEncoder().encode(canonicalJson(statement));
  const ed = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, keys.edPrivate, buf(msg)));
  let pq: string | null = null;
  if (keys.pqSecret && keys.pq_public_key) {
    const { ml_dsa65 } = await import("@noble/post-quantum/ml-dsa.js");
    const pub = Uint8Array.from(atob(keys.pq_public_key), (c) => c.charCodeAt(0));
    // argument order differs between library versions: sign, then prove it verifies
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const lib = ml_dsa65 as any;
    let sig: Uint8Array = lib.sign(msg, keys.pqSecret);
    if (!ml_dsa65.verify(sig, msg, pub)) sig = lib.sign(keys.pqSecret, msg);
    if (!ml_dsa65.verify(sig, msg, pub)) throw new Error("enroll.browser_pq_failed");
    pq = b64(sig);
  }
  return { signature: b64(ed), pq_signature: pq };
}

/** The API server as the Python tool expects it (it appends /api/v1). */
export function serverUrl(): string {
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || "";
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  const base = apiUrl.startsWith("http") ? apiUrl : origin + apiUrl;
  return base.replace(/\/api\/v1\/?$/, "").replace(/\/$/, "") || origin;
}

/** Run the whole enrollment in this browser. Returns the keys file to download. */
export async function enrollInBrowser(token: string, opts: { name?: string; hybrid?: boolean } = {}): Promise<AgentKeysFile> {
  if (!browserCanEnroll()) throw new Error("enroll.browser_unsupported");
  const ch = (await api.post("/agent-enrollment/challenge", { token })).data as {
    challenge: string; org_id: number; enrollment_id: number; name: string | null; require_hybrid: boolean;
  };
  const keys = await newKeys(!!opts.hybrid || ch.require_hybrid);
  const name = (ch.name || opts.name || "").trim();
  const statement = {
    type: "provenza.agent.enroll", v: 1, challenge: ch.challenge, org_id: ch.org_id,
    enrollment_id: ch.enrollment_id, public_key: keys.public_key, pq_public_key: keys.pq_public_key, name,
  };
  const { signature, pq_signature } = await sign(keys, statement);
  const res = (await api.post("/agent-enrollment/enroll", {
    token, challenge: ch.challenge, public_key: keys.public_key, pq_public_key: keys.pq_public_key,
    name: name || null, signature, pq_signature,
  })).data as { agent_id: number; api_key: string | null; key_fingerprint: string };
  const fp = await keyFingerprint(keys.public_key, keys.pq_public_key);
  if (fp !== res.key_fingerprint) throw new Error("enroll.browser_fingerprint_mismatch");
  return {
    server: serverUrl(), agent_id: res.agent_id, api_key: res.api_key, private_key: keys.private_key,
    public_key: keys.public_key, pq_private_key: keys.pq_private_key, pq_public_key: keys.pq_public_key,
    key_fingerprint: res.key_fingerprint,
  };
}

export function downloadKeysFile(file: AgentKeysFile) {
  const blob = new Blob([JSON.stringify(file, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "provenza-agent.json";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
