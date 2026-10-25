// Passkeys and signing sessions (docs/pvp/edge.md, section 2).
//
// A person who signs (an administrator or approver) confirms each sign-in
// once with a passkey - the device's PIN or biometric. The passkey certifies
// a session key made HERE, with WebCrypto, non-extractable: page scripts can
// sign with it, nobody can read it, and it lives in this browser's
// IndexedDB only until the session ends. The server never holds a private
// key; it only checks what was signed.
import { api } from "./api";
import { canonicalJson } from "./ed25519_verify";

export interface SessionPeer {
  session_id: string;
  created_at: string;
  ip: string | null;
  user_agent: string | null;
}

export interface SessionState {
  signing: boolean;
  session_id: string | null;
  status: "active" | "blocked";
  expires_at?: string;
  certified?: boolean;
  public_key?: string | null;
  has_passkey: boolean;
  /** sessions of this person waiting for this one to let them in */
  waiting?: SessionPeer[];
  /** for a blocked session: the open ones */
  active_elsewhere?: SessionPeer[];
}

export interface Passkey {
  id: number;
  label: string;
  created_at: string;
  last_used_at: string | null;
  algorithm: string;
  /** pins the passkey for offline checks of approvals (tools/provenza_audit.py) */
  fingerprint: string;
}

export interface Assertion {
  credential_id: string;
  client_data_json: string;
  authenticator_data: string;
  signature: string;
}

export interface Challenge {
  statement: Record<string, unknown>;
  challenge: string;
  rp_id: string;
  user_verification: UserVerificationRequirement;
  timeout: number;
  allow_credentials: { type: "public-key"; id: string }[];
}

// ------------------------------------------------------------------ encodings

function bytes(input: ArrayBuffer | ArrayBufferView): Uint8Array {
  return input instanceof ArrayBuffer ? new Uint8Array(input) : new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
}

export function b64url(input: ArrayBuffer | ArrayBufferView): string {
  let s = "";
  bytes(input).forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(text: string): ArrayBuffer {
  const s = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out.buffer;
}

function b64(input: ArrayBuffer): string {
  let s = "";
  new Uint8Array(input).forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s);
}

export function passkeysSupported(): boolean {
  return typeof window !== "undefined" && !!window.PublicKeyCredential && !!navigator.credentials;
}

// ------------------------------------------------------------------ session keys (IndexedDB)

const DB_NAME = "provenza-signing";
const STORE = "session-keys";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function store<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest): Promise<T> {
  const db = await openDb();
  try {
    return await new Promise<T>((resolve, reject) => {
      const req = fn(db.transaction(STORE, mode).objectStore(STORE));
      req.onsuccess = () => resolve(req.result as T);
      req.onerror = () => reject(req.error);
    });
  } finally {
    db.close();
  }
}

async function loadKey(sid: string): Promise<CryptoKeyPair | null> {
  try {
    return (await store<CryptoKeyPair | undefined>("readonly", (s) => s.get(sid))) ?? null;
  } catch {
    return null;
  }
}

async function forgetKey(sid: string): Promise<void> {
  try {
    await store("readwrite", (s) => s.delete(sid));
  } catch {
    // nothing stored, or storage unavailable: nothing to forget
  }
}

/** This session's key: made here once, non-extractable, kept until the session ends. */
async function sessionKey(sid: string): Promise<CryptoKeyPair> {
  const found = await loadKey(sid);
  if (found) return found;
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
  await store("readwrite", (s) => s.put(kp, sid));
  return kp;
}

async function publicKeyOf(kp: CryptoKeyPair): Promise<string> {
  return b64(await crypto.subtle.exportKey("raw", kp.publicKey));
}

/** The session key's signature over a statement's canonical JSON (base64). */
export async function signWithSessionKey(sid: string, statement: Record<string, unknown>): Promise<string> {
  const kp = await loadKey(sid);
  if (!kp) throw new Error("session.no_key");
  const data = new TextEncoder().encode(canonicalJson(statement));
  return b64(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, data));
}

// ------------------------------------------------------------------ passkeys

/** The passkey's answer to a WebAuthn request the server built (also for policy releases). */
export async function passkeyAssertion(ch: Challenge): Promise<Assertion> {
  return assert(ch);
}

async function assert(ch: Challenge): Promise<Assertion> {
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge: fromB64url(ch.challenge),
      rpId: ch.rp_id,
      allowCredentials: ch.allow_credentials.map((c) => ({ type: c.type, id: fromB64url(c.id) })),
      userVerification: ch.user_verification,
      timeout: ch.timeout,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("passkey.cancelled");
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    credential_id: b64url(cred.rawId),
    client_data_json: b64url(r.clientDataJSON),
    authenticator_data: b64url(r.authenticatorData),
    signature: b64url(r.signature),
  };
}

/** Have the passkey confirm a statement the server builds for `purpose`. */
export async function confirmWithPasskey(purpose: string, params: Record<string, unknown> = {}) {
  const { data } = await api.post<Challenge>("/auth/session/challenge", { purpose, params });
  return { statement: data.statement, assertion: await assert(data) };
}

export async function getSession(): Promise<SessionState> {
  const { data } = await api.get<SessionState>("/auth/session");
  return data;
}

/** One PIN prompt per sign-in: the passkey certifies this session's key. */
export async function certifySession(state: SessionState): Promise<void> {
  if (!state.session_id) return;
  const kp = await sessionKey(state.session_id);
  const publicKey = await publicKeyOf(kp);
  const { statement, assertion } = await confirmWithPasskey("session.certificate", { public_key: publicKey });
  await api.post("/auth/session/certificate", { public_key: publicKey, statement, assertion });
}

/** This browser still holds the key of the certified session. */
export async function hasSessionKey(sid: string | null): Promise<boolean> {
  return !!sid && !!(await loadKey(sid));
}

export async function admitSession(blockedSessionId: string, usePasskey: boolean, password?: string) {
  if (usePasskey) {
    const { statement, assertion } = await confirmWithPasskey("session.admit", { blocked_session_id: blockedSessionId });
    await api.post("/auth/session/admit", { blocked_session_id: blockedSessionId, statement, assertion });
  } else {
    await api.post("/auth/session/admit", { blocked_session_id: blockedSessionId, password });
  }
}

export async function refuseSession(blockedSessionId: string) {
  await api.post("/auth/session/refuse", { blocked_session_id: blockedSessionId });
}

/** A blocked sign-in ends the person's other sessions - with the passkey only. */
export async function takeOver() {
  const { statement, assertion } = await confirmWithPasskey("session.takeover");
  await api.post("/auth/session/takeover", { statement, assertion });
}

/** Signing out: the session key signs its own revocation and is deleted here. */
export async function revocation(sid: string | null): Promise<Record<string, unknown> | null> {
  if (!sid) return null;
  try {
    const statement = { type: "provenza.session.revoke", v: 1, session_id: sid, issued_at: Math.floor(Date.now() / 1000) };
    const signature = await signWithSessionKey(sid, statement);
    return { statement, signature };
  } catch {
    return null;
  } finally {
    await forgetKey(sid);
  }
}

export async function listPasskeys(): Promise<Passkey[]> {
  const { data } = await api.get<Passkey[]>("/users/me/passkeys");
  return data;
}

interface RegistrationOptions {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: "public-key"; alg: number }[];
  timeout: number;
  attestation: AttestationConveyancePreference;
  authenticatorSelection: AuthenticatorSelectionCriteria;
  excludeCredentials: { type: "public-key"; id: string }[];
  vouch_required: boolean;
}

/** Add a passkey; a person who already has one confirms the new one with it. */
export async function registerPasskey(label: string, password: string): Promise<Passkey> {
  const { data: o } = await api.post<RegistrationOptions>("/users/me/passkeys/options");
  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge: fromB64url(o.challenge),
      rp: o.rp,
      user: { id: fromB64url(o.user.id), name: o.user.name, displayName: o.user.displayName },
      pubKeyCredParams: o.pubKeyCredParams,
      timeout: o.timeout,
      attestation: o.attestation,
      authenticatorSelection: o.authenticatorSelection,
      excludeCredentials: o.excludeCredentials.map((c) => ({ type: c.type, id: fromB64url(c.id) })),
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("passkey.cancelled");
  const r = cred.response as AuthenticatorAttestationResponse;
  const body: Record<string, unknown> = {
    label,
    password,
    client_data_json: b64url(r.clientDataJSON),
    attestation_object: b64url(r.attestationObject),
  };
  if (o.vouch_required) body.vouch = await confirmWithPasskey("passkey.add", { credential_id: b64url(cred.rawId) });
  const { data } = await api.post<Passkey>("/users/me/passkeys", body);
  return data;
}

export async function removePasskey(id: number, password: string): Promise<void> {
  const { statement, assertion } = await confirmWithPasskey("passkey.remove", { passkey_id: id });
  await api.post(`/users/me/passkeys/${id}/remove`, { password, statement, assertion });
}
