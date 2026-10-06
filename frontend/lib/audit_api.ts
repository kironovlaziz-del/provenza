// Tamper-evident audit log (docs/audit-proofs.md): API calls and checks the
// browser does itself - record hash, Merkle inclusion path (RFC 9162) and the
// checkpoint signature (Ed25519 + ML-DSA-65 via ed25519_verify.ts). The
// standalone tools/provenza_audit.py does the same offline.
import { api } from "./api";
import { canonicalJson, verifyEvidence } from "./ed25519_verify";

export interface CheckpointT {
  org_id: number;
  tree_size: number;
  root_hash: string;
  issued_at: string;
  algorithm: string;
  statement: string;
  signature: string;
  pq_signature: string | null;
  public_key: string;
  pq_public_key: string | null;
  key_fingerprint: string;
}

export interface IntegrityT {
  head_seq: number;
  checkpoint: CheckpointT | null;
  unsigned_records: number;
}

export interface ProofT {
  format: string;
  record: { id: number; payload: Record<string, unknown>; canonical: string; record_hash: string };
  leaf_index: number;
  tree_size: number;
  inclusion_path: string[];
  checkpoint: CheckpointT;
}

export interface ChainProblem {
  kind: string;
  seq?: number;
  id?: number;
  tree_size?: number;
  checkpoint_id?: number;
}

export interface ChainReportT {
  ok: boolean;
  records: number;
  head_seq: number;
  head_hash: string | null;
  root_hash: string | null;
  checkpoints: number;
  checkpoint_roots_checked: number;
  checkpoint_signatures_checked: number;
  latest_checkpoint_size: number;
  problem_count: number;
  problems: ChainProblem[];
}

export async function getIntegrity() {
  return (await api.get<IntegrityT>("/audit-logs/integrity")).data;
}

export async function createCheckpoint() {
  return (await api.post<CheckpointT | null>("/audit-logs/checkpoints")).data;
}

export async function getProof(id: number) {
  return (await api.get<ProofT>(`/audit-logs/${id}/proof`)).data;
}

export async function verifyChain() {
  return (await api.post<ChainReportT>("/audit-logs/verify")).data;
}

// ---- browser-side verification ----

export type ProofCheck =
  | { ok: true; fingerprint: string; scheme: string; treeSize: number }
  | { ok: false; reason: string };

function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/i.test(hex)) throw new Error("not a 32-byte hex hash");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const buf = new ArrayBuffer(len);
  const all = new Uint8Array(buf);
  let o = 0;
  for (const p of parts) {
    all.set(p, o);
    o += p.length;
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}

const LEAF = new Uint8Array([0]);
const NODE = new Uint8Array([1]);

/** RFC 9162 section 2.1.3.2 - mirrors backend audit_chain.verify_inclusion. */
async function inclusionOk(index: number, size: number, data: Uint8Array, path: Uint8Array[], root: Uint8Array) {
  if (index < 0 || index >= size) return false;
  // tree sizes stay far below 2^53, so plain division keeps the bit arithmetic exact
  let fn = index;
  let sn = size - 1;
  let r = await sha256(LEAF, data);
  for (const p of path) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = await sha256(NODE, p, r);
      if (fn % 2 === 0) {
        while (fn !== 0 && fn % 2 === 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = await sha256(NODE, r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && toHex(r) === toHex(root);
}

export async function checkCheckpoint(cp: CheckpointT): Promise<ProofCheck> {
  let st: Record<string, unknown>;
  try {
    st = JSON.parse(cp.statement);
  } catch {
    return { ok: false, reason: "statement_invalid" };
  }
  if (canonicalJson(st) !== cp.statement || st.type !== "provenza.audit.checkpoint") {
    return { ok: false, reason: "statement_invalid" };
  }
  if (typeof st.algorithm !== "string" || typeof st.key_fingerprint !== "string") {
    return { ok: false, reason: "statement_invalid" };
  }
  if (st.org_id !== cp.org_id || st.tree_size !== cp.tree_size || st.root_hash !== cp.root_hash
      || st.algorithm !== cp.algorithm || st.key_fingerprint !== cp.key_fingerprint) {
    return { ok: false, reason: "statement_mismatch" };
  }
  const res = await verifyEvidence({
    signed_payload: st,
    signed_message: cp.statement,
    signature: cp.signature,
    public_key: cp.public_key,
    pq_signature: cp.pq_signature,
    pq_public_key: cp.pq_public_key,
    algorithm: st.algorithm,
  });
  if (res.status !== "verified") return { ok: false, reason: res.status === "unsupported" ? "unsupported" : "signature" };
  if (res.fingerprint !== st.key_fingerprint) return { ok: false, reason: "fingerprint" };
  return { ok: true, fingerprint: res.fingerprint as string, scheme: res.scheme as string, treeSize: cp.tree_size };
}

export async function checkProof(p: ProofT): Promise<ProofCheck> {
  if (!globalThis.crypto?.subtle) return { ok: false, reason: "unsupported" };
  try {
    const recHash = toHex(await sha256(new TextEncoder().encode(p.record.canonical)));
    if (recHash !== p.record.record_hash) return { ok: false, reason: "record_altered" };
    const rec = JSON.parse(p.record.canonical) as { seq?: number; org_id?: number };
    if (rec.seq !== p.leaf_index + 1 || rec.org_id !== p.checkpoint.org_id || p.tree_size !== p.checkpoint.tree_size) {
      return { ok: false, reason: "statement_mismatch" };
    }
    const path = p.inclusion_path.map(hexToBytes);
    if (!(await inclusionOk(p.leaf_index, p.tree_size, hexToBytes(recHash), path, hexToBytes(p.checkpoint.root_hash)))) {
      return { ok: false, reason: "not_included" };
    }
    return await checkCheckpoint(p.checkpoint);
  } catch {
    return { ok: false, reason: "malformed" };
  }
}

// ---- audit key rotation (docs/audit-proofs.md) ----

export interface AuditKeyT {
  fingerprint: string;
  algorithm: string;
  public_key: string;
  pq_public_key: string | null;
  organization_key: boolean;
  created_at: string;
}

export interface HandoverT {
  org_id: number;
  rotation_id: number;
  tree_size: number;
  root_hash: string;
  issued_at: string;
  statement: string;
  old_key_fingerprint: string;
  old_public_key: string;
  old_pq_public_key: string | null;
  old_signature: string;
  old_pq_signature: string | null;
  new_key_fingerprint: string;
  new_public_key: string;
  new_pq_public_key: string | null;
  new_signature: string;
  new_pq_signature: string | null;
}

export interface PendingRotationT {
  id: number;
  new_key: AuditKeyT;
  proposed_by: number;
  proposed_at: string;
  activate_after: string;
  reason: string | null;
  quorum: number;
  approvals: { user_id: number; email: string; approved_at: string; counts: boolean }[];
  ready: boolean;
}

export interface KeyStatusT {
  current: AuditKeyT | null;
  pending: PendingRotationT | null;
  handovers: HandoverT[];
  quorum: number;
  notice_hours: number;
}

export async function getKeyStatus() {
  return (await api.get<KeyStatusT>("/audit-logs/keys")).data;
}

export async function proposeRotation(reason: string) {
  return (await api.post<{ id: number }>("/audit-logs/keys/rotations", { reason: reason || null })).data;
}

export async function approveRotation(id: number, fingerprint: string) {
  return (await api.post(`/audit-logs/keys/rotations/${id}/approve`, { fingerprint })).data;
}

export async function cancelRotation(id: number) {
  return (await api.post(`/audit-logs/keys/rotations/${id}/cancel`)).data;
}

export async function completeRotation(id: number) {
  return (await api.post<HandoverT>(`/audit-logs/keys/rotations/${id}/complete`)).data;
}

/** Both keys signed the same handover statement, and it names exactly these keys. */
export async function checkHandover(h: HandoverT): Promise<boolean> {
  let st: Record<string, unknown>;
  try {
    st = JSON.parse(h.statement);
  } catch {
    return false;
  }
  if (canonicalJson(st) !== h.statement || st.type !== "provenza.audit.key_handover") return false;
  if (st.org_id !== h.org_id || st.rotation_id !== h.rotation_id || st.tree_size !== h.tree_size
      || st.root_hash !== h.root_hash || st.old_key_fingerprint !== h.old_key_fingerprint
      || st.new_key_fingerprint !== h.new_key_fingerprint || h.old_key_fingerprint === h.new_key_fingerprint) {
    return false;
  }
  if (typeof st.old_algorithm !== "string" || typeof st.new_algorithm !== "string") return false;
  const sides = [
    { sig: h.old_signature, pq: h.old_pq_signature, pub: h.old_public_key, pqPub: h.old_pq_public_key, alg: st.old_algorithm, fp: h.old_key_fingerprint },
    { sig: h.new_signature, pq: h.new_pq_signature, pub: h.new_public_key, pqPub: h.new_pq_public_key, alg: st.new_algorithm, fp: h.new_key_fingerprint },
  ];
  for (const s of sides) {
    const res = await verifyEvidence({
      signed_payload: st, signed_message: h.statement, signature: s.sig, public_key: s.pub,
      pq_signature: s.pq, pq_public_key: s.pqPub, algorithm: s.alg,
    });
    if (res.status !== "verified" || res.fingerprint !== s.fp) return false;
  }
  return true;
}

/**
 * Compare the fingerprint this browser pinned with the current key:
 * "match", "changed" (valid handovers lead from the pin to the current key -
 * the new fingerprint still has to be confirmed where it was published),
 * or "unknown" (no valid chain: check where the pin came from first).
 */
export async function pinStatus(pinned: string, current: string, handovers: HandoverT[]): Promise<"match" | "changed" | "unknown"> {
  if (pinned === current) return "match";
  const links = new Map<string, string>();
  for (const h of handovers) if (await checkHandover(h)) links.set(h.old_key_fingerprint, h.new_key_fingerprint);
  let fp: string | undefined = pinned;
  const seen = new Set<string>();
  while (fp && !seen.has(fp)) {
    seen.add(fp);
    fp = links.get(fp);
    if (fp === current) return "changed";
  }
  return "unknown";
}
