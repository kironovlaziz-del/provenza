// Signed policy releases (docs/pvp/edge.md, section 3): the working copy is
// frozen into a release that administrators sign with their passkeys; once a
// release is in force, a change that loosens anything applies only when the
// quorum has signed the next release.
import { api } from "./api";
import { passkeyAssertion, type Challenge } from "./signing";

export interface Change {
  section: string;
  key: string;
  label: string;
  change: "added" | "removed" | "changed";
  fields: { field: string | null; before: unknown; after: unknown }[];
}

export interface ReleaseSummary {
  id: number;
  number: number;
  status: "draft" | "in_force" | "superseded" | "withdrawn";
  created_at: string;
  in_force_at: string | null;
  not_after: number;
  offline_seconds: number;
  bundle: { version: number; sha256: string };
  manifest: { version: number; sha256: string };
  quorum: number;
}

export interface Signer {
  user_id: number;
  email: string;
  signed_at: string;
}

export interface ReleaseSettings {
  quorum: number;
  validity_days: number;
  offline_seconds: number;
  /** SHA-256 of the egress proxy binaries sensors let out of a proxy host */
  proxy_binaries: string[];
  /** SHA-256 of the configurations such a proxy may run with (sha256sum proxy.json) */
  proxy_configs: string[];
  /** enforce: no action without the agent's signature and an egress proxy's judgement under the signed policy */
  enforcement: "observe" | "enforce";
}

export interface ReleaseState {
  settings: ReleaseSettings;
  in_force: (ReleaseSummary & { signers: Signer[]; problem: string | null; expired: boolean }) | null;
  draft: (ReleaseSummary & { signers: Signer[]; changes: Change[]; can_sign: boolean }) | null;
  unsigned_changes: Change[] | null;
  unsigned_count: number | null;
}

export async function getReleaseState(): Promise<ReleaseState> {
  const { data } = await api.get<ReleaseState>("/policy-releases/state");
  return data;
}

export async function prepareRelease(): Promise<ReleaseState> {
  const { data } = await api.post<ReleaseState>("/policy-releases/prepare");
  return data;
}

/** One PIN prompt: this administrator's passkey signs the release. */
export async function signRelease(id: number): Promise<ReleaseState> {
  const { data: ch } = await api.post<Challenge>(`/policy-releases/${id}/challenge`);
  const assertion = await passkeyAssertion(ch);
  const { data } = await api.post<ReleaseState>(`/policy-releases/${id}/sign`, { statement: ch.statement, assertion });
  return data;
}

export async function withdrawRelease(id: number): Promise<ReleaseState> {
  const { data } = await api.post<ReleaseState>(`/policy-releases/${id}/withdraw`);
  return data;
}

export async function saveReleaseSettings(s: ReleaseSettings): Promise<ReleaseSettings> {
  const { data } = await api.put<ReleaseSettings>("/policy-releases/settings", s);
  return data;
}
