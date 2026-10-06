"use client";

import React, { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/Pill";
import { useAuth } from "@/lib/auth";
import {
  getIdentityOverview,
  identityError,
  revokeKey,
  rotateKey,
  saveIdentitySettings,
  type IdentityOverview,
  type IdentitySettings,
} from "@/lib/agent_identity_api";
import Link from "next/link";
import { listEnrollments, revokeEnrollment, type EnrollmentT } from "@/lib/enrollment_api";

const LIST: React.CSSProperties = { maxHeight: 520, overflowY: "auto", overflowX: "auto" };

function EnrollmentTokens({ isAdmin }: { isAdmin: boolean }) {
  const { t, i18n } = useTranslation();
  const [rows, setRows] = useState<EnrollmentT[] | null>(null);
  const load = () => listEnrollments().then(setRows).catch(() => setRows([]));
  useEffect(() => { load(); }, []);
  const STATE: Record<string, string> = { open: "pill-accent", used: "pill-low", revoked: "pill-critical", expired: "pill-neutral" };
  return (
    <div className="panel" style={{ marginBottom: 20 }}>
      <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <h2>{t("enroll.tokens_title")}</h2>
        {isAdmin && <Link href="/agents/new" className="btn btn-sm btn-primary">{t("enroll.issue")}</Link>}
      </div>
      <div style={{ overflowX: "auto" }}>
        <table className="table-cards">
          <thead>
            <tr>
              <th>{t("enroll.col_token")}</th>
              <th>{t("enroll.col_for")}</th>
              <th>{t("enroll.col_state")}</th>
              <th>{t("enroll.col_expires")}</th>
              {isAdmin && <th />}
            </tr>
          </thead>
          <tbody>
            {rows === null && <tr className="empty-row"><td colSpan={5}>{t("common.loading")}</td></tr>}
            {rows?.length === 0 && <tr className="empty-row"><td colSpan={5}>{t("enroll.none")}</td></tr>}
            {rows?.map((r) => (
              <tr key={r.id}>
                <td data-label={t("enroll.col_token")} className="mono">{r.token_prefix}…</td>
                <td data-label={t("enroll.col_for")}>
                  {r.purpose === "rekey" ? t("enroll.for_rekey", { id: r.agent_id }) : (r.name || t("enroll.for_new"))}
                  {r.purpose === "new" && r.agent_id && <div className="hint-text"><Link href={`/agents/${r.agent_id}`}>#{r.agent_id}</Link></div>}
                </td>
                <td data-label={t("enroll.col_state")}><span className={`pill ${STATE[r.state] ?? "pill-neutral"}`}>{t(`enroll.state_${r.state}`)}</span></td>
                <td data-label={t("enroll.col_expires")} className="mono" style={{ fontSize: 12 }}>{new Date(r.expires_at).toLocaleString(i18n.language)}</td>
                {isAdmin && (
                  <td>
                    {r.state === "open" && (
                      <button type="button" className="btn btn-sm" onClick={() => revokeEnrollment(r.id).then(load)}>{t("enroll.revoke")}</button>
                    )}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function AgentIdentityPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [data, setData] = useState<IdentityOverview | null>(null);
  const [form, setForm] = useState<IdentitySettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [issued, setIssued] = useState<{ name: string; key: string; until: string | null } | null>(null);
  const [copied, setCopied] = useState(false);

  const load = useCallback(() => {
    getIdentityOverview()
      .then((d) => {
        setData(d);
        setForm({ ...d.settings });
      })
      .catch((e) => setError(identityError(e, t("identity.load_failed", "Could not load agent identity."))));
  }, [t]);

  useEffect(load, [load]);

  async function run(action: () => Promise<unknown>, ok?: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await action();
      if (ok) setNotice(ok);
      load();
    } catch (e) {
      setError(identityError(e, t("identity.failed", "Could not save.")));
    } finally {
      setBusy(false);
    }
  }

  function save() {
    if (!form || !data) return;
    if (form.require_agent_key && !data.settings.require_agent_key) {
      const ok = window.confirm(
        t(
          "identity.confirm_require",
          "Require agent keys? Agents that still call Provenza with a user's token will be refused on check, record, delegate, messages, memory and the gateway. Make sure every agent has its key first.",
        ),
      );
      if (!ok) return;
    }
    const relaxing = (!form.require_agent_key && data.settings.require_agent_key)
      || (form.allow_keyless_agents && !data.settings.allow_keyless_agents)
      || (form.allow_direct_registration && !data.settings.allow_direct_registration);
    if (relaxing && !window.confirm(t(
      "identity.confirm_relax",
      "Relax agent identity? A user session will be able to act in an agent's name, or agents without a signing key will be able to act unsigned - neither can be verified later. Every change is in the audit log.",
    ))) return;
    if (form.require_pq_signatures && !data.settings.require_pq_signatures) {
      const ok = window.confirm(
        t(
          "identity.confirm_require_pq",
          "Require post-quantum signatures? Agents without a hybrid key (Ed25519-only or no signing key) will have their delegations, actions and messages refused until they get one.",
        ),
      );
      if (!ok) return;
    }
    run(() => saveIdentitySettings(form), t("identity.saved", "Saved"));
  }

  async function rotate(id: number, name: string) {
    if (!window.confirm(t("identity.confirm_rotate", "Issue a new key for this agent? The current key keeps working until the grace period ends."))) return;
    setBusy(true);
    setError(null);
    try {
      const r = await rotateKey(id);
      setIssued({ name, key: r.api_key, until: r.previous_key_valid_until });
      setCopied(false);
      load();
    } catch (e) {
      setError(identityError(e, t("identity.failed", "Could not save.")));
    } finally {
      setBusy(false);
    }
  }

  const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "—");

  if (!data || !form) {
    return (
      <>
        <PageHeader title={t("identity.title", "Agent Identity")} />
        <div className="content"><div className="hint-text">{error ?? t("common.loading", "Loading…")}</div></div>
      </>
    );
  }

  const neverUsed = data.agents.filter((a) => !a.key_last_used_at && !a.key_revoked_at).length;
  const noOwner = data.agents.filter((a) => !a.owner_active).length;

  return (
    <>
      <PageHeader title={t("identity.title", "Agent Identity")} />
      <div className="content">
        <p className="hint-text" style={{ marginTop: 0 }}>
          {t(
            "identity.hint",
            "Each agent authenticates with its own key (header X-Agent-Key). A key works only on agent endpoints, only for its own agent, and never opens admin pages. Actions run on behalf of the agent's owner, or an admin if it has none.",
          )}
        </p>
        {error && <div className="panel" style={{ marginBottom: 16, borderColor: "#ef4444" }}><div className="panel-body" style={{ color: "#ef4444" }}>{error}</div></div>}
        {notice && <div className="hint-text" style={{ marginBottom: 16 }}>{notice}</div>}

        {issued && (
          <div className="panel" style={{ marginBottom: 20, borderColor: "#f59e0b" }}>
            <div className="panel-body">
              <strong>{t("identity.new_key_for", "New key for")} {issued.name}</strong>
              <p className="hint-text" style={{ fontSize: 12, margin: "4px 0 8px" }}>
                {t("identity.shown_once", "Shown only once - store it in the agent's secret store now.")}
                {issued.until ? ` ${t("identity.old_valid_until", "The previous key works until")} ${fmt(issued.until)}.` : ""}
              </p>
              <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                <code className="mono" style={{ fontSize: 13, wordBreak: "break-all", padding: "6px 8px", border: "1px solid var(--border, #ddd)", borderRadius: 6 }}>
                  {issued.key}
                </code>
                <button className="btn btn-sm" onClick={() => { navigator.clipboard?.writeText(issued.key); setCopied(true); }}>
                  {copied ? t("identity.copied", "Copied") : t("identity.copy", "Copy")}
                </button>
                <button className="btn btn-sm" onClick={() => setIssued(null)}>{t("identity.done", "Done")}</button>
              </div>
            </div>
          </div>
        )}

        {(!data.settings.require_agent_key || data.settings.allow_keyless_agents || data.settings.allow_direct_registration) && (
          <div className="panel" style={{ marginBottom: 16, borderColor: "#ef4444" }}>
            <div className="panel-body" style={{ color: "#ef4444", fontSize: 13 }}>
              ⚠ {t("identity.relaxed_warning", "Agent identity is relaxed in this organization:")}{" "}
              {[
                !data.settings.require_agent_key ? t("identity.relaxed_session", "user sessions can act in an agent's name") : null,
                data.settings.allow_keyless_agents ? t("identity.relaxed_keyless", "agents without a signing key can act unsigned") : null,
                data.settings.allow_direct_registration ? t("identity.relaxed_direct", "agents and keys can be registered without proof of possession") : null,
              ].filter(Boolean).join("; ")}.{" "}
              {t("identity.relaxed_hint", "What they do cannot be verified later. Turn it back on in Settings below once your agents use their own keys.")}
            </div>
          </div>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginBottom: 20 }}>
          <div className="panel"><div className="panel-body">
            <div className="hint-text" style={{ fontSize: 12 }}>{t("identity.mode", "Agent key")}</div>
            <div style={{ fontSize: 18, fontWeight: 600 }}>
              {data.settings.require_agent_key ? t("identity.required", "Required") : t("identity.optional", "Optional")}
            </div>
          </div></div>
          <div className="panel"><div className="panel-body">
            <div className="hint-text" style={{ fontSize: 12 }}>{t("identity.never_used", "Keys never used")}</div>
            <div style={{ fontSize: 24, fontWeight: 600 }}>{neverUsed}</div>
          </div></div>
          <div className="panel"><div className="panel-body">
            <div className="hint-text" style={{ fontSize: 12 }}>{t("identity.no_owner", "Agents without an active owner")}</div>
            <div style={{ fontSize: 24, fontWeight: 600 }}>{noOwner}</div>
          </div></div>
        </div>

        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header"><h2>{t("identity.agents_title", "Agent keys")}</h2></div>
          <div className="panel-body" style={LIST}>
            <table>
              <thead>
                <tr>
                  <th>{t("identity.col_agent", "Agent")}</th>
                  <th>{t("identity.col_owner", "Accountable owner")}</th>
                  <th>{t("identity.col_key", "Key")}</th>
                  <th>{t("identity.col_last_used", "Last used")}</th>
                  {isAdmin && <th />}
                </tr>
              </thead>
              <tbody>
                {data.agents.map((a) => (
                  <tr key={a.agent_id}>
                    <td>
                      {a.name} <StatusPill status={a.status} />
                      {!a.has_public_key && <div className="hint-text" style={{ fontSize: 11 }}>{t("identity.no_signing_key", "no signing key")}</div>}
                    </td>
                    <td style={{ fontSize: 12 }}>
                      {a.owner_active ? a.owner : <span style={{ color: "#f59e0b" }}>{t("identity.falls_back_admin", "none - acts as an admin")}</span>}
                    </td>
                    <td style={{ fontSize: 12 }}>
                      {a.key_revoked_at ? (
                        <span className="pill pill-critical">{t("identity.revoked", "revoked")}</span>
                      ) : (
                        <span className="pill pill-low">{t("identity.active", "active")}</span>
                      )}
                      {a.key_rotated_at && <div className="hint-text" style={{ fontSize: 11 }}>{t("identity.rotated", "rotated")} {fmt(a.key_rotated_at)}</div>}
                      {a.previous_key_valid_until && (
                        <div className="hint-text" style={{ fontSize: 11 }}>{t("identity.old_valid_until", "The previous key works until")} {fmt(a.previous_key_valid_until)}</div>
                      )}
                    </td>
                    <td style={{ fontSize: 12 }}>{fmt(a.key_last_used_at)}</td>
                    {isAdmin && (
                      <td style={{ whiteSpace: "nowrap" }}>
                        <button className="btn btn-sm btn-primary" disabled={busy || a.status === "retired"} onClick={() => rotate(a.agent_id, a.name)}>
                          {a.key_revoked_at ? t("identity.issue", "Issue key") : t("identity.rotate", "Rotate")}
                        </button>{" "}
                        {!a.key_revoked_at && (
                          <button className="btn btn-sm" disabled={busy}
                            onClick={() => {
                              if (window.confirm(t("identity.confirm_revoke", "Revoke this agent's key now? It will be refused immediately until a new key is issued.")))
                                run(() => revokeKey(a.agent_id), t("identity.revoked_ok", "Key revoked"));
                            }}>
                            {t("identity.revoke", "Revoke")}
                          </button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <EnrollmentTokens isAdmin={isAdmin} />

        <div className="panel">
          <div className="panel-header"><h2>{t("identity.settings_title", "Settings")}</h2></div>
          <div className="panel-body">
            <label style={{ display: "flex", gap: 10, alignItems: "flex-start", marginBottom: 14 }}>
              <input type="checkbox" checked={form.require_agent_key} disabled={!isAdmin}
                onChange={(e) => setForm({ ...form, require_agent_key: e.target.checked })} style={{ width: "auto", marginTop: 3 }} />
              <span>
                <strong>{t("identity.require", "Require agent keys")}</strong>
                <span className="hint-text" style={{ display: "block", fontSize: 12 }}>
                  {t("identity.require_hint", "A user's session can no longer call check, record, delegate, messages, memory or the gateway in an agent's name. The UI keeps working.")}
                </span>
              </span>
            </label>
            <label style={{ display: "flex", gap: 10, alignItems: "flex-start", marginBottom: 14 }}>
              <input type="checkbox" checked={!!form.require_pq_signatures} disabled={!isAdmin}
                onChange={(e) => setForm({ ...form, require_pq_signatures: e.target.checked })} style={{ width: "auto", marginTop: 3 }} />
              <span>
                <strong>{t("identity.require_pq", "Require post-quantum signatures")}</strong>
                <span className="hint-text" style={{ display: "block", fontSize: 12 }}>
                  {t("identity.require_pq_hint", "New agents and key changes must use the hybrid Ed25519 + ML-DSA-65 scheme; agents without a hybrid key (Ed25519-only or no signing key) cannot delegate, record actions or send messages until they get one.")}
                </span>
              </span>
            </label>
            <label style={{ display: "flex", gap: 10, alignItems: "flex-start", marginBottom: 14 }}>
              <input type="checkbox" checked={!!form.allow_keyless_agents} disabled={!isAdmin}
                onChange={(e) => setForm({ ...form, allow_keyless_agents: e.target.checked })} style={{ width: "auto", marginTop: 3 }} />
              <span>
                <strong>{t("identity.allow_keyless", "Allow agents without a signing key (not recommended)")}</strong>
                <span className="hint-text" style={{ display: "block", fontSize: 12 }}>
                  {t("identity.allow_keyless_hint", "Off by default: an agent without a signing key cannot delegate or record actions, because nothing it does could be verified later. Turn on only temporarily, while agents get their keys.")}
                </span>
              </span>
            </label>
            <label style={{ display: "flex", gap: 10, alignItems: "flex-start", marginBottom: 14 }}>
              <input type="checkbox" checked={!!form.allow_direct_registration} disabled={!isAdmin}
                onChange={(e) => setForm({ ...form, allow_direct_registration: e.target.checked })} style={{ width: "auto", marginTop: 3 }} />
              <span>
                <strong>{t("identity.allow_direct", "Allow registration without proof of possession (not recommended)")}</strong>
                <span className="hint-text" style={{ display: "block", fontSize: 12 }}>
                  {t("identity.allow_direct_hint", "Off by default: agents join with a one-time enrollment token and prove they hold their key; keys change only with proof. On: admins can register agents and replace keys directly, as before.")}
                </span>
              </span>
            </label>
            <div className="field" style={{ margin: 0, maxWidth: 260 }}>
              <label htmlFor="id-grace">{t("identity.grace", "Rotation grace period, minutes")}</label>
              <input id="id-grace" type="number" min={0} max={1440} disabled={!isAdmin} value={form.rotation_grace_minutes}
                onChange={(e) => setForm({ ...form, rotation_grace_minutes: Number(e.target.value) })} />
              <div className="hint-text" style={{ fontSize: 12 }}>{t("identity.grace_hint", "How long the old key keeps working after a rotation (0–1440)")}</div>
            </div>
            {isAdmin && (
              <button className="btn btn-primary btn-sm" style={{ marginTop: 12 }}
                disabled={busy || form.rotation_grace_minutes < 0 || form.rotation_grace_minutes > 1440} onClick={save}>
                {t("identity.save", "Save")}
              </button>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
