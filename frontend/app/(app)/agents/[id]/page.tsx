"use client";

import React, { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { getAgent, updateAgent, killAgent, listAgentActions, listKeyRevocations, listSigningKeys, revokeSigningKey, setSigningKey } from "@/lib/agent_api";
import type { Agent, AgentActionT, KeyRevocationT, SigningKeyT } from "@/lib/agent_types";
import { useAuth } from "@/lib/auth";
import { getIdentityOverview } from "@/lib/agent_identity_api";
import { issueEnrollment, type EnrollmentT } from "@/lib/enrollment_api";
import { EnrollPanel } from "@/components/EnrollPanel";
import { AgentAssignment } from "@/components/AgentAssignment";
import { AgentAttestation } from "@/components/AgentAttestation";
import { translateApiError } from "@/lib/errors";

export default function AgentDetailPage() {
  const params = useParams<{ id: string }>();
  const agentId = Number(params.id);
  const { t, i18n } = useTranslation();
  const [agent, setAgent] = useState<Agent | null>(null);
  const [actions, setActions] = useState<AgentActionT[]>([]);
  const [loading, setLoading] = useState(true);
  const [keys, setKeys] = useState<SigningKeyT[]>([]);
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [newKey, setNewKey] = useState("");
  const [newPqKey, setNewPqKey] = useState("");
  const [keyError, setKeyError] = useState<string | null>(null);
  const [savingKey, setSavingKey] = useState(false);
  const [revocations, setRevocations] = useState<KeyRevocationT[]>([]);
  const [revoking, setRevoking] = useState<{ keyId: number; reason: string; since: string } | null>(null);
  const [revokeError, setRevokeError] = useState<string | null>(null);
  const [rekey, setRekey] = useState<EnrollmentT | null>(null);
  const [directAllowed, setDirectAllowed] = useState(false);
  const [statusError, setStatusError] = useState<string | null>(null);

  useEffect(() => {
    if (!isAdmin) return;
    getIdentityOverview().then((o) => setDirectAllowed(!!o.settings.allow_direct_registration)).catch(() => setDirectAllowed(false));
  }, [isAdmin]);

  async function reloadKeys() {
    const [ks, rs] = await Promise.all([listSigningKeys(agentId).catch(() => []), listKeyRevocations(agentId).catch(() => [])]);
    setKeys(ks);
    setRevocations(rs);
  }

  async function handleRevoke(e: React.FormEvent) {
    e.preventDefault();
    if (!revoking) return;
    setRevokeError(null);
    try {
      // datetime-local is local time; the API takes an absolute moment
      const since = revoking.since ? new Date(revoking.since).toISOString() : undefined;
      await revokeSigningKey(agentId, revoking.keyId, revoking.reason.trim(), since);
      setRevoking(null);
      setAgent(await getAgent(agentId));
      await reloadKeys();
    } catch (err) {
      const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
      setRevokeError(translateApiError(detail, t, t("agents.revoke_failed")));
    }
  }

  useEffect(() => {
    Promise.all([getAgent(agentId), listAgentActions({ agent_id: agentId }), listSigningKeys(agentId).catch(() => [])])
      .then(([a, acts, ks]) => {
        setAgent(a);
        setActions(acts);
        setKeys(ks);
        listKeyRevocations(agentId).then(setRevocations).catch(() => setRevocations([]));
      })
      .finally(() => setLoading(false));
  }, [agentId]);

  async function handleSetKey(e: React.FormEvent) {
    e.preventDefault();
    setSavingKey(true);
    setKeyError(null);
    try {
      const updated = await setSigningKey(agentId, newKey.trim(), newPqKey.replace(/\s+/g, "") || undefined);
      setAgent(updated);
      await reloadKeys();
      setNewKey("");
      setNewPqKey("");
    } catch (err) {
      const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
      setKeyError(
        Array.isArray(detail) && detail[0]?.msg
          ? String(detail[0].msg).replace(/^Value error, /, "")
          : translateApiError(detail, t, t("agents.key_set_failed")),
      );
    } finally {
      setSavingKey(false);
    }
  }

  if (loading) return <div className="content"><p className="hint-text">{t("common.loading")}</p></div>;
  if (!agent) return <div className="content"><p className="hint-text">{t("agents.not_found")}</p></div>;
  const currentKey = keys.find((k) => !k.retired_at) ?? null;
  const revocationOf = (k: SigningKeyT) =>
    revocations.find((r) => r.signing_key_id === k.id || r.fingerprint === k.fingerprint) ?? null;
  const currentRevoked = currentKey ? revocationOf(currentKey) : null;
  const fmt = (iso: string) => new Date(iso).toLocaleString(i18n.language);
  const statusPill = agent.status === "active" ? "pill-low" : agent.status === "suspended" ? "pill-medium" : "pill-neutral";
  const scheme = !agent.public_key ? "none" : agent.pq_public_key ? "hybrid" : "classic";

  async function kill() {
    const reason = window.prompt(t("agents.kill_prompt", { name: agent?.name }) as string);
    if (reason === null) return;
    setStatusError(null);
    try {
      await killAgent(agentId, reason || "manual kill", true);
      setAgent(await getAgent(agentId));
    } catch (err) {
      const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
      setStatusError(translateApiError(detail, t, t("agents.status_change_failed")));
    }
  }

  async function changeStatus(next: "active" | "retired") {
    const question = next === "retired" ? t("agents.confirm_retire", { name: agent?.name }) : t("agents.confirm_reactivate", { name: agent?.name });
    if (!window.confirm(question)) return;
    setStatusError(null);
    try {
      setAgent(await updateAgent(agentId, { status: next }));
    } catch (err) {
      const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
      setStatusError(translateApiError(detail, t, t("agents.status_change_failed")));
    }
  }

  const chips = (label: string, values?: string[] | null) => (
    <div className="ag-rights-row">
      <div className="ag-label">{label}</div>
      <div className="ag-chips">
        {values && values.length > 0
          ? values.map((v) => <span key={v} className="pill pill-neutral">{v}</span>)
          : <span className="hint-text">—</span>}
      </div>
    </div>
  );

  return (
    <>
      <PageHeader
        title={agent.name}
        actions={
          <>
            {/* active: Kill (suspend) or Retire; suspended: Reactivate or Retire; retired: final */}
            {isAdmin && agent.status === "active" && (
              <button type="button" className="btn btn-sm btn-danger" onClick={kill}>{t("agents.kill")}</button>
            )}
            {isAdmin && agent.status === "suspended" && (
              <button type="button" className="btn btn-sm" onClick={() => changeStatus("active")}>{t("agents.reactivate")}</button>
            )}
            {isAdmin && agent.status !== "retired" && (
              <button type="button" className="btn btn-sm" onClick={() => changeStatus("retired")}>{t("agents.retire")}</button>
            )}
            <Link href="/agents" className="btn btn-sm">← {t("agents.back")}</Link>
          </>
        }
      />
      <div className="content agent-page">
        {/* ---- summary ---- */}
        <div className="panel ag-hero">
          <div className="ag-hero-main">
            <div className="ag-hero-badges">
              <span className={`pill ${statusPill}`}>{t(`agents.status_${agent.status}`, agent.status)}</span>
              {agent.agent_type && <span className="pill pill-neutral">{agent.agent_type}</span>}
              <span className={`pill ${scheme === "hybrid" ? "pill-accent" : scheme === "classic" ? "pill-neutral" : "pill-high"}`}>
                {scheme === "hybrid" ? t("agents.scheme_hybrid_short") : scheme === "classic" ? t("agents.scheme_classic_short") : t("agents.no_key")}
              </span>
              {currentRevoked && <span className="pill pill-critical">{t("agents.key_revoked")}</span>}
            </div>
            {agent.description && <p className="ag-desc">{agent.description}</p>}
          </div>
          <dl className="ag-facts">
            <div><dt>{t("agents.col_depth")}</dt><dd>{agent.max_delegation_depth}</dd></div>
            <div><dt>ID</dt><dd>#{agent.id}</dd></div>
            <div><dt>{t("agents.created")}</dt><dd>{new Date(agent.created_at).toLocaleDateString(i18n.language)}</dd></div>
          </dl>
        </div>

        {statusError && <p className="error-text ag-banner">{statusError}</p>}
        {agent.status === "retired" && <p className="hint-text ag-banner">{t("agents.retired_note")}</p>}
        {currentRevoked && agent.status === "active" && (
          <p className="error-text ag-banner">{t("agents.current_key_revoked_banner")}</p>
        )}

        <div className="ag-grid">
          {/* ---- access ---- */}
          <section className="panel">
            <div className="panel-header"><h2>{t("agents.access")}</h2></div>
            <div className="panel-body ag-stack">
              <AgentAssignment agent={agent} isAdmin={isAdmin} onChanged={() => { getAgent(agentId).then(setAgent).catch(() => undefined); }} />
              {chips(t("agents.capabilities"), agent.capabilities)}
              {chips(t("agents.tools"), agent.allowed_tools)}
              {chips(t("agents.models"), agent.allowed_models)}
              {(user?.role === "admin" || user?.role === "approver") && (
                <Link href={`/policy-hierarchy?agent=${agent.id}`} className="ag-small">{t("ph.agent_effective_link")} →</Link>
              )}
            </div>
          </section>

          {/* ---- identity ---- */}
          <section className="panel">
            <div className="panel-header"><h2>{t("agents.identity")}</h2></div>
            <div className="panel-body ag-stack">
              <AgentAttestation agentId={agentId} rev={agent.role_id} />
              {agent.key_fingerprint ? (
                <>
                  <div>
                    <div className="ag-label">{t("agents.key_fingerprint")}</div>
                    <code className="ag-code">{agent.key_fingerprint}</code>
                  </div>
                  <div className="ag-kv">
                    <div><div className="ag-label">{t("agents.scheme")}</div>{agent.pq_public_key ? t("agents.scheme_hybrid") : t("agents.scheme_classic")}</div>
                    {agent.key_origin && <div><div className="ag-label">{t("agents.key_origin")}</div>{t(`agents.key_origin_${agent.key_origin}`)}</div>}
                    {currentKey && <div><div className="ag-label">{t("agents.key_from")}</div>{fmt(currentKey.created_at)}</div>}
                  </div>
                  {currentRevoked && (
                    <div className="ag-revoked">
                      <span className="pill pill-critical">{t("agents.key_revoked")}</span>{" "}
                      {t("agents.key_untrusted_from", { time: fmt(currentRevoked.untrusted_from) })}
                      {currentRevoked.reason && <div className="hint-text">{currentRevoked.reason}</div>}
                    </div>
                  )}
                  <p className="hint-text ag-small">
                    {agent.key_origin === "server" ? t("agents.key_server_note") : t("agents.key_agent_note")}
                  </p>
                  {agent.public_key && (
                    <details className="ag-details">
                      <summary>{t("agents.public_key")}</summary>
                      <code className="ag-code">{agent.public_key}</code>
                      {agent.pq_public_key && (
                        <>
                          <div className="ag-label" style={{ marginTop: 8 }}>{t("agents.pq_public_key")}</div>
                          <code className="ag-code ag-code-long">{agent.pq_public_key}</code>
                        </>
                      )}
                    </details>
                  )}
                </>
              ) : (
                <p className="hint-text">{t("agents.no_key_hint")}</p>
              )}
            </div>
          </section>
        </div>

        {/* ---- signing keys ---- */}
        <section className="panel ag-section">
          <div className="panel-header"><h2>{t("agents.signing_keys")}</h2></div>
          <div className="ag-table-wrap">
            <table className="table-cards">
              <thead>
                <tr>
                  <th>{t("agents.key_fingerprint")}</th>
                  <th>{t("agents.scheme")}</th>
                  <th>{t("agents.key_origin")}</th>
                  <th>{t("agents.key_period")}</th>
                  <th>{t("agents.key_revocation")}</th>
                </tr>
              </thead>
              <tbody>
                {keys.length === 0 && <tr className="empty-row"><td colSpan={5}>—</td></tr>}
                {keys.map((k) => {
                  const rev = revocationOf(k);
                  return (
                    <React.Fragment key={k.id}>
                      <tr>
                        <td data-label={t("agents.key_fingerprint")}>
                          <code className="ag-fp" title={k.fingerprint}>{k.fingerprint}</code>
                        </td>
                        <td data-label={t("agents.scheme")}>
                          <span className={`pill ${k.pq_public_key ? "pill-accent" : "pill-neutral"}`}>
                            {k.pq_public_key ? t("agents.scheme_hybrid_short") : t("agents.scheme_classic_short")}
                          </span>
                        </td>
                        <td data-label={t("agents.key_origin")} className="ag-nowrap">{t(`agents.key_origin_${k.origin}`)}</td>
                        <td data-label={t("agents.key_period")} className="ag-period">
                          <div>{fmt(k.created_at)}</div>
                          <div className="hint-text">→ {k.retired_at ? fmt(k.retired_at) : t("agents.key_current")}</div>
                        </td>
                        <td data-label={t("agents.key_revocation")}>
                          {rev ? (
                            <div className="ag-rev-cell" title={rev.reason}>
                              <span className="pill pill-critical">{t("agents.key_revoked")}</span>
                              <div className="hint-text">{t("agents.key_untrusted_from", { time: fmt(rev.untrusted_from) })}</div>
                              {rev.reason && <div className="hint-text ag-reason">«{rev.reason}»</div>}
                            </div>
                          ) : isAdmin ? (
                            <button type="button" className="btn btn-sm" onClick={() => { setRevokeError(null); setRevoking({ keyId: k.id, reason: "", since: "" }); }}>
                              {t("agents.key_revoke")}
                            </button>
                          ) : <span className="hint-text">—</span>}
                        </td>
                      </tr>
                      {revoking?.keyId === k.id && (
                        <tr className="ag-form-row">
                          <td colSpan={5}>
                            <form onSubmit={handleRevoke} className="ag-stack">
                              <div className="hint-text">{t(k.retired_at ? "agents.revoke_hint" : "agents.revoke_hint_current")}</div>
                              <div className="form-row">
                                <div className="field">
                                  <label htmlFor={`rv-reason-${k.id}`}>{t("agents.revoke_reason")}</label>
                                  <input id={`rv-reason-${k.id}`} required minLength={3} maxLength={500} value={revoking.reason}
                                    onChange={(e) => setRevoking({ ...revoking, reason: e.target.value })} />
                                </div>
                                <div className="field">
                                  <label htmlFor={`rv-since-${k.id}`}>{t("agents.revoke_since")}</label>
                                  <input id={`rv-since-${k.id}`} type="datetime-local" value={revoking.since}
                                    onChange={(e) => setRevoking({ ...revoking, since: e.target.value })} />
                                </div>
                              </div>
                              {revokeError && <div className="error-text">{revokeError}</div>}
                              <div className="ag-actions">
                                <button type="submit" className="btn btn-sm btn-danger">{t("agents.key_revoke")}</button>
                                <button type="button" className="btn btn-sm" onClick={() => setRevoking(null)}>{t("common.cancel")}</button>
                              </div>
                            </form>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
          {isAdmin && (
            <div className="panel-body ag-footer">
              <div className="hint-text ag-small">{t("enroll.rotate_hint")}</div>
              {!rekey ? (
                <div>
                  <button type="button" className="btn btn-sm" onClick={async () => {
                    try {
                      setRekey(await issueEnrollment({ purpose: "rekey", agent_id: agentId, require_hybrid: !!agent?.pq_public_key }));
                    } catch (err) {
                      const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
                      setKeyError(translateApiError(detail, t, t("agents.key_set_failed")));
                    }
                  }}>
                    {t("enroll.issue_rekey")}
                  </button>
                  {keyError && !directAllowed && <p className="error-text">{keyError}</p>}
                </div>
              ) : (
                <>
                  <p className="hint-text">{t("enroll.token_once")}</p>
                  <EnrollPanel token={rekey.token ?? ""} hybrid={rekey.require_hybrid} rekey />
                </>
              )}
            </div>
          )}
          {isAdmin && directAllowed && (
            <details className="panel-body ag-footer ag-details">
              <summary>{t("agents.key_replace")} — {t("enroll.unproven")}</summary>
              <form onSubmit={handleSetKey} style={{ marginTop: 10 }}>
                <div className="field">
                  <label htmlFor="ag-new-key">{t("agents.public_key")}</label>
                  <input id="ag-new-key" className="mono" required value={newKey} onChange={(e) => setNewKey(e.target.value)}
                    placeholder={t("agents.public_key_placeholder")} />
                  <p className="hint-text">{t("agents.key_replace_hint")}</p>
                </div>
                <div className="field">
                  <label htmlFor="ag-new-pq">{t("agents.pq_public_key")}</label>
                  <textarea id="ag-new-pq" className="mono" rows={3} value={newPqKey} onChange={(e) => setNewPqKey(e.target.value)}
                    placeholder={t("agents.pq_public_key_placeholder")} style={{ fontSize: 11, wordBreak: "break-all" }} />
                  <p className="hint-text">{t("agents.pq_public_key_replace_hint")}</p>
                </div>
                {keyError && <p className="error-text">{keyError}</p>}
                <button className="btn btn-sm btn-primary" type="submit" disabled={savingKey || !newKey.trim()}>
                  {t("agents.key_replace_submit")}
                </button>
              </form>
            </details>
          )}
        </section>

        {/* ---- recent actions ---- */}
        <section className="panel ag-section">
          <div className="panel-header"><h2>{t("agents.recent_actions")}</h2></div>
          <div className="ag-table-wrap">
            <table className="table-cards">
              <thead>
                <tr>
                  <th>{t("chains.tl_time")}</th>
                  <th>{t("chains.tl_tool")}</th>
                  <th>{t("chains.tl_result")}</th>
                  <th>{t("chains.tl_reason")}</th>
                </tr>
              </thead>
              <tbody>
                {actions.length === 0 && <tr className="empty-row"><td colSpan={4} className="hint-text" style={{ textAlign: "center", padding: 24 }}>{t("chains.no_actions")}</td></tr>}
                {actions.map((a) => (
                  <tr key={a.id}>
                    <td data-label={t("chains.tl_time")} className="mono" style={{ fontSize: 12, whiteSpace: "nowrap" }}>{fmt(a.created_at)}</td>
                    <td data-label={t("chains.tl_tool")} className="mono" style={{ fontSize: 12 }}>{a.tool_name}</td>
                    <td data-label={t("chains.tl_result")}><span className={`pill ${a.policy_check_result === "denied" ? "pill-critical" : "pill-low"}`}>{a.policy_check_result}</span></td>
                    <td data-label={t("chains.tl_reason")} className="hint-text" style={{ fontSize: 12 }}>{a.reason || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </>
  );
}
