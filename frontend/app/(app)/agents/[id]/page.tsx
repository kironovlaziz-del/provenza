"use client";

import React, { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { getAgent, listAgentActions, listSigningKeys, setSigningKey } from "@/lib/agent_api";
import type { Agent, AgentActionT, SigningKeyT } from "@/lib/agent_types";
import { useAuth } from "@/lib/auth";
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

  useEffect(() => {
    Promise.all([getAgent(agentId), listAgentActions({ agent_id: agentId }), listSigningKeys(agentId).catch(() => [])])
      .then(([a, acts, ks]) => {
        setAgent(a);
        setActions(acts);
        setKeys(ks);
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
      setKeys(await listSigningKeys(agentId));
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

  const chips = (label: string, values?: string[] | null) => (
    <div className="field">
      <label>{label}</label>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
        {(values && values.length > 0)
          ? values.map((v) => (
              <span key={v} className="pill pill-neutral mono" style={{ fontSize: 11 }}>{v}</span>
            ))
          : <span className="hint-text">—</span>}
      </div>
    </div>
  );

  return (
    <>
      <PageHeader title={`🤖 ${agent.name}`} />
      <div className="content">
        <Link href="/agents" className="btn btn-sm" style={{ marginBottom: 16 }}>← {t("agents.back")}</Link>

        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-body">
            <div style={{ display: "flex", gap: 24, flexWrap: "wrap", marginBottom: 12 }}>
              <div><div className="hint-text">{t("agents.col_type")}</div><strong>{agent.agent_type || "—"}</strong></div>
              <div><div className="hint-text">{t("agents.col_status")}</div><strong>{t(`agents.status_${agent.status}`, agent.status)}</strong></div>
              <div><div className="hint-text">{t("agents.col_depth")}</div><strong>{agent.max_delegation_depth}</strong></div>
              <div><div className="hint-text">{t("agents.owner_team")}</div><strong>{agent.owner_team || "—"}</strong></div>
            </div>
            {chips(t("agents.capabilities"), agent.capabilities)}
            {chips(t("agents.tools"), agent.allowed_tools)}
            {chips(t("agents.models"), agent.allowed_models)}
            {agent.public_key && (
              <div className="field">
                <label>{t("agents.public_key")}</label>
                <code className="mono" style={{ fontSize: 11, wordBreak: "break-all" }}>{agent.public_key}</code>
              </div>
            )}
            {agent.key_fingerprint && (
              <div className="field">
                <label>{t("agents.key_fingerprint")}</label>
                <code className="mono" style={{ fontSize: 11, wordBreak: "break-all" }}>{agent.key_fingerprint}</code>
                <p className="hint-text" style={{ marginTop: 4 }}>
                  {t("agents.scheme")}: {agent.pq_public_key ? t("agents.scheme_hybrid") : t("agents.scheme_classic")}
                </p>
                <p className="hint-text" style={{ marginTop: 4 }}>
                  {agent.key_origin === "server" ? t("agents.key_server_note") : t("agents.key_agent_note")}
                </p>
              </div>
            )}
          </div>
        </div>

        <h2 style={{ fontSize: 15, marginBottom: 12 }}>{t("agents.signing_keys")}</h2>
        <div className="panel" style={{ marginBottom: 20 }}>
          <table>
            <thead>
              <tr>
                <th>{t("agents.key_fingerprint")}</th>
                <th>{t("agents.scheme")}</th>
                <th>{t("agents.key_origin")}</th>
                <th>{t("agents.key_from")}</th>
                <th>{t("agents.key_until")}</th>
              </tr>
            </thead>
            <tbody>
              {keys.length === 0 && <tr className="empty-row"><td colSpan={5}>—</td></tr>}
              {keys.map((k) => (
                <tr key={k.id}>
                  <td className="mono" style={{ fontSize: 11 }}>{k.fingerprint}</td>
                  <td>{k.pq_public_key ? t("agents.scheme_hybrid_short") : t("agents.scheme_classic_short")}</td>
                  <td>{t(`agents.key_origin_${k.origin}`)}</td>
                  <td className="mono" style={{ fontSize: 12 }}>{new Date(k.created_at).toLocaleString(i18n.language)}</td>
                  <td className="mono" style={{ fontSize: 12 }}>
                    {k.retired_at ? new Date(k.retired_at).toLocaleString(i18n.language) : t("agents.key_current")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {isAdmin && (
            <div className="panel-body" style={{ borderTop: "1px solid var(--border, #334155)" }}>
              <form onSubmit={handleSetKey}>
                <div className="field">
                  <label>{t("agents.key_replace")}</label>
                  <input
                    className="mono"
                    required
                    value={newKey}
                    onChange={(e) => setNewKey(e.target.value)}
                    placeholder={t("agents.public_key_placeholder")}
                  />
                  <p className="hint-text">{t("agents.key_replace_hint")}</p>
                </div>
                <div className="field">
                  <label>{t("agents.pq_public_key")}</label>
                  <textarea
                    className="mono"
                    rows={3}
                    value={newPqKey}
                    onChange={(e) => setNewPqKey(e.target.value)}
                    placeholder={t("agents.pq_public_key_placeholder")}
                    style={{ fontSize: 11, wordBreak: "break-all" }}
                  />
                  <p className="hint-text">{t("agents.pq_public_key_replace_hint")}</p>
                </div>
                {keyError && <p className="error-text">{keyError}</p>}
                <button className="btn btn-sm btn-primary" type="submit" disabled={savingKey || !newKey.trim()}>
                  {t("agents.key_replace_submit")}
                </button>
              </form>
            </div>
          )}
        </div>

        <h2 style={{ fontSize: 15, marginBottom: 12 }}>{t("agents.recent_actions")}</h2>
        <div className="panel">
          <table>
            <thead>
              <tr>
                <th>{t("chains.tl_time")}</th>
                <th>{t("chains.tl_tool")}</th>
                <th>{t("chains.tl_result")}</th>
                <th>{t("chains.tl_reason")}</th>
              </tr>
            </thead>
            <tbody>
              {actions.length === 0 && <tr className="empty-row"><td colSpan={4}>{t("chains.no_actions")}</td></tr>}
              {actions.map((a) => (
                <tr key={a.id}>
                  <td className="mono" style={{ fontSize: 12 }}>{new Date(a.created_at).toLocaleString(i18n.language)}</td>
                  <td className="mono" style={{ fontSize: 12 }}>{a.tool_name}</td>
                  <td><span className={`pill ${a.policy_check_result === "denied" ? "pill-critical" : "pill-low"}`}>{a.policy_check_result}</span></td>
                  <td className="hint-text" style={{ fontSize: 12 }}>{a.reason || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
