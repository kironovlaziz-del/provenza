"use client";

// Every kind of agent incident (the server raises many: action mismatches,
// tampering, impersonation, breaker trips, escalations, ...), filterable,
// with the repeat escalators on top. Reviewers mark them handled.

import React, { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { RiskPill } from "@/components/Pill";
import {
  AgentIncidentTypeCount,
  getAgentIncidentTypes,
  getEscalationSummary,
  listAgentIncidents,
  listAgents,
  resolveAgentIncident,
} from "@/lib/agent_api";
import type { Agent, AgentIncidentT, EscalationSummaryRow } from "@/lib/agent_types";
import { useAuth } from "@/lib/auth";

const SEVERITIES = ["critical", "high", "medium", "low"];

function humanize(type: string) {
  return type.replace(/_/g, " ");
}

/** What matters in an incident's details, without dumping the whole object. */
function DetailSummary({ inc }: { inc: AgentIncidentT }) {
  const { t } = useTranslation();
  const d = (inc.details || {}) as Record<string, unknown>;
  const list = (key: string) => (Array.isArray(d[key]) ? (d[key] as unknown[]).map(String) : []);
  if (list("escalated").length) {
    return (
      <span>
        {t("agent_incidents.over_requested")}: <span className="u-mono">{list("escalated").join(", ")}</span>
        {list("parent_had").length > 0 && (
          <span className="hint-text"> · {t("agent_incidents.parent_had")}: {list("parent_had").join(", ")}</span>
        )}
      </span>
    );
  }
  const shown = Object.entries(d)
    .filter(([, v]) => v !== null && v !== "" && (typeof v !== "object" || Array.isArray(v)))
    .slice(0, 4);
  if (!shown.length) return <span className="hint-text">—</span>;
  return (
    <span className="u-mono" style={{ fontSize: 12 }}>
      {shown.map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : String(v)}`).join(" · ")}
    </span>
  );
}

export function AgentIncidents() {
  const { t, i18n } = useTranslation();
  const { user } = useAuth();
  const canTriage = user?.role === "admin" || user?.role === "approver";

  const [types, setTypes] = useState<AgentIncidentTypeCount[]>([]);
  const [type, setType] = useState("");
  const [severity, setSeverity] = useState("");
  const [unresolvedOnly, setUnresolvedOnly] = useState(true);
  const [rows, setRows] = useState<AgentIncidentT[]>([]);
  const [summary, setSummary] = useState<EscalationSummaryRow[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<number | null>(null);

  useEffect(() => {
    getAgentIncidentTypes().then(setTypes).catch(() => setTypes([]));
    getEscalationSummary().then((s) => setSummary(s.agents || [])).catch(() => setSummary([]));
    listAgents(500).then(setAgents).catch(() => setAgents([]));
  }, []);

  function load() {
    setLoading(true);
    listAgentIncidents({
      ...(type ? { incident_type: type } : {}),
      ...(severity ? { severity } : {}),
      unresolved_only: unresolvedOnly,
      limit: 200,
    })
      .then((page) => setRows(page.items || []))
      .finally(() => setLoading(false));
  }
  useEffect(load, [type, severity, unresolvedOnly]); // eslint-disable-line react-hooks/exhaustive-deps

  const agentName = useMemo(() => new Map(agents.map((a) => [a.id, a.name])), [agents]);
  const name = (id?: number | null) => (id ? agentName.get(id) ?? `#${id}` : "—");
  const typeLabel = (k: string) => t(`agent_incidents.types.${k}`, { defaultValue: humanize(k) });

  async function setResolved(inc: AgentIncidentT, resolved: boolean) {
    setBusyId(inc.id);
    try {
      await resolveAgentIncident(inc.id, resolved);
      load();
      getAgentIncidentTypes().then(setTypes);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <>
      <p className="hint-text u-mb-16">{t("agent_incidents.hint_all")}</p>

      {summary.length > 0 && (!type || type === "capability_escalation") && (
        <div className="panel u-mb-16">
          <div className="panel-header"><h2>{t("agent_incidents.repeat_offenders")}</h2></div>
          <div className="panel-body u-row-tight">
            {summary.map((row) => (
              <div key={row.agent_id} className="stat" style={{ minWidth: 160 }}>
                <div className="stat-label">{name(row.agent_id)}</div>
                <div className="stat-value" style={row.attempts >= 3 ? { color: "var(--risk-critical)" } : undefined}>
                  {row.attempts} <span className="hint-text">{t("agent_incidents.attempts")}</span>
                </div>
                {row.last_attempt && (
                  <div className="hint-text">{t("agent_incidents.last")}: {new Date(row.last_attempt).toLocaleString(i18n.language)}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="panel">
        <div className="panel-header u-flex u-justify-between u-items-center u-flex-wrap u-gap-8">
          <h2>{t("agent_incidents.all_title")}</h2>
          <div className="u-row-tight u-items-center">
            <select value={type} onChange={(e) => setType(e.target.value)} aria-label={t("agent_incidents.type")}>
              <option value="">{t("agent_incidents.all_types")}</option>
              {types.filter((x) => x.incident_type).map((x) => (
                <option key={x.incident_type!} value={x.incident_type!}>
                  {typeLabel(x.incident_type!)} ({unresolvedOnly ? x.unresolved : x.total})
                </option>
              ))}
            </select>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label={t("incidents.col_severity")}>
              <option value="">{t("incidents.filter_severity_all")}</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{t(`incidents.filter_severity_${s}`)}</option>)}
            </select>
            <label className="u-flex u-items-center u-gap-6 hint-text">
              <input type="checkbox" style={{ width: "auto" }} checked={unresolvedOnly}
                     onChange={(e) => setUnresolvedOnly(e.target.checked)} />
              {t("agent_incidents.unresolved_only")}
            </label>
          </div>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table>
            <thead>
              <tr>
                <th>{t("incidents.col_severity")}</th>
                <th>{t("agent_incidents.type")}</th>
                <th>{t("agent_incidents.agent")}</th>
                <th>{t("agent_incidents.details")}</th>
                <th>{t("agent_incidents.chain")}</th>
                <th>{t("agent_incidents.when")}</th>
                {canTriage && <th></th>}
              </tr>
            </thead>
            <tbody>
              {loading && <tr className="empty-row"><td colSpan={7}>{t("common.loading")}</td></tr>}
              {!loading && rows.length === 0 && (
                <tr className="empty-row"><td colSpan={7}>{t("agent_incidents.none")}</td></tr>
              )}
              {rows.map((inc) => (
                <tr key={inc.id} style={inc.resolved ? { opacity: 0.6 } : undefined}>
                  <td>{inc.severity ? <RiskPill level={inc.severity} /> : "—"}</td>
                  <td>{inc.incident_type ? typeLabel(inc.incident_type) : "—"}</td>
                  <td>{name(inc.agent_id)}</td>
                  <td><DetailSummary inc={inc} /></td>
                  <td className="hint-text">{inc.chain_id ? `#${inc.chain_id}` : "—"}</td>
                  <td className="u-mono u-nowrap">{new Date(inc.created_at).toLocaleString(i18n.language)}</td>
                  {canTriage && (
                    <td className="u-nowrap">
                      <button className={`btn btn-sm${inc.resolved ? "" : " btn-primary"}`} disabled={busyId === inc.id}
                              onClick={() => setResolved(inc, !inc.resolved)}>
                        {inc.resolved ? t("incidents.btn_reopen") : t("incidents.btn_resolve")}
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
