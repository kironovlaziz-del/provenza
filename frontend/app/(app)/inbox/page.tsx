"use client";

// Inbox: what is waiting for a person, in one place - actions an agent may run
// only after a human approves them (decided right here, signed as on the
// Approvals page), open incidents, and AI found in use that nobody reviewed
// yet. Beside it, a short summary of what runs on its own.

import Link from "next/link";
import { useRouter } from "next/navigation";
import React, { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { PageHeader } from "@/components/PageHeader";
import { LoadError } from "@/components/LoadError";
import { RiskPill } from "@/components/Pill";
import { SetupChecklist } from "@/components/SetupChecklist";
import { AgentActionApprovals } from "@/components/approvals/AgentActionApprovals";
import { useAuth } from "@/lib/auth";
import { apiErrorMessage } from "@/lib/inventory_api";
import { homeFor } from "@/lib/navigation";
import {
  fetchDashboardStats, listIncidentsPage, listShadowSightings, updateShadowSighting, type DashboardStats,
} from "@/lib/api";
import { listAgentIncidents } from "@/lib/agent_api";
import type { AgentIncidentT } from "@/lib/agent_types";
import { listFoundAgents, type FoundAgentT } from "@/lib/endpoints_api";
import type { Incident, ShadowSighting } from "@/lib/types";

type Filter = "all" | "approvals" | "incidents" | "new_ai";

function humanize(k: string) {
  return k.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

export default function InboxPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const router = useRouter();
  const role = user?.role;
  const decider = role === "admin" || role === "approver";

  const [filter, setFilter] = useState<Filter>("all");
  const [approvals, setApprovals] = useState<number | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [agentIncidents, setAgentIncidents] = useState<AgentIncidentT[]>([]);
  const [sightings, setSightings] = useState<ShadowSighting[]>([]);
  const [found, setFound] = useState<FoundAgentT[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState<number | null>(null);

  // a plain user decides nothing: their start page is the AI list
  useEffect(() => {
    if (role && homeFor(role) !== "/inbox") router.replace(homeFor(role));
  }, [role, router]);

  const refresh = useCallback(() => {
    // each list on its own: one that fails does not hide the others
    const fail = (e: unknown) => setLoadError(apiErrorMessage(e, t("common.load_failed")));
    setLoadError(null);
    Promise.allSettled([
      listIncidentsPage(0, 100).then((p) => setIncidents(p.items.filter((i) => i.status !== "resolved"))).catch(fail),
      listAgentIncidents({ unresolved_only: true, limit: 50 }).then((p) => setAgentIncidents(p.items)).catch(fail),
      listShadowSightings("new").then(setSightings).catch(fail),
      listFoundAgents("new", 0, 50).then((p) => setFound(p.items)).catch(fail),
      fetchDashboardStats(7).then(setStats).catch(fail),
    ]).finally(() => setLoaded(true));
  }, [t]);

  useEffect(() => {
    if (role && homeFor(role) === "/inbox") refresh();
  }, [role, refresh]);

  async function dismiss(s: ShadowSighting) {
    setBusy(s.id);
    try {
      await updateShadowSighting(s.id, { status: "dismissed" });
      setSightings((list) => list.filter((x) => x.id !== s.id));
    } catch (e) {
      setLoadError(apiErrorMessage(e, t("common.load_failed")));
    } finally {
      setBusy(null);
    }
  }

  const incidentCount = incidents.length + agentIncidents.length;
  const newAiCount = sightings.length + found.length;
  const total = (approvals ?? 0) + incidentCount + newAiCount;
  const show = (f: Filter) => filter === "all" || filter === f;
  const chips: { key: Filter; label: string; n: number }[] = [
    { key: "all", label: t("inbox.all"), n: total },
    { key: "approvals", label: t("inbox.approvals"), n: approvals ?? 0 },
    { key: "incidents", label: t("inbox.incidents"), n: incidentCount },
    { key: "new_ai", label: t("inbox.new_ai"), n: newAiCount },
  ];

  if (role && homeFor(role) !== "/inbox") return null; // on its way to the AI list

  return (
    <>
      <PageHeader title={t("inbox.title")} />
      <div className="content">
        <p className="hint-text u-mb-16">{t("inbox.hint")}</p>
        <LoadError message={loadError} onRetry={refresh} />
        {role === "admin" && <SetupChecklist />}

        <div className="inbox-chips" role="tablist" aria-label={t("inbox.filter")}>
          {chips.map((c) => (
            <button key={c.key} type="button" role="tab" aria-selected={filter === c.key}
              className={`inbox-chip${filter === c.key ? " on" : ""}`} onClick={() => setFilter(c.key)}>
              {c.label} <span>{c.n}</span>
            </button>
          ))}
        </div>

        <div className="inbox-grid">
          <div className="inbox-main">
            {show("approvals") && (
              <section className="inbox-section">
                <AgentActionApprovals readOnly={!decider} onCount={setApprovals} compact />
              </section>
            )}

            {show("incidents") && (
              <section className="panel inbox-section">
                <div className="panel-header">
                  <h2>{t("inbox.open_incidents")} ({incidentCount})</h2>
                  <Link href="/incidents" className="btn btn-sm">{t("inbox.open_all")}</Link>
                </div>
                <div className="panel-body inbox-list">
                  {loaded && incidentCount === 0 && <p className="hint-text">{t("inbox.no_incidents")}</p>}
                  {incidents.slice(0, 10).map((i) => (
                    <Link key={`p${i.id}`} href="/incidents" className="inbox-row">
                      <RiskPill level={i.severity} />
                      <span className="inbox-row-main">
                        <b>{i.summary}</b>
                        <small>{i.category} · {new Date(i.created_at).toLocaleString()}</small>
                      </span>
                    </Link>
                  ))}
                  {agentIncidents.slice(0, 10).map((i) => (
                    <Link key={`a${i.id}`} href="/incidents?tab=agents" className="inbox-row">
                      <RiskPill level={i.severity || "medium"} />
                      <span className="inbox-row-main">
                        <b>{i.incident_type
                          ? t(`agent_incidents.types.${i.incident_type}`, { defaultValue: humanize(i.incident_type) })
                          : t("inbox.agent_incident")}</b>
                        <small>
                          {i.agent_id ? `${t("inbox.agent")} #${i.agent_id} · ` : ""}{new Date(i.created_at).toLocaleString()}
                        </small>
                      </span>
                    </Link>
                  ))}
                </div>
              </section>
            )}

            {show("new_ai") && (
              <section className="panel inbox-section">
                <div className="panel-header">
                  <h2>{t("inbox.new_ai_title")} ({newAiCount})</h2>
                  <Link href="/shadow-ai" className="btn btn-sm">{t("inbox.open_all")}</Link>
                </div>
                <div className="panel-body inbox-list">
                  {loaded && newAiCount === 0 && <p className="hint-text">{t("inbox.no_new_ai")}</p>}
                  {sightings.slice(0, 10).map((s) => (
                    <div key={`s${s.id}`} className="inbox-row">
                      <span className="pill pill-medium">{t("inbox.shadow")}</span>
                      <span className="inbox-row-main">
                        <b>{s.tool_name}</b>
                        <small>
                          {[s.domain, s.seen_count ? t("inbox.seen", { count: s.seen_count }) : null,
                            s.last_seen_at ? new Date(s.last_seen_at).toLocaleDateString() : null].filter(Boolean).join(" · ")}
                        </small>
                      </span>
                      <span className="inbox-row-acts">
                        <Link href="/shadow-ai" className="btn btn-sm">{t("inbox.review")}</Link>
                        {decider && (
                          <button type="button" className="btn btn-sm" disabled={busy === s.id} onClick={() => dismiss(s)}>
                            {t("inbox.dismiss")}
                          </button>
                        )}
                      </span>
                    </div>
                  ))}
                  {found.slice(0, 10).map((f) => (
                    <div key={`f${f.id}`} className="inbox-row">
                      <span className="pill pill-accent">{t("inbox.found_agent")}</span>
                      <span className="inbox-row-main">
                        <b>{f.name}</b>
                        <small>{[f.vendor, f.device_host, f.device_user].filter(Boolean).join(" · ")}</small>
                      </span>
                      <span className="inbox-row-acts">
                        <Link href="/agents-found" className="btn btn-sm">{t("inbox.review")}</Link>
                      </span>
                    </div>
                  ))}
                </div>
              </section>
            )}
          </div>

          <aside className="inbox-side">
            <section className="panel">
              <div className="panel-header"><h2>{t("inbox.summary")}</h2></div>
              <div className="panel-body">
                {!stats && <p className="hint-text">{loaded ? "—" : t("common.loading")}</p>}
                {stats && (
                  <>
                    <dl className="inbox-stats">
                      <div><dt>{t("dashboard.stat_pending")}</dt><dd>{stats.pending_approvals}</dd></div>
                      <div><dt>{t("inbox.denied")}</dt><dd>{stats.calls_by_day.reduce((n, d) => n + (d.denied || 0), 0)}</dd></div>
                      <div><dt>{t("dashboard.stat_policies")}</dt><dd>{stats.total_policies}</dd></div>
                      <div><dt>{t("dashboard.stat_calls", "LLM calls (gateway)")}</dt><dd>{stats.total_calls}</dd></div>
                    </dl>
                    <p className="hint-text" style={{ margin: "12px 0 4px" }}>{t("dashboard.calls_trend", "LLM calls per day")} · {t("dashboard.window", { days: 7 })}</p>
                    <ResponsiveContainer width="100%" height={140}>
                      <LineChart data={stats.calls_by_day} margin={{ top: 4, right: 4, bottom: 0, left: -24 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                        <XAxis dataKey="date" fontSize={10} tickFormatter={(d: string) => d.slice(5)} />
                        <YAxis fontSize={10} allowDecimals={false} />
                        <Tooltip />
                        <Line type="monotone" dataKey="total" stroke="#3987e5" strokeWidth={2} dot={false}
                          name={t("dashboard.line_total", "Total")} />
                        <Line type="monotone" dataKey="denied" stroke="#c1352f" strokeWidth={2} dot={false}
                          name={t("dashboard.line_denied", "Denied")} />
                      </LineChart>
                    </ResponsiveContainer>
                  </>
                )}
              </div>
            </section>
            <section className="panel">
              <div className="panel-header"><h2>{t("inbox.elsewhere")}</h2></div>
              <div className="panel-body inbox-links">
                <Link href="/inventory">{t("inbox.link_ai")}</Link>
                <Link href="/audit">{t("inbox.link_audit")}</Link>
                <Link href="/compliance">{t("inbox.link_compliance")}</Link>
                <Link href="/help">{t("inbox.link_help")}</Link>
              </div>
            </section>
          </aside>
        </div>
      </div>
    </>
  );
}
