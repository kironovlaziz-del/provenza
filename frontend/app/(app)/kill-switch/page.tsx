"use client";

// Kill switch: stop an agent, a team, every agent or all of the
// organization's AI traffic - with a reason and a confirmation - see what
// is stopped now, and lift a stop, which gives back exactly what it stopped.

import React, { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import { translateApiError } from "@/lib/errors";
import { listAgents } from "@/lib/agent_api";
import type { Agent } from "@/lib/agent_types";
import { listTeams, type TeamT } from "@/lib/teams_api";
import {
  KILL_SCOPES, ORG_WIDE, killEvents, killOverview, liftStop, stopScope,
  type KillEventT, type KillOverviewT, type KillScope, type StoppedAgent,
} from "@/lib/kill_switch_api";

const CONFIRM_WORD = "STOP";

function apiError(err: unknown, t: ReturnType<typeof useTranslation>["t"], fallback: string) {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  const msg = Array.isArray(detail) && detail[0]?.msg ? String(detail[0].msg).replace(/^Value error, /, "") : null;
  return msg ?? translateApiError(detail, t, fallback);
}

function names(list: StoppedAgent[], max = 8) {
  const shown = list.slice(0, max).map((a) => a.name ?? `#${a.id}`).join(", ");
  return list.length > max ? `${shown} +${list.length - max}` : shown;
}

export default function KillSwitchPage() {
  const { t, i18n } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [overview, setOverview] = useState<KillOverviewT | null>(null);
  const [events, setEvents] = useState<KillEventT[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [teams, setTeams] = useState<TeamT[]>([]);
  const [scope, setScope] = useState<KillScope | null>(null);
  const [targetId, setTargetId] = useState<string>("");
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const [chains, setChains] = useState(true);
  const [liftFor, setLiftFor] = useState<number | null>(null);
  const [liftReason, setLiftReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(() => {
    Promise.all([killOverview(), killEvents(100)])
      .then(([o, e]) => { setOverview(o); setEvents(e); })
      .catch((err) => setError(apiError(err, t, t("ks.load_failed"))));
  }, [t]);
  useEffect(load, [load]);
  useEffect(() => {
    if (!isAdmin) return;
    listAgents(500).then(setAgents).catch(() => setAgents([]));
    listTeams().then(setTeams).catch(() => setTeams([]));
  }, [isAdmin]);

  const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString(i18n.language) : "—");
  const orgWide = scope !== null && ORG_WIDE.includes(scope);
  const liveAgents = useMemo(() => agents.filter((a) => a.status !== "retired"), [agents]);
  const target = (e: KillEventT) =>
    e.scope === "agent" ? (e.agent_id ? <Link href={`/agents/${e.agent_id}`}>{e.target_name}</Link> : e.target_name)
      : e.scope === "team" ? <>{e.target_name}{e.team_ids.length > 1 ? ` (+${e.team_ids.length - 1} ${t("ks.sub_teams")})` : ""}</>
        : t(`ks.scope.${e.scope}`);

  const canStop = scope !== null && reason.trim().length >= 3
    && (orgWide ? typed.trim().toUpperCase() === CONFIRM_WORD : targetId !== "")
    && !busy;

  function pick(s: KillScope) {
    setScope(scope === s ? null : s);
    setTargetId("");
    setTyped("");
    setError(null);
  }

  async function stop(e: React.FormEvent) {
    e.preventDefault();
    if (!scope || !canStop) return;
    if (!orgWide) {
      const name = scope === "agent" ? agents.find((a) => String(a.id) === targetId)?.name
        : teams.find((x) => String(x.id) === targetId)?.name;
      if (!window.confirm(t(`ks.confirm_${scope}`, { name }))) return;
    }
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const ev = await stopScope({
        scope, target_id: orgWide ? null : Number(targetId), reason: reason.trim(),
        confirm: orgWide ? scope : undefined, terminate_chains: chains,
      });
      setNotice(t("ks.stopped_notice", { agents: ev.agents.length, chains: ev.chains.length }));
      setScope(null);
      setReason("");
      setTyped("");
      setTargetId("");
      load();
      listAgents(500).then(setAgents).catch(() => undefined);
    } catch (err) {
      setError(apiError(err, t, t("ks.failed")));
    } finally {
      setBusy(false);
    }
  }

  async function lift(ev: KillEventT) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const out = await liftStop(ev.id, liftReason.trim());
      const r = out.lift_result;
      setNotice(t("ks.lifted_notice", {
        restored: r?.restored.length ?? 0, kept: r?.kept.length ?? 0, skipped: r?.skipped.length ?? 0,
      }));
      setLiftFor(null);
      setLiftReason("");
      load();
      if (isAdmin) listAgents(500).then(setAgents).catch(() => undefined);
    } catch (err) {
      setError(apiError(err, t, t("ks.failed")));
    } finally {
      setBusy(false);
    }
  }

  const counts = overview?.agents ?? {};
  const active = overview?.active ?? [];
  const stoppedState = overview?.traffic_stopped ? "traffic" : overview?.all_agents_stopped ? "agents"
    : active.length ? "some" : "none";

  return (
    <>
      <PageHeader title={t("ks.title")} />
      <div className="content agent-page">
        <p className="hint-text u-mb-16">{t("ks.intro")}</p>

        {overview && (
          <div className={`ks-state${stoppedState === "none" ? "" : " ks-stopped"}`} role="status">
            <strong>{t(`ks.state.${stoppedState}`, { count: active.length })}</strong>
            <div className="ks-counts">
              {(["active", "suspended", "quarantined", "retired"] as const).map((s) => (
                <span key={s} className={`pill ${s === "active" ? "pill-low" : s === "retired" ? "pill-neutral" : "pill-medium"}`}>
                  {t(`ks.agents_${s}`, { count: counts[s] ?? 0 })}
                </span>
              ))}
            </div>
          </div>
        )}
        {error && <p className="error-text u-mb-16">{error}</p>}
        {notice && <p className="hint-text u-mb-16">{notice}</p>}

        {/* ---------------- active stops ---------------- */}
        <section className="panel ag-section">
          <div className="panel-header"><h2>{t("ks.active")}</h2></div>
          <div className="panel-body">
            {active.length === 0 && <p className="hint-text ag-small">{t("ks.no_active")}</p>}
            {active.map((ev) => (
              <div key={ev.id} className="ks-event">
                <div className="ks-event-head">
                  <span className="pill pill-critical">{t(`ks.scope.${ev.scope}`)}</span>
                  {(ev.scope === "agent" || ev.scope === "team") && <strong>{target(ev)}</strong>}
                  <span className="hint-text ag-small">#{ev.id} · {fmt(ev.created_at)} · {ev.created_by_email ?? "—"}</span>
                  {isAdmin && liftFor !== ev.id && (
                    <div className="ag-row-actions">
                      <button className="btn btn-sm" disabled={busy} onClick={() => { setLiftFor(ev.id); setLiftReason(""); }}>{t("ks.lift")}</button>
                    </div>
                  )}
                </div>
                <div className="ag-small"><span className="ag-reason">{ev.reason}</span></div>
                <div className="ks-names hint-text">
                  {t("ks.held", { agents: ev.agents.length, chains: ev.chains.length })}
                  {ev.agents.length > 0 && <>: {names(ev.agents)}</>}
                </div>
                {ev.scope === "org_traffic" && <div className="ks-names hint-text">{t("ks.traffic_note")}</div>}
                {liftFor === ev.id && (
                  <div className="ag-stack" style={{ gap: 8 }}>
                    <p className="hint-text ag-small">{t("ks.lift_explain", { count: ev.agents.length })}</p>
                    <div className="field" style={{ margin: 0 }}>
                      <label htmlFor={`lift-${ev.id}`}>{t("ks.lift_reason")}</label>
                      <input id={`lift-${ev.id}`} maxLength={2000} value={liftReason} placeholder={t("ks.lift_reason_ph")}
                        onChange={(e) => setLiftReason(e.target.value)} />
                    </div>
                    <div className="ag-actions">
                      <button className="btn btn-sm btn-primary" disabled={busy} onClick={() => lift(ev)}>{t("ks.lift_confirm")}</button>
                      <button className="btn btn-sm" onClick={() => setLiftFor(null)}>{t("ks.cancel")}</button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>

        {/* ---------------- stop ---------------- */}
        {isAdmin && (
          <section className="panel ag-section">
            <div className="panel-header"><h2>{t("ks.stop_title")}</h2></div>
            <div className="panel-body">
              <div className="ks-levels" role="radiogroup" aria-label={t("ks.stop_title")}>
                {KILL_SCOPES.map((s, i) => (
                  <button key={s} type="button" role="radio" aria-checked={scope === s}
                    className={`ks-level${scope === s ? " active" : ""}`} onClick={() => pick(s)}>
                    <span className="ks-step">{t("ks.level", { n: i + 1 })}</span>
                    <strong>{t(`ks.scope.${s}`)}</strong>
                    <span className="ks-what">{t(`ks.what.${s}`)}</span>
                  </button>
                ))}
              </div>

              {scope && (
                <form onSubmit={stop} className="ag-stack" style={{ marginTop: 16 }}>
                  {scope === "agent" && (
                    <div className="field" style={{ margin: 0 }}>
                      <label htmlFor="ks-agent">{t("ks.agent")}</label>
                      <select id="ks-agent" value={targetId} onChange={(e) => setTargetId(e.target.value)} required>
                        <option value="">{t("ks.choose_agent")}</option>
                        {liveAgents.map((a) => (
                          <option key={a.id} value={a.id}>{a.name}{a.status !== "active" ? ` (${a.status})` : ""}</option>
                        ))}
                      </select>
                    </div>
                  )}
                  {scope === "team" && (
                    <div className="field" style={{ margin: 0 }}>
                      <label htmlFor="ks-team">{t("ks.team")}</label>
                      <select id="ks-team" value={targetId} onChange={(e) => setTargetId(e.target.value)} required>
                        <option value="">{t("ks.choose_team")}</option>
                        {teams.map((x) => <option key={x.id} value={x.id}>{x.name} · {t("ks.team_agents", { count: x.agents })}</option>)}
                      </select>
                      <p className="hint-text">{t("ks.team_hint")}</p>
                    </div>
                  )}
                  <div className="field" style={{ margin: 0 }}>
                    <label htmlFor="ks-reason">{t("ks.reason")}</label>
                    <textarea id="ks-reason" rows={2} maxLength={2000} required value={reason}
                      placeholder={t("ks.reason_ph")} onChange={(e) => setReason(e.target.value)} />
                  </div>
                  <label style={{ display: "flex", gap: 8, alignItems: "flex-start", fontWeight: 400 }}>
                    <input type="checkbox" style={{ width: "auto", marginTop: 3 }} checked={chains}
                      onChange={(e) => setChains(e.target.checked)} />
                    <span>{t("ks.terminate_chains")}<span className="hint-text" style={{ display: "block", fontSize: 12 }}>{t("ks.terminate_chains_hint")}</span></span>
                  </label>
                  {orgWide && (
                    <div className="ag-revoked">
                      <p style={{ margin: "0 0 8px" }}>{t(`ks.warn.${scope}`)}</p>
                      <div className="field" style={{ margin: 0 }}>
                        <label htmlFor="ks-typed">{t("ks.type_to_confirm", { word: CONFIRM_WORD })}</label>
                        <input id="ks-typed" className="mono" autoComplete="off" value={typed}
                          onChange={(e) => setTyped(e.target.value)} />
                      </div>
                    </div>
                  )}
                  <div className="ag-actions">
                    <button className="btn btn-danger" type="submit" disabled={!canStop}>{t(`ks.do.${scope}`)}</button>
                    <button className="btn" type="button" onClick={() => setScope(null)}>{t("ks.cancel")}</button>
                  </div>
                </form>
              )}
            </div>
          </section>
        )}

        {/* ---------------- history ---------------- */}
        <section className="panel ag-section">
          <div className="panel-header"><h2>{t("ks.history")}</h2></div>
          <div className="ag-table-wrap">
            <table className="table-cards">
              <thead>
                <tr>
                  <th>{t("ks.when")}</th>
                  <th>{t("ks.what_col")}</th>
                  <th>{t("ks.reason")}</th>
                  <th>{t("ks.stopped_col")}</th>
                  <th>{t("ks.undo_col")}</th>
                </tr>
              </thead>
              <tbody>
                {events.length === 0 && (
                  <tr className="empty-row"><td colSpan={5} className="hint-text" style={{ padding: 20 }}>{t("ks.no_history")}</td></tr>
                )}
                {events.map((ev) => {
                  const r = ev.lift_result;
                  return (
                    <tr key={ev.id}>
                      <td data-label={t("ks.when")} className="ag-period">
                        {fmt(ev.created_at)}
                        <div className="hint-text" style={{ fontSize: 11 }}>{ev.created_by_email ?? "—"}</div>
                      </td>
                      <td data-label={t("ks.what_col")}>
                        <span className={`pill ${ev.active ? "pill-critical" : "pill-neutral"}`}>{t(`ks.scope.${ev.scope}`)}</span>
                        {(ev.scope === "agent" || ev.scope === "team") && <div style={{ marginTop: 4 }}>{target(ev)}</div>}
                      </td>
                      <td data-label={t("ks.reason")} className="ks-names"><span className="ag-reason">{ev.reason}</span></td>
                      <td data-label={t("ks.stopped_col")} className="ks-names">
                        {t("ks.held", { agents: ev.agents.length, chains: ev.chains.length })}
                        {ev.agents.length > 0 && (
                          <details className="ag-details"><summary>{t("ks.show_agents")}</summary>{names(ev.agents, 50)}</details>
                        )}
                      </td>
                      <td data-label={t("ks.undo_col")} className="ks-names">
                        {ev.active ? <span className="pill pill-critical">{t("ks.in_force")}</span> : (
                          <>
                            <div>{t("ks.lifted_by", { when: fmt(ev.lifted_at), who: ev.lifted_by_email ?? "—" })}</div>
                            {ev.lift_reason && <div className="ag-reason">{ev.lift_reason}</div>}
                            {r && (
                              <div className="hint-text">
                                {t("ks.result", { restored: r.restored.length, kept: r.kept.length, skipped: r.skipped.length })}
                                {(r.kept.length > 0 || r.skipped.length > 0) && (
                                  <details className="ag-details">
                                    <summary>{t("ks.details")}</summary>
                                    {r.kept.map((a) => <div key={`k${a.id}`}>{a.name ?? `#${a.id}`}: {t("ks.kept_by", { id: a.event_id })}</div>)}
                                    {r.skipped.map((a) => (
                                      <div key={`s${a.id}`}>{a.name ?? `#${a.id}`}: {a.why ? t(`errors.${a.why}`, a.why) : t("ks.skipped_status", { status: a.status })}</div>
                                    ))}
                                  </details>
                                )}
                              </div>
                            )}
                          </>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </>
  );
}
