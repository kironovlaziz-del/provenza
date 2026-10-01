"use client";

import React, { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/Pill";
import { useAuth } from "@/lib/auth";
import {
  behaviorError,
  getBehaviorOverview,
  refreshBaseline,
  releaseAgent,
  saveBehaviorSettings,
  type BehaviorMode,
  type BehaviorOverview,
  type BehaviorSettings,
} from "@/lib/behavior_api";

const MODES: BehaviorMode[] = ["off", "monitor", "enforce"];

export default function AgentBehaviorPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [data, setData] = useState<BehaviorOverview | null>(null);
  const [form, setForm] = useState<BehaviorSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    getBehaviorOverview()
      .then((d) => {
        setData(d);
        setForm({ ...d.settings });
      })
      .catch((e) => setError(behaviorError(e, t("behavior.load_failed", "Could not load the behaviour monitor."))));
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
      setError(behaviorError(e, t("behavior.failed", "Could not save.")));
    } finally {
      setBusy(false);
    }
  }

  function save() {
    if (!form || !data) return;
    if (form.mode === "enforce" && data.settings.mode !== "enforce") {
      const ok = window.confirm(
        t(
          "behavior.confirm_enforce",
          "Switch to enforce? Agents whose score reaches the threshold will be quarantined automatically and every action they attempt will be refused until an admin releases them.",
        ),
      );
      if (!ok) return;
    }
    run(() => saveBehaviorSettings(form), t("behavior.saved", "Saved"));
  }

  if (!data || !form) {
    return (
      <>
        <PageHeader title={t("behavior.title", "Behavior Monitor")} />
        <div className="content"><div className="hint-text">{error ?? t("common.loading", "Loading…")}</div></div>
      </>
    );
  }

  const quarantined = data.agents.filter((a) => a.status === "quarantined");
  const b = data.bounds;
  const fmt = (iso: string) => new Date(iso).toLocaleString();
  const outOfBounds =
    form.threshold < b.threshold[0] || form.threshold > b.threshold[1] ||
    form.min_samples < b.min_samples[0] || form.min_samples > b.min_samples[1] ||
    form.baseline_days < b.baseline_days[0] || form.baseline_days > b.baseline_days[1];

  return (
    <>
      <PageHeader title={t("behavior.title", "Behavior Monitor")} />
      <div className="content">
        <p className="hint-text" style={{ marginTop: 0 }}>
          {t(
            "behavior.hint",
            "Each agent is compared with its own recent behaviour: new tools, bursts of activity, runs of denials, unusual hours (OWASP ASI10). In enforce mode a strongly deviating agent is quarantined until an admin releases it.",
          )}
        </p>
        {error && <div className="panel" style={{ marginBottom: 16, borderColor: "#ef4444" }}><div className="panel-body" style={{ color: "#ef4444" }}>{error}</div></div>}
        {notice && <div className="hint-text" style={{ marginBottom: 16 }}>{notice}</div>}

        {/* ---- quarantine ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header"><h2>🔒 {t("behavior.quarantine_title", "Quarantined agents")} ({quarantined.length})</h2></div>
          <div className="panel-body">
            {quarantined.length === 0 ? (
              <p className="hint-text" style={{ margin: 0 }}>{t("behavior.quarantine_empty", "No agent is quarantined.")}</p>
            ) : (
              quarantined.map((a) => (
                <div key={a.agent_id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0" }}>
                  <strong>{a.name}</strong>
                  {isAdmin && (
                    <button
                      className="btn btn-sm btn-primary"
                      disabled={busy}
                      onClick={() => {
                        if (window.confirm(t("behavior.confirm_release", "Release this agent? Its actions will be evaluated normally again.")))
                          run(() => releaseAgent(a.agent_id), t("behavior.released", "Agent released"));
                      }}
                    >
                      {t("behavior.release", "Release")}
                    </button>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* ---- anomalies ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header"><h2>{t("behavior.anomalies_title", "Recent anomalies")}</h2></div>
          <div className="panel-body" style={{ overflowX: "auto" }}>
            {data.anomalies.length === 0 ? (
              <p className="hint-text" style={{ margin: 0 }}>{t("behavior.anomalies_empty", "No deviations detected.")}</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>{t("behavior.col_time", "Time")}</th>
                    <th>{t("behavior.col_agent", "Agent")}</th>
                    <th>{t("behavior.col_signals", "Signals")}</th>
                    <th>{t("behavior.col_score", "Score")}</th>
                    <th>{t("behavior.col_outcome", "Outcome")}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.anomalies.map((x) => (
                    <tr key={x.id}>
                      <td style={{ fontSize: 12 }}>{fmt(x.detected_at)}</td>
                      <td>{x.agent_name}{x.tool_name ? <span className="hint-text mono" style={{ fontSize: 11 }}> · {x.tool_name}</span> : null}</td>
                      <td style={{ fontSize: 12 }}>
                        {Object.keys(x.signals).map((s) => (
                          <div key={s}>{t(`behavior.signal_${s}`, s)}</div>
                        ))}
                      </td>
                      <td><strong>{x.score}</strong><span className="hint-text"> / {data.settings.threshold}</span></td>
                      <td>
                        <span className={`pill ${x.outcome === "quarantined" ? "pill-critical" : "pill-medium"}`}>
                          {t(`behavior.outcome_${x.outcome}`, x.outcome)}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* ---- settings ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header"><h2>{t("behavior.settings_title", "Settings")}</h2></div>
          <div className="panel-body">
            <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 14 }}>
              {MODES.map((m) => (
                <label key={m} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                  <input
                    type="radio"
                    name="bh-mode"
                    checked={form.mode === m}
                    disabled={!isAdmin}
                    onChange={() => setForm({ ...form, mode: m })}
                    style={{ width: "auto", marginTop: 3 }}
                  />
                  <span>
                    <strong>{t(`behavior.mode_${m}`, m)}</strong>
                    <span className="hint-text" style={{ display: "block", fontSize: 12 }}>{t(`behavior.mode_${m}_hint`, "")}</span>
                  </span>
                </label>
              ))}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12 }}>
              {(["threshold", "min_samples", "baseline_days"] as const).map((f) => (
                <div className="field" key={f} style={{ margin: 0 }}>
                  <label htmlFor={`bh-${f}`}>{t(`behavior.field_${f}`, f)}</label>
                  <input
                    id={`bh-${f}`}
                    type="number"
                    min={b[f][0]}
                    max={b[f][1]}
                    disabled={!isAdmin}
                    value={form[f]}
                    onChange={(e) => setForm({ ...form, [f]: Number(e.target.value) })}
                  />
                  <div className="hint-text" style={{ fontSize: 12 }}>
                    {t(`behavior.help_${f}`, "")} ({b[f][0]}–{b[f][1]})
                  </div>
                </div>
              ))}
            </div>
            <div className="hint-text" style={{ fontSize: 12, marginTop: 10 }}>
              {t("behavior.weights", "Signal weights")}:{" "}
              {Object.entries(data.weights).map(([k, v]) => `${t(`behavior.signal_${k}`, k)} ${v}`).join(" · ")}
            </div>
            {isAdmin && (
              <button className="btn btn-primary btn-sm" style={{ marginTop: 12 }} disabled={busy || outOfBounds} onClick={save}>
                {t("behavior.save", "Save")}
              </button>
            )}
          </div>
        </div>

        {/* ---- baselines ---- */}
        <div className="panel">
          <div className="panel-header"><h2>{t("behavior.baselines_title", "Agent baselines")}</h2></div>
          <div className="panel-body" style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>{t("behavior.col_agent", "Agent")}</th>
                  <th>{t("behavior.col_status", "Status")}</th>
                  <th>{t("behavior.col_baseline", "Baseline")}</th>
                  <th>{t("behavior.col_tools", "Usual tools")}</th>
                  {isAdmin && <th />}
                </tr>
              </thead>
              <tbody>
                {data.agents.map((a) => (
                  <tr key={a.agent_id}>
                    <td>{a.name}</td>
                    <td><StatusPill status={a.status} /></td>
                    <td style={{ fontSize: 12 }}>
                      {!a.baseline ? (
                        <span className="hint-text">{t("behavior.no_baseline", "not computed yet")}</span>
                      ) : (
                        <>
                          <div>
                            {a.baseline.mature
                              ? t("behavior.mature", "mature")
                              : t("behavior.learning", "learning")}{" "}
                            · {a.baseline.samples} {t("behavior.samples", "samples")} · {a.baseline.span_days} {t("behavior.days", "days")}
                          </div>
                          <div className="hint-text">
                            p95 {a.baseline.p95_per_5min}/5min · {t("behavior.denials", "denials")} {Math.round(a.baseline.denial_rate * 1000) / 10}%
                          </div>
                        </>
                      )}
                    </td>
                    <td className="mono" style={{ fontSize: 11 }}>{a.baseline?.top_tools.join(", ") || "—"}</td>
                    {isAdmin && (
                      <td>
                        <button className="btn btn-sm" disabled={busy} onClick={() => run(() => refreshBaseline(a.agent_id), t("behavior.saved", "Saved"))}>
                          {t("behavior.refresh", "Recompute")}
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
}
