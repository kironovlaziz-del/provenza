"use client";

// Retention of agent telemetry: how long policy checks and what agents sent
// and got back are kept (services/retention.py runs every 5 minutes).

import React, { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import {
  getRetention,
  retentionError,
  runRetention,
  saveRetention,
  type RetentionKey,
  type RetentionOverview,
  type RetentionSettings,
} from "@/lib/retention_api";

const KEYS: RetentionKey[] = ["agent_check_retention_days", "agent_content_retention_days"];
const valid = (v: number | null) => v == null || (Number.isInteger(v) && v >= 1 && v <= 3650);

export default function RetentionPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [data, setData] = useState<RetentionOverview | null>(null);
  const [form, setForm] = useState<RetentionSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    getRetention()
      .then((d) => {
        setData(d);
        setForm(d.settings);
      })
      .catch((e) => setError(retentionError(e, t("retention.load_failed", "Could not load the retention settings."))));
  }, [t]);

  useEffect(load, [load]);

  async function run<T>(action: () => Promise<T>, ok: (r: T) => string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      setNotice(ok(await action()));
      load();
    } catch (e) {
      setError(retentionError(e, t("retention.failed", "Could not save.")));
    } finally {
      setBusy(false);
    }
  }

  const title = t("retention.title", "Data retention");
  if (!data || !form) {
    return (
      <>
        <PageHeader title={title} />
        <div className="content"><div className="hint-text">{error ?? t("common.loading", "Loading…")}</div></div>
      </>
    );
  }

  const label = (k: RetentionKey) => k === "agent_check_retention_days"
    ? t("retention.checks", "Agent policy checks, days")
    : t("retention.content", "Agent content, days");
  const hint = (k: RetentionKey) => k === "agent_check_retention_days"
    ? t("retention.checks_hint", "Verdicts of /actions/check older than this are deleted, except those an action or approval refers to (1–3650)")
    : t("retention.content_hint", "Arguments and outputs of agent actions are erased; who did what, when and the verdict stay for the audit trail and the charts (1–3650)");

  return (
    <>
      <PageHeader title={title} />
      <div className="content">
        <p className="hint-text" style={{ marginTop: 0 }}>
          {t("retention.hint", "How long agent telemetry is kept. The LLM gateway keeps no prompt or answer at all, and the audit log is never deleted. Retention runs every 5 minutes.")}
        </p>
        {error && <div className="panel" style={{ marginBottom: 16, borderColor: "#ef4444" }}><div className="panel-body" style={{ color: "#ef4444" }}>{error}</div></div>}
        {notice && <div className="hint-text" style={{ marginBottom: 16 }}>{notice}</div>}

        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header"><h2>{t("retention.settings", "Settings")}</h2></div>
          <div className="panel-body">
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 12 }}>
              {KEYS.map((k) => (
                <div key={k} className="field" style={{ margin: 0 }}>
                  <label htmlFor={`r-${k}`}>{label(k)}</label>
                  <label style={{ display: "flex", gap: 8, alignItems: "center", fontWeight: "normal", marginBottom: 6 }}>
                    <input type="checkbox" checked={form[k] == null} disabled={!isAdmin} style={{ width: "auto" }}
                      onChange={(e) => setForm({ ...form, [k]: e.target.checked ? null : 90 })} />
                    {t("retention.keep_forever", "Keep indefinitely")}
                  </label>
                  <input id={`r-${k}`} type="number" min={1} max={3650} disabled={!isAdmin || form[k] == null}
                    value={form[k] ?? ""} onChange={(e) => setForm({ ...form, [k]: Number(e.target.value) })} />
                  <div className="hint-text" style={{ fontSize: 12 }}>{hint(k)}</div>
                </div>
              ))}
            </div>
            {isAdmin && (
              <button className="btn btn-primary btn-sm" style={{ marginTop: 12 }}
                disabled={busy || !KEYS.every((k) => valid(form[k]))}
                onClick={() => run(() => saveRetention(form), () => t("retention.saved", "Saved"))}>
                {t("retention.save", "Save")}
              </button>
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
            <h2>{t("retention.runs", "Runs")}</h2>
            {isAdmin && (
              <button className="btn btn-sm" disabled={busy}
                onClick={() => run(() => runRetention(), (r) =>
                  `${t("retention.done", "Done")}: ${t("retention.col_checks", "checks deleted")} ${r.purged_checks}, ${t("retention.col_content", "actions erased")} ${r.scrubbed_content}`)}>
                {t("retention.run_now", "Run now")}
              </button>
            )}
          </div>
          <div className="panel-body" style={{ maxHeight: 380, overflowY: "auto" }}>
            {data.runs.length === 0 ? (
              <p className="hint-text" style={{ margin: 0 }}>{t("retention.runs_empty", "No run has changed anything yet.")}</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>{t("retention.col_time", "Time")}</th>
                    <th>{t("retention.col_checks", "checks deleted")}</th>
                    <th>{t("retention.col_content", "actions erased")}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.runs.map((r) => (
                    <tr key={r.id}>
                      <td style={{ fontSize: 12, whiteSpace: "nowrap" }}>
                        {new Date(r.ran_at).toLocaleString()}{" "}
                        {r.trigger === "manual" && <span className="pill pill-neutral">{t("retention.manual", "manual")}</span>}
                      </td>
                      <td>{r.purged_checks}</td>
                      <td>{r.scrubbed_content}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
