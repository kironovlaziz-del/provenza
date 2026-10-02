"use client";

import React, { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import {
  getQueueOverview,
  queueError,
  saveQueueSettings,
  sweepNow,
  type QueueOverview,
  type QueueSettings,
} from "@/lib/queue_api";

const LIST: React.CSSProperties = { maxHeight: 380, overflowY: "auto", overflowX: "auto" };

function age(seconds: number | null, t: (k: string, d: string) => string): string {
  if (seconds == null) return "—";
  if (seconds < 120) return `${seconds} ${t("queue.sec", "s")}`;
  if (seconds < 7200) return `${Math.round(seconds / 60)} ${t("queue.min", "min")}`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)} ${t("queue.h", "h")}`;
  return `${Math.round(seconds / 86400)} ${t("queue.d", "d")}`;
}

export default function QueueTtlPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [data, setData] = useState<QueueOverview | null>(null);
  const [form, setForm] = useState<QueueSettings | null>(null);
  const [keepForever, setKeepForever] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    getQueueOverview()
      .then((d) => {
        setData(d);
        setForm({ ...d.settings, raw_prompt_retention_days: d.settings.raw_prompt_retention_days ?? 90 });
        setKeepForever(d.settings.raw_prompt_retention_days == null);
      })
      .catch((e) => setError(queueError(e, t("queue.load_failed", "Could not load queue settings."))));
  }, [t]);

  useEffect(load, [load]);

  async function run(action: () => Promise<unknown>, ok?: (r: any) => string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const r = await action();
      if (ok) setNotice(ok(r));
      load();
    } catch (e) {
      setError(queueError(e, t("queue.failed", "Could not save.")));
    } finally {
      setBusy(false);
    }
  }

  function save() {
    if (!form) return;
    const payload = { ...form, raw_prompt_retention_days: keepForever ? null : form.raw_prompt_retention_days };
    if (!keepForever && data?.settings.raw_prompt_retention_days == null) {
      const ok = window.confirm(
        t(
          "queue.confirm_retention",
          "Turn on retention? Encrypted raw prompts older than this will be wiped permanently at the next sweep; the masked text and the audit trail stay.",
        ),
      );
      if (!ok) return;
    }
    run(() => saveQueueSettings(payload), () => t("queue.saved", "Saved"));
  }

  const fmt = (iso: string) => new Date(iso).toLocaleString();

  if (!data || !form) {
    return (
      <>
        <PageHeader title={t("queue.title", "Queue & Retention")} />
        <div className="content"><div className="hint-text">{error ?? t("common.loading", "Loading…")}</div></div>
      </>
    );
  }

  const ttl = data.settings.queue_ttl_seconds;
  const apprTtl = data.settings.approval_ttl_hours * 3600;
  const tiles: { key: keyof QueueOverview["live"]; limit: number }[] = [
    { key: "pending", limit: ttl },
    { key: "approved", limit: ttl },
    { key: "processing", limit: ttl },
    { key: "pending_approval", limit: apprTtl },
  ];
  const badRetention = !keepForever && (!form.raw_prompt_retention_days || form.raw_prompt_retention_days < 1 || form.raw_prompt_retention_days > 3650);

  return (
    <>
      <PageHeader title={t("queue.title", "Queue & Retention")} />
      <div className="content">
        <p className="hint-text" style={{ marginTop: 0 }}>
          {t(
            "queue.hint",
            "AI requests run in a background queue. A request that waits too long is not sent late: it expires. A request delivered to the worker twice is processed once. Requests nobody approves expire, and encrypted raw prompts can be wiped after a retention period. A sweep enforces this every 5 minutes.",
          )}
        </p>
        {error && <div className="panel" style={{ marginBottom: 16, borderColor: "#ef4444" }}><div className="panel-body" style={{ color: "#ef4444" }}>{error}</div></div>}
        {notice && <div className="hint-text" style={{ marginBottom: 16 }}>{notice}</div>}

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: 12, marginBottom: 20 }}>
          {tiles.map(({ key, limit }) => {
            const row = data.live[key];
            const late = row.oldest_age_seconds != null && row.oldest_age_seconds > limit * 0.8;
            return (
              <div className="panel" key={key} style={late ? { borderColor: "#f59e0b" } : undefined}>
                <div className="panel-body">
                  <div className="hint-text" style={{ fontSize: 12 }}>{t(`queue.live_${key}`, key)}</div>
                  <div style={{ fontSize: 24, fontWeight: 600 }}>{row.count}</div>
                  <div className="hint-text" style={{ fontSize: 11 }}>
                    {t("queue.oldest", "oldest")}: {age(row.oldest_age_seconds, t)}
                  </div>
                </div>
              </div>
            );
          })}
          <div className="panel"><div className="panel-body">
            <div className="hint-text" style={{ fontSize: 12 }}>{t("queue.expired_7d", "Expired · 7 days")}</div>
            <div style={{ fontSize: 24, fontWeight: 600 }}>{data.expired_7d}</div>
          </div></div>
          <div className="panel"><div className="panel-body">
            <div className="hint-text" style={{ fontSize: 12 }}>{t("queue.raw_kept", "Raw prompts kept (encrypted)")}</div>
            <div style={{ fontSize: 24, fontWeight: 600 }}>{data.raw_prompts_kept}</div>
          </div></div>
        </div>

        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
            <h2>{t("queue.sweeps_title", "Sweeps")}</h2>
            {isAdmin && (
              <button className="btn btn-sm" disabled={busy}
                onClick={() => run(() => sweepNow(), (r) =>
                  `${t("queue.swept", "Sweep done")}: ${t("queue.col_expired_queued", "expired in queue")} ${r.expired_queued}, ${t("queue.col_expired_approvals", "expired approvals")} ${r.expired_approvals}, ${t("queue.col_failed_stuck", "worker lost")} ${r.failed_stuck}, ${t("queue.col_purged", "prompts wiped")} ${r.purged_prompts}`)}>
                {t("queue.sweep_now", "Sweep now")}
              </button>
            )}
          </div>
          <div className="panel-body" style={LIST}>
            {data.sweeps.length === 0 ? (
              <p className="hint-text" style={{ margin: 0 }}>{t("queue.sweeps_empty", "No sweep has changed anything yet.")}</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>{t("queue.col_time", "Time")}</th>
                    <th>{t("queue.col_expired_queued", "expired in queue")}</th>
                    <th>{t("queue.col_expired_approvals", "expired approvals")}</th>
                    <th>{t("queue.col_failed_stuck", "worker lost")}</th>
                    <th>{t("queue.col_purged", "prompts wiped")}</th>
                    <th>{t("queue.col_telemetry", "agent telemetry")}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.sweeps.map((s) => (
                    <tr key={s.id}>
                      <td style={{ fontSize: 12, whiteSpace: "nowrap" }}>
                        {fmt(s.ran_at)} {s.trigger === "manual" && <span className="pill pill-neutral">{t("queue.manual", "manual")}</span>}
                      </td>
                      <td>{s.expired_queued}</td>
                      <td>{s.expired_approvals}</td>
                      <td>{s.failed_stuck}</td>
                      <td>{s.purged_prompts}</td>
                      <td style={{ fontSize: 12 }}>{(s.purged_checks ?? 0) + (s.scrubbed_content ?? 0) ? `${s.purged_checks ?? 0} / ${s.scrubbed_content ?? 0}` : "0"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header"><h2>{t("queue.settings_title", "Settings")}</h2></div>
          <div className="panel-body">
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 12 }}>
              <div className="field" style={{ margin: 0 }}>
                <label htmlFor="q-ttl">{t("queue.queue_ttl", "Queue TTL, seconds")}</label>
                <input id="q-ttl" type="number" min={60} max={86400} disabled={!isAdmin} value={form.queue_ttl_seconds}
                  onChange={(e) => setForm({ ...form, queue_ttl_seconds: Number(e.target.value) })} />
                <div className="hint-text" style={{ fontSize: 12 }}>{t("queue.queue_ttl_hint", "A queued request that has not started by then expires instead of running late (60–86400)")}</div>
              </div>
              <div className="field" style={{ margin: 0 }}>
                <label htmlFor="q-appr">{t("queue.approval_ttl", "Approval deadline, hours")}</label>
                <input id="q-appr" type="number" min={1} max={720} disabled={!isAdmin} value={form.approval_ttl_hours}
                  onChange={(e) => setForm({ ...form, approval_ttl_hours: Number(e.target.value) })} />
                <div className="hint-text" style={{ fontSize: 12 }}>{t("queue.approval_ttl_hint", "A request nobody approves or rejects by then expires (1–720)")}</div>
              </div>
              <div className="field" style={{ margin: 0 }}>
                <label htmlFor="q-ret">{t("queue.retention", "Raw prompt retention, days")}</label>
                <label style={{ display: "flex", gap: 8, alignItems: "center", fontWeight: "normal", marginBottom: 6 }}>
                  <input type="checkbox" checked={keepForever} disabled={!isAdmin} onChange={(e) => setKeepForever(e.target.checked)} style={{ width: "auto" }} />
                  {t("queue.keep_forever", "Keep indefinitely")}
                </label>
                <input id="q-ret" type="number" min={1} max={3650} disabled={!isAdmin || keepForever}
                  value={form.raw_prompt_retention_days ?? ""}
                  onChange={(e) => setForm({ ...form, raw_prompt_retention_days: Number(e.target.value) })} />
                <div className="hint-text" style={{ fontSize: 12 }}>{t("queue.retention_hint", "Only the encrypted original is wiped; the masked text stays for the audit trail (1–3650)")}</div>
              </div>
              {(["agent_check_retention_days", "agent_content_retention_days"] as const).map((k) => (
                <div key={k} className="field" style={{ margin: 0 }}>
                  <label htmlFor={`q-${k}`}>
                    {k === "agent_check_retention_days"
                      ? t("queue.check_retention", "Agent policy checks, days")
                      : t("queue.content_retention", "Agent & LLM content, days")}
                  </label>
                  <label style={{ display: "flex", gap: 8, alignItems: "center", fontWeight: "normal", marginBottom: 6 }}>
                    <input type="checkbox" checked={form[k] == null} disabled={!isAdmin} style={{ width: "auto" }}
                      onChange={(e) => setForm({ ...form, [k]: e.target.checked ? null : 90 })} />
                    {t("queue.keep_forever", "Keep indefinitely")}
                  </label>
                  <input id={`q-${k}`} type="number" min={1} max={3650} disabled={!isAdmin || form[k] == null}
                    value={form[k] ?? ""} onChange={(e) => setForm({ ...form, [k]: Number(e.target.value) })} />
                  <div className="hint-text" style={{ fontSize: 12 }}>
                    {k === "agent_check_retention_days"
                      ? t("queue.check_retention_hint", "Verdicts of /actions/check older than this are deleted, except those an action or approval refers to (1–3650)")
                      : t("queue.content_retention_hint", "Arguments, outputs, prompts and answers are erased; who did what, when and the verdict stay for the audit trail and the charts (1–3650)")}
                  </div>
                </div>
              ))}
            </div>
            {isAdmin && (
              <button className="btn btn-primary btn-sm" style={{ marginTop: 12 }}
                disabled={busy || badRetention ||
                  (["agent_check_retention_days", "agent_content_retention_days"] as const).some((k) => form[k] != null && ((form[k] as number) < 1 || (form[k] as number) > 3650)) || form.queue_ttl_seconds < 60 || form.queue_ttl_seconds > 86400 || form.approval_ttl_hours < 1 || form.approval_ttl_hours > 720}
                onClick={save}>
                {t("queue.save", "Save")}
              </button>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
