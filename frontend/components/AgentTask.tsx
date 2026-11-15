"use client";

// The task a person gave the agent, signed (docs/proof-of-authority.md):
// what it is to do, which of its tools it may use for it and until when.
// The agent names the task on its calls; Provenza refuses a call outside it,
// and the action's Proof of Authority starts with the person who gave it.

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { confirmDialog } from "@/components/Dialog";
import { useAuth } from "@/lib/auth";
import { translateApiError } from "@/lib/errors";
import { endMandate, giveMandate, listMandates, type MandateT } from "@/lib/mandates_api";
import { splitNames } from "@/lib/tool_names";

const HOURS = [1, 8, 24, 72, 168];

export function AgentTask({ agentId, active }: { agentId: number; active: boolean }) {
  const { t, i18n } = useTranslation();
  const { user } = useAuth();
  const canGive = user?.role === "admin" || user?.role === "approver";
  const [current, setCurrent] = useState<MandateT | null>(null);
  const [history, setHistory] = useState<MandateT[]>([]);
  const [draft, setDraft] = useState<{ task: string; tools: string; hours: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [n, setN] = useState(0);

  useEffect(() => {
    listMandates(agentId).then((d) => { setCurrent(d.current); setHistory(d.history); }).catch(() => undefined);
  }, [agentId, n]);

  const fmt = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString(i18n.language) : "—");
  const fail = (err: unknown, fallback: string) => {
    const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
    setError(translateApiError(detail, t, fallback));
  };

  async function give() {
    if (!draft) return;
    const tools = splitNames(draft.tools);
    setBusy(true);
    setError(null);
    try {
      await giveMandate(agentId, draft.task.trim(), tools.length ? tools : null, draft.hours);
      setDraft(null);
      setN((x) => x + 1);
    } catch (err) {
      fail(err, t("task.give_failed"));
    } finally {
      setBusy(false);
    }
  }

  async function end(m: MandateT) {
    if (!await confirmDialog(t("task.confirm_end"))) return;
    setError(null);
    try {
      await endMandate(agentId, m.id);
      setN((x) => x + 1);
    } catch (err) {
      fail(err, t("task.end_failed"));
    }
  }

  const earlier = history.filter((m) => m.id !== current?.id).slice(0, 5);

  return (
    <section className="panel">
      <div className="panel-header"><h2>{t("task.title")}</h2></div>
      <div className="panel-body ag-stack">
        <p className="hint-text ag-small">{t("task.hint")}</p>
        {current ? (
          <div>
            <div className="ag-label">{t("task.current")} #{current.id}</div>
            <p style={{ margin: "4px 0", whiteSpace: "pre-wrap" }}>{current.task}</p>
            <div className="hint-text ag-small">
              {t("task.tools")}: {current.tools ? current.tools.join(", ") : t("task.all_tools")} ·{" "}
              {t("task.until")} {fmt(current.expires_at)}
            </div>
            {canGive && (
              <button type="button" className="btn btn-sm" style={{ marginTop: 8 }} onClick={() => end(current)}>
                {t("task.end")}
              </button>
            )}
          </div>
        ) : (
          <p className="ag-small">{t("task.none")}</p>
        )}

        {canGive && active && draft === null && (
          <div>
            <button type="button" className="btn btn-sm btn-primary"
              onClick={() => setDraft({ task: "", tools: "", hours: 8 })}>
              {current ? t("task.replace") : t("task.give")}
            </button>
          </div>
        )}
        {draft !== null && (
          <div className="ag-stack" style={{ gap: 8 }}>
            <label className="ag-label" htmlFor="task-text">{t("task.what")}</label>
            <textarea id="task-text" rows={3} maxLength={2000} value={draft.task} autoFocus
              placeholder={t("task.what_placeholder") as string}
              onChange={(e) => setDraft({ ...draft, task: e.target.value })} />
            <label className="ag-label" htmlFor="task-tools">{t("task.tools")}</label>
            <input id="task-tools" value={draft.tools} placeholder={t("task.tools_placeholder") as string}
              onChange={(e) => setDraft({ ...draft, tools: e.target.value })} />
            <label className="ag-label" htmlFor="task-hours">{t("task.valid_for")}</label>
            <select id="task-hours" value={draft.hours}
              onChange={(e) => setDraft({ ...draft, hours: Number(e.target.value) })}>
              {HOURS.map((h) => <option key={h} value={h}>{t("task.hours", { count: h })}</option>)}
            </select>
            <p className="hint-text ag-small">{t("task.sign_note")}</p>
            <div style={{ display: "flex", gap: 8 }}>
              <button type="button" className="btn btn-sm btn-primary" disabled={busy || !draft.task.trim()} onClick={give}>
                {t("task.sign_and_give")}
              </button>
              <button type="button" className="btn btn-sm" disabled={busy} onClick={() => setDraft(null)}>
                {t("common.cancel")}
              </button>
            </div>
          </div>
        )}
        {error && <p className="error-text">{error}</p>}

        {earlier.length > 0 && (
          <details>
            <summary className="ag-small">{t("task.earlier")}</summary>
            <ul className="ag-small" style={{ margin: "6px 0 0", paddingLeft: 18 }}>
              {earlier.map((m) => (
                <li key={m.id}>
                  #{m.id} · {t(`task.status_${m.status}`)} · {fmt(m.created_at)} — {m.task.slice(0, 120)}
                </li>
              ))}
            </ul>
          </details>
        )}
      </div>
    </section>
  );
}
