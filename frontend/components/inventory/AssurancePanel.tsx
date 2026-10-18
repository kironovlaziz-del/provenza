"use client";

import React, { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/lib/auth";
import { apiErrorMessage } from "@/lib/inventory_api";
import {
  ASSURANCE_KINDS,
  ASSURANCE_RESULTS,
  addRecord,
  listForSystem,
  type AssuranceRecord,
  type AssuranceRecordIn,
} from "@/lib/assurance_api";

const RESULT_PILL: Record<string, string> = { passed: "pill-low", passed_with_findings: "pill-medium", failed: "pill-critical" };

function today() {
  return new Date().toISOString().slice(0, 10);
}

const EMPTY: AssuranceRecordIn = { kind: "evaluation", title: "", performed_on: today(), performed_by: "", result: "passed" };

/** The tests an AI system went through, newest first, and a form to record
 *  one. Provenza does not run the tests; it keeps what an auditor asks for. */
export function AssurancePanel({ systemId }: { systemId: number }) {
  const { t, i18n } = useTranslation();
  const { user } = useAuth();
  const canRecord = user?.role === "admin" || user?.role === "approver" || user?.role === "compliance";
  const [records, setRecords] = useState<AssuranceRecord[] | null>(null);
  const [form, setForm] = useState<AssuranceRecordIn | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    listForSystem(systemId).then(setRecords).catch(() => setRecords(null));
  }, [systemId]);
  useEffect(load, [load]);

  if (records === null) return null;   // not allowed to read, or not loaded

  const set = (k: keyof AssuranceRecordIn, v: string) => setForm((f) => (f ? { ...f, [k]: v } : f));
  const fmt = (d: string | null | undefined) => (d ? new Date(d).toLocaleDateString(i18n.language) : "—");

  async function save() {
    if (!form) return;
    setBusy(true);
    setError(null);
    try {
      const clean = Object.fromEntries(Object.entries(form).map(([k, v]) => [k, v === "" ? null : v])) as unknown as AssuranceRecordIn;
      await addRecord(systemId, clean);
      setForm(null);
      load();
    } catch (e) {
      setError(apiErrorMessage(e, t("assurance.save_failed", "Could not save the record.")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel" style={{ marginBottom: 20 }}>
      <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
        <h2>{t("assurance.title", "Testing and assurance")}</h2>
        {canRecord && !form && (
          <button className="btn btn-sm btn-primary" onClick={() => setForm({ ...EMPTY, performed_on: today() })}>
            {t("assurance.add", "Record a test")}
          </button>
        )}
      </div>
      <div className="panel-body hint-text" style={{ paddingTop: 0 }}>
        {t("assurance.hint", "Evaluations, bias tests, red teaming and robustness tests of this system, with who ran them and the evidence. A test counts for a year. EU AI Act Art. 15 needs an evaluation and a red teaming or robustness test; Art. 10 a bias test.")}
      </div>

      {form && (
        <div className="panel-body" style={{ borderTop: "1px solid var(--border)" }}>
          <div className="form-row" style={{ flexWrap: "wrap" }}>
            <div className="field">
              <label>{t("assurance.kind", "Kind")}</label>
              <select value={form.kind} onChange={(e) => set("kind", e.target.value)}>
                {ASSURANCE_KINDS.map((k) => <option key={k} value={k}>{t(`assurance.kinds.${k}`, k)}</option>)}
              </select>
            </div>
            <div className="field" style={{ flex: "2 1 260px" }}>
              <label>{t("assurance.test_title", "What was tested")}</label>
              <input value={form.title} maxLength={255} onChange={(e) => set("title", e.target.value)}
                placeholder={t("assurance.title_placeholder", "Accuracy on the 2026 Q3 holdout set")} />
            </div>
            <div className="field">
              <label>{t("assurance.performed_on", "Date")}</label>
              <input type="date" value={form.performed_on} max={today()} onChange={(e) => set("performed_on", e.target.value)} />
            </div>
            <div className="field">
              <label>{t("assurance.performed_by", "By")}</label>
              <input value={form.performed_by ?? ""} maxLength={255} onChange={(e) => set("performed_by", e.target.value)}
                placeholder={t("assurance.by_placeholder", "ML team, an outside firm")} />
            </div>
            <div className="field">
              <label>{t("assurance.result", "Result")}</label>
              <select value={form.result} onChange={(e) => set("result", e.target.value)}>
                {ASSURANCE_RESULTS.map((r) => <option key={r} value={r}>{t(`assurance.results.${r}`, r)}</option>)}
              </select>
            </div>
          </div>
          <div className="field">
            <label>{t("assurance.summary", "Summary")}</label>
            <textarea rows={2} value={form.summary ?? ""} onChange={(e) => set("summary", e.target.value)} />
          </div>
          {form.result !== "passed" && (
            <div className="field">
              <label>{t("assurance.findings", "Findings and what is done about them")}</label>
              <textarea rows={2} value={form.findings ?? ""} onChange={(e) => set("findings", e.target.value)} />
            </div>
          )}
          <div className="form-row" style={{ flexWrap: "wrap" }}>
            <div className="field" style={{ flex: "2 1 260px" }}>
              <label>{t("assurance.evidence", "Report link")}</label>
              <input value={form.evidence_url ?? ""} maxLength={500} onChange={(e) => set("evidence_url", e.target.value)}
                placeholder="https://" />
            </div>
            <div className="field">
              <label>{t("assurance.next_due", "Test again by")}</label>
              <input type="date" value={form.next_due ?? ""} onChange={(e) => set("next_due", e.target.value)} />
            </div>
          </div>
          {error && <p className="error-text">{error}</p>}
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn btn-primary btn-sm" disabled={busy || !form.title.trim()} onClick={save}>
              {t("assurance.save", "Save")}
            </button>
            <button className="btn btn-sm" disabled={busy} onClick={() => { setForm(null); setError(null); }}>
              {t("common.cancel", "Cancel")}
            </button>
          </div>
          <p className="hint-text" style={{ fontSize: 12 }}>{t("assurance.append_only", "A record cannot be changed later; a correction is a new record.")}</p>
        </div>
      )}

      {records.length === 0 ? (
        <div className="panel-body hint-text">{t("assurance.empty", "No test recorded yet.")}</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>{t("assurance.performed_on", "Date")}</th>
              <th>{t("assurance.kind", "Kind")}</th>
              <th>{t("assurance.test_title", "What was tested")}</th>
              <th>{t("assurance.performed_by", "By")}</th>
              <th>{t("assurance.result", "Result")}</th>
              <th>{t("assurance.next_due", "Test again by")}</th>
            </tr>
          </thead>
          <tbody>
            {records.map((r) => (
              <tr key={r.id}>
                <td className="mono">{fmt(r.performed_on)}</td>
                <td>{t(`assurance.kinds.${r.kind}`, r.kind)}</td>
                <td>
                  {r.evidence_url ? <a href={r.evidence_url} target="_blank" rel="noopener noreferrer">{r.title}</a> : r.title}
                  {(r.summary || r.findings) && (
                    <div className="hint-text" style={{ fontSize: 12 }}>{[r.summary, r.findings].filter(Boolean).join(" · ")}</div>
                  )}
                </td>
                <td>{r.performed_by || "—"}</td>
                <td><span className={`pill ${RESULT_PILL[r.result] ?? "pill-neutral"}`}>{t(`assurance.results.${r.result}`, r.result)}</span></td>
                <td className="mono">{fmt(r.next_due)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
