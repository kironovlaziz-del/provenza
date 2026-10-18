"use client";

import Link from "next/link";
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import { apiErrorMessage, getSystem } from "@/lib/inventory_api";
import type { AISystemT } from "@/lib/inventory_types";
import {
  approveDraft,
  getForSystem,
  getTemplate,
  isFilled,
  isRequired,
  saveDraft,
  type Answers,
  type Question,
  type SystemAssessments,
  type Template,
} from "@/lib/impact_api";

// One questionnaire per AI system: the ISO/IEC 42005 impact assessment, the
// GDPR DPIA and the EU AI Act FRIA at once. A draft is edited; approving it
// freezes that version, and the next change starts a new one.
export default function ImpactAssessmentPage() {
  const params = useParams();
  const id = Number(params?.id);
  const { t, i18n } = useTranslation();
  const { user } = useAuth();
  const canEdit = user?.role === "admin" || user?.role === "compliance";

  const [system, setSystem] = useState<AISystemT | null>(null);
  const [tpl, setTpl] = useState<Template | null>(null);
  const [data, setData] = useState<SystemAssessments | null>(null);
  const [answers, setAnswers] = useState<Answers>({});
  const [editing, setEditing] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [showMissing, setShowMissing] = useState(false);

  const load = useCallback(async () => {
    const [s, tp, d] = await Promise.all([getSystem(id), getTemplate(), getForSystem(id)]);
    setSystem(s);
    setTpl(tp);
    setData(d);
    if (d.draft) {
      setAnswers(d.draft.answers);
      setEditing(canEdit);
    } else if (d.approved) {
      setAnswers(d.approved.answers);
      setEditing(false);
    } else {
      setAnswers({});
      setEditing(canEdit);
    }
    setDirty(false);
  }, [id, canEdit]);

  useEffect(() => {
    if (!Number.isFinite(id)) return;
    load().catch((e) => setError(apiErrorMessage(e, t("ia.load_failed", "Could not load the assessment."))));
  }, [id, load, t]);

  // a follow-up question (required_if) shows only when its condition holds or it has an answer
  const visible = (q: Question) => !q.required_if || isRequired(q, answers) || isFilled(answers[q.id]);

  const missing = useMemo(() => {
    if (!tpl) return [];
    return tpl.sections.flatMap((s) => s.questions)
      .filter((q) => isRequired(q, answers) && !isFilled(answers[q.id]))
      .map((q) => q.id);
  }, [tpl, answers]);
  const required = useMemo(
    () => (tpl ? tpl.sections.flatMap((s) => s.questions).filter((q) => isRequired(q, answers)).length : 0),
    [tpl, answers],
  );

  function set(qid: string, v: string | string[]) {
    setAnswers((cur) => ({ ...cur, [qid]: v }));
    setDirty(true);
    setNotice(null);
  }

  async function onSave() {
    setBusy(true);
    setError(null);
    try {
      await saveDraft(id, answers);
      await load();
      setNotice(t("ia.saved", "Draft saved."));
    } catch (e) {
      setError(apiErrorMessage(e, t("ia.save_failed", "Could not save the draft.")));
    } finally {
      setBusy(false);
    }
  }

  async function onApprove() {
    if (missing.length) {
      setShowMissing(true);
      setError(t("ia.incomplete", "Answer the highlighted questions first."));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      if (dirty || !data?.draft) await saveDraft(id, answers);
      await approveDraft(id);
      await load();
      setShowMissing(false);
      setNotice(t("ia.approved_notice", "Approved. This version is now the system's impact assessment."));
    } catch (e) {
      setError(apiErrorMessage(e, t("ia.approve_failed", "Could not approve.")));
    } finally {
      setBusy(false);
    }
  }

  const fmt = (s: string | null | undefined) => (s ? new Date(s).toLocaleDateString(i18n.language) : "—");
  const opt = (q: Question, o: string) => t(`ia.o.${q.id}.${o}`, o.replace(/_/g, " "));

  function control(q: Question) {
    const v = answers[q.id];
    const ro = !editing;
    if (q.type === "text") {
      return (
        <textarea rows={3} value={(v as string) ?? ""} readOnly={ro} disabled={ro}
          onChange={(e) => set(q.id, e.target.value)} style={{ width: "100%" }} />
      );
    }
    if (q.type === "date") {
      return <input type="date" value={(v as string) ?? ""} disabled={ro} onChange={(e) => set(q.id, e.target.value)} style={{ maxWidth: 200 }} />;
    }
    const multi = q.type === "multi";
    const chosen = multi ? ((v as string[]) ?? []) : [v as string];
    return (
      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px 16px" }}>
        {q.options.map((o) => (
          <label key={o} style={{ display: "flex", gap: 6, alignItems: "center", cursor: ro ? "default" : "pointer" }}>
            <input type={multi ? "checkbox" : "radio"} name={q.id} disabled={ro} checked={chosen.includes(o)}
              style={{ width: "auto" }}
              onChange={(e) => {
                if (!multi) return set(q.id, o);
                const cur = (v as string[]) ?? [];
                set(q.id, e.target.checked ? [...cur, o] : cur.filter((x) => x !== o));
              }} />
            {opt(q, o)}
          </label>
        ))}
      </div>
    );
  }

  if (!system || !tpl || !data) {
    return (
      <>
        <PageHeader title={t("ia.title", "Impact assessment")} />
        <div className="content">{error ? <p className="error-text">{error}</p> : <div className="loading-line">…</div>}</div>
      </>
    );
  }

  const a = data.approved;
  const dueSoon = a?.review_due ? new Date(a.review_due).getTime() < Date.now() : false;

  return (
    <>
      <PageHeader title={`${t("ia.title", "Impact assessment")} · ${system.name}`} />
      <div className="content">
        <Link href={`/inventory/${id}`} className="btn btn-sm" style={{ marginBottom: 16 }}>
          ← {t("ia.back", "Back to the system")}
        </Link>

        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-body" style={{ display: "flex", gap: 28, flexWrap: "wrap", alignItems: "center" }}>
            <div>
              <div className="hint-text">{t("ia.status", "Status")}</div>
              {a ? (
                <span className={`pill ${dueSoon ? "pill-medium" : "pill-low"}`}>
                  {t("ia.approved_v", "Approved")} v{a.version}
                </span>
              ) : (
                <span className="pill pill-neutral">{t("ia.not_approved", "Not approved yet")}</span>
              )}
              {data.draft && <span className="pill pill-neutral" style={{ marginLeft: 6 }}>{t("ia.draft_v", "Draft")} v{data.draft.version}</span>}
            </div>
            {a && (
              <>
                <div><div className="hint-text">{t("ia.approved_on", "Approved on")}</div><strong>{fmt(a.approved_at)}</strong></div>
                <div><div className="hint-text">{t("ia.review_due", "Review due")}</div><strong>{fmt(a.review_due)}</strong></div>
                <div><div className="hint-text">{t("ia.q.residual", "Residual risk")}</div><strong>{a.residual ? t(`ia.o.residual.${a.residual}`, a.residual) : "—"}</strong></div>
                <div><div className="hint-text">{t("ia.q.decision", "Decision")}</div><strong>{a.decision ? t(`ia.o.decision.${a.decision}`, a.decision) : "—"}</strong></div>
              </>
            )}
            {editing && (
              <div><div className="hint-text">{t("ia.progress", "Required answers")}</div><strong>{required - missing.length} / {required}</strong></div>
            )}
          </div>
          <div className="panel-body hint-text" style={{ paddingTop: 0 }}>
            {t("ia.intro", "One questionnaire serves as the ISO/IEC 42005 impact assessment, the GDPR data protection impact assessment and the EU AI Act fundamental rights impact assessment. The Compliance page reads the approved version.")}
          </div>
        </div>

        {error && <p className="error-text" style={{ marginBottom: 12 }}>{error}</p>}
        {notice && <p className="hint-text" style={{ marginBottom: 12 }}>{notice}</p>}

        {tpl.sections.map((s) => (
          <div className="panel" key={s.id} style={{ marginBottom: 16 }}>
            <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
              <h2>{t(`ia.s.${s.id}`, s.title)}</h2>
              <span className="hint-text" style={{ fontSize: 12 }}>{s.refs.join(" · ")}</span>
            </div>
            <div className="panel-body">
              {s.questions.filter(visible).map((q) => {
                const flag = showMissing && missing.includes(q.id);
                return (
                  <div key={q.id} className="field" style={{ marginBottom: 14, ...(flag ? { borderLeft: "3px solid var(--risk-critical)", paddingLeft: 10 } : {}) }}>
                    <label style={{ fontWeight: 600 }}>
                      {t(`ia.q.${q.id}`, q.label)}
                      {isRequired(q, answers) && <span style={{ color: "var(--risk-critical)" }}> *</span>}
                    </label>
                    {q.help && <div className="hint-text" style={{ fontSize: 12, marginBottom: 4 }}>{t(`ia.h.${q.id}`, q.help)}</div>}
                    {control(q)}
                  </div>
                );
              })}
            </div>
          </div>
        ))}

        {canEdit && (
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", margin: "8px 0 24px" }}>
            {editing ? (
              <>
                <button className="btn btn-sm" disabled={busy || !dirty} onClick={onSave}>{t("ia.save", "Save draft")}</button>
                <button className="btn btn-primary btn-sm" disabled={busy} onClick={onApprove}>{t("ia.approve", "Approve")}</button>
              </>
            ) : (
              <button className="btn btn-primary btn-sm" onClick={() => setEditing(true)}>{t("ia.revise", "Start a new version")}</button>
            )}
          </div>
        )}

        {data.history.length > 0 && (
          <div className="panel">
            <div className="panel-header"><h2>{t("ia.history", "Approved versions")}</h2></div>
            <table>
              <thead>
                <tr>
                  <th>{t("ia.version", "Version")}</th>
                  <th>{t("ia.approved_on", "Approved on")}</th>
                  <th>{t("ia.q.residual", "Residual risk")}</th>
                  <th>{t("ia.q.decision", "Decision")}</th>
                  <th>{t("ia.review_due", "Review due")}</th>
                </tr>
              </thead>
              <tbody>
                {data.history.map((h) => (
                  <tr key={h.id}>
                    <td>v{h.version}</td>
                    <td className="mono">{fmt(h.approved_at)}</td>
                    <td>{h.residual ? t(`ia.o.residual.${h.residual}`, h.residual) : "—"}</td>
                    <td>{h.decision ? t(`ia.o.decision.${h.decision}`, h.decision) : "—"}</td>
                    <td className="mono">{fmt(h.review_due)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
