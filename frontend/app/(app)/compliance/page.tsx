"use client";

import Link from "next/link";
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import {
  STATUS_PILL,
  attest,
  complianceError,
  createReport,
  getComplianceStatus,
  listReports,
  type CStatus,
  type ComplianceResult,
  type Evidence,
  type FrameworkId,
  type ReportListItem,
  type RequirementResult,
} from "@/lib/compliance_api";

const STATUSES: CStatus[] = ["fail", "manual", "partial", "pass", "na"];

function EvidenceChips({ items }: { items: Evidence[] }) {
  if (!items.length) return null;
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 4 }}>
      {items.map((e, i) => {
        const body = (
          <>
            <span className="hint-text">{e.label}:</span> <strong>{String(e.value ?? "—")}</strong>
          </>
        );
        const style: React.CSSProperties = { fontSize: 11, padding: "2px 8px", borderRadius: 10, border: "1px solid var(--border, #334155)" };
        return e.link ? (
          e.link.startsWith("/") ? (
            <Link key={i} href={e.link} style={style}>{body}</Link>
          ) : (
            <a key={i} href={e.link} target="_blank" rel="noreferrer" style={style}>{body}</a>
          )
        ) : (
          <span key={i} style={style}>{body}</span>
        );
      })}
    </div>
  );
}

function AttestForm({
  requirement,
  systemId,
  onDone,
}: {
  requirement: RequirementResult;
  systemId: number | null;
  onDone: (msg: string | null, err: string | null) => void;
}) {
  const { t } = useTranslation();
  const [status, setStatus] = useState<"met" | "not_met" | "not_applicable">("met");
  const [note, setNote] = useState("");
  const [url, setUrl] = useState("");
  const [days, setDays] = useState(365);
  const [busy, setBusy] = useState(false);
  const badUrl = url !== "" && !/^(https?:\/\/|\/)\S+$/.test(url);

  async function submit() {
    setBusy(true);
    try {
      await attest({ requirement_id: requirement.id, system_id: systemId, status, note, evidence_url: url, valid_days: days });
      onDone(t("compliance.attested", "Attestation recorded"), null);
    } catch (e) {
      onDone(null, complianceError(e, t("compliance.failed", "Could not save.")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ borderTop: "1px dashed var(--border, #334155)", marginTop: 8, paddingTop: 8 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 8 }}>
        <select value={status} onChange={(e) => setStatus(e.target.value as typeof status)}>
          <option value="met">{t("compliance.att_met", "Met")}</option>
          <option value="not_met">{t("compliance.att_not_met", "Not met")}</option>
          <option value="not_applicable">{t("compliance.att_na", "Not applicable")}</option>
        </select>
        <input placeholder={t("compliance.att_url", "Link to the document (optional)")} value={url} onChange={(e) => setUrl(e.target.value)} />
        <input type="number" min={1} max={1825} value={days} onChange={(e) => setDays(Number(e.target.value))}
          title={t("compliance.att_days", "Valid for, days")} />
      </div>
      <textarea rows={2} maxLength={4000} style={{ width: "100%", marginTop: 6 }}
        placeholder={t("compliance.att_note", "What was checked, by whom, where the evidence is")} value={note} onChange={(e) => setNote(e.target.value)} />
      {badUrl && <div style={{ color: "#ef4444", fontSize: 12 }}>{t("compliance.att_bad_url", "Use an https:// link or a path in Provenza")}</div>}
      <button className="btn btn-primary btn-sm" disabled={busy || badUrl || days < 1 || days > 1825} onClick={submit}>
        {t("compliance.att_save", "Record attestation")}
      </button>
      <span className="hint-text" style={{ fontSize: 11, marginLeft: 8 }}>
        {t("compliance.att_valid", "Valid for")} {days} {t("compliance.days", "days")} · {t("compliance.att_audit", "recorded in the audit log")}
      </span>
    </div>
  );
}

export default function CompliancePage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const role = user?.role as string | undefined;
  const canAttest = role === "admin" || role === "compliance";

  const [data, setData] = useState<ComplianceResult | null>(null);
  const [reports, setReports] = useState<ReportListItem[]>([]);
  const [fw, setFw] = useState<FrameworkId | "all">("all");
  const [filter, setFilter] = useState<CStatus | "open" | "all">("open");
  const [open, setOpen] = useState<string | null>(null);
  const [form, setForm] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    getComplianceStatus()
      .then(setData)
      .catch((e) => setError(complianceError(e, t("compliance.load_failed", "Could not load compliance status."))));
    listReports().then(setReports).catch(() => undefined);
  }, [t]);

  useEffect(load, [load]);

  const reqs = useMemo(() => {
    if (!data) return [];
    return data.requirements.filter(
      (r) =>
        (fw === "all" || r.framework === fw) &&
        (filter === "all" || (filter === "open" ? ["fail", "manual", "partial"].includes(r.status) : r.status === filter)),
    );
  }, [data, fw, filter]);

  function done(msg: string | null, err: string | null) {
    setNotice(msg);
    setError(err);
    if (msg) {
      setForm(null);
      load();
    }
  }

  async function report() {
    setBusy(true);
    setError(null);
    try {
      const r = await createReport(fw === "all" ? undefined : [fw]);
      setNotice(`${t("compliance.report_created", "Report created")} · SHA-256 ${r.sha256.slice(0, 16)}…`);
      load();
    } catch (e) {
      setError(complianceError(e, t("compliance.failed", "Could not save.")));
    } finally {
      setBusy(false);
    }
  }

  if (!data) {
    return (
      <>
        <PageHeader title={t("compliance.title", "Compliance")} />
        <div className="content"><div className="hint-text">{error ?? t("common.loading", "Loading…")}</div></div>
      </>
    );
  }

  return (
    <>
      <PageHeader title={t("compliance.title", "Compliance")} />
      <div className="content">
        <p className="hint-text" style={{ marginTop: 0 }}>
          {t(
            "compliance.hint",
            "Requirements of the EU AI Act, GDPR, ISO/IEC 42001, NIST AI RMF and the OWASP Agentic Top 10, checked against what Provenza actually knows. What only a person can confirm (documents, procedures) is attested here, with a link to the evidence. A pointer for orientation, not legal advice.",
          )}
        </p>
        {error && <div className="panel" style={{ marginBottom: 16, borderColor: "#ef4444" }}><div className="panel-body" style={{ color: "#ef4444" }}>{error}</div></div>}
        {notice && <div className="hint-text" style={{ marginBottom: 16 }}>{notice}</div>}

        {/* ---- scores ---- */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 12, marginBottom: 20 }}>
          {Object.entries(data.summary).map(([id, s]) => (
            <button key={id} type="button" onClick={() => setFw(fw === id ? "all" : (id as FrameworkId))} className="panel"
              style={{ textAlign: "left", cursor: "pointer", borderColor: fw === id ? "#3b82f6" : undefined, background: "inherit" }}>
              <div className="panel-body">
                <div style={{ fontWeight: 600 }}>{s.name}</div>
                <div style={{ fontSize: 28, fontWeight: 700 }}>{s.score == null ? "—" : `${s.score}%`}</div>
                <div style={{ height: 6, borderRadius: 3, background: "rgba(148,163,184,0.25)", overflow: "hidden", margin: "4px 0 6px" }}>
                  <div style={{ width: `${s.score ?? 0}%`, height: "100%", background: (s.score ?? 0) >= 80 ? "#22c55e" : (s.score ?? 0) >= 50 ? "#f59e0b" : "#ef4444" }} />
                </div>
                <div className="hint-text" style={{ fontSize: 11 }}>
                  {STATUSES.filter((k) => s.counts[k]).map((k) => `${t(`compliance.status_${k}`, k)} ${s.counts[k]}`).join(" · ")}
                </div>
              </div>
            </button>
          ))}
        </div>

        {/* ---- requirements ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <h2>
              {fw === "all" ? t("compliance.all", "All frameworks") : data.summary[fw]?.name} · {reqs.length}
            </h2>
            <select value={filter} onChange={(e) => setFilter(e.target.value as typeof filter)} style={{ width: "auto" }}>
              <option value="open">{t("compliance.filter_open", "Needs attention")}</option>
              <option value="all">{t("compliance.filter_all", "All")}</option>
              {STATUSES.map((s) => <option key={s} value={s}>{t(`compliance.status_${s}`, s)}</option>)}
            </select>
          </div>
          <div className="panel-body" style={{ maxHeight: 640, overflowY: "auto" }}>
            {reqs.length === 0 ? (
              <p className="hint-text" style={{ margin: 0 }}>{t("compliance.none", "Nothing here.")}</p>
            ) : (
              reqs.map((r) => (
                <div key={r.id} style={{ borderBottom: "1px solid var(--border, #334155)", padding: "10px 0" }}>
                  <div style={{ display: "flex", gap: 10, alignItems: "flex-start", cursor: "pointer" }} onClick={() => setOpen(open === r.id ? null : r.id)}>
                    <span className={`pill ${STATUS_PILL[r.status]}`} style={{ minWidth: 84, textAlign: "center" }}>{t(`compliance.status_${r.status}`, r.status)}</span>
                    <div style={{ flex: 1 }}>
                      <div>
                        <span className="mono hint-text" style={{ fontSize: 12 }}>{data.summary[r.framework]?.name} {r.ref}</span>{" "}
                        <strong>{t(`compliance.req.${r.id}`, r.title)}</strong>
                      </div>
                      <div className="hint-text" style={{ fontSize: 12 }}>{r.detail}</div>
                    </div>
                    {r.fix && ["fail", "partial"].includes(r.status) && (
                      <Link href={r.fix} className="btn btn-sm" onClick={(e) => e.stopPropagation()}>{t("compliance.fix", "Fix")} →</Link>
                    )}
                  </div>
                  {open === r.id && (
                    <div style={{ marginLeft: 94, marginTop: 6 }}>
                      <EvidenceChips items={r.evidence} />
                      {r.attestation && (
                        <div className="hint-text" style={{ fontSize: 12, marginTop: 6 }}>
                          {t("compliance.attested_on", "Attested")} {new Date(r.attestation.attested_at).toLocaleDateString()}
                          {r.attestation.valid_until ? ` · ${t("compliance.until", "valid until")} ${new Date(r.attestation.valid_until).toLocaleDateString()}` : ""}
                          {r.attestation.note ? ` · ${r.attestation.note}` : ""}
                        </div>
                      )}
                      {r.scope === "org" && r.attest && canAttest && (
                        form === r.id ? (
                          <AttestForm requirement={r} systemId={null} onDone={done} />
                        ) : (
                          <button className="btn btn-sm" style={{ marginTop: 6 }} onClick={() => setForm(r.id)}>{t("compliance.attest", "Attest")}</button>
                        )
                      )}
                      {r.systems && r.systems.length > 0 && (
                        <table style={{ marginTop: 8 }}>
                          <tbody>
                            {r.systems.map((s) => {
                              const key = `${r.id}:${s.system_id}`;
                              return (
                                <tr key={s.system_id}>
                                  <td style={{ width: 90 }}><span className={`pill ${STATUS_PILL[s.status]}`}>{t(`compliance.status_${s.status}`, s.status)}</span></td>
                                  <td>
                                    <Link href={`/inventory/${s.system_id}`}>{s.system}</Link>
                                    <div className="hint-text" style={{ fontSize: 12 }}>{s.detail}</div>
                                    <EvidenceChips items={s.evidence} />
                                    {r.attest && canAttest && (form === key ? (
                                      <AttestForm requirement={r} systemId={s.system_id} onDone={done} />
                                    ) : (
                                      <button className="btn btn-sm" style={{ marginTop: 4 }} onClick={() => setForm(key)}>{t("compliance.attest", "Attest")}</button>
                                    ))}
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      )}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* ---- reports ---- */}
        <div className="panel">
          <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
            <h2>{t("compliance.reports", "Reports for auditors")}</h2>
            <button className="btn btn-primary btn-sm" disabled={busy} onClick={report}>
              {fw === "all" ? t("compliance.report_all", "Create report (all frameworks)") : `${t("compliance.report_one", "Create report")}: ${data.summary[fw]?.name}`}
            </button>
          </div>
          <div className="panel-body" style={{ maxHeight: 320, overflowY: "auto" }}>
            <p className="hint-text" style={{ marginTop: 0, fontSize: 12 }}>
              {t("compliance.reports_hint", "A report is a frozen snapshot with a SHA-256 fingerprint; the report page checks that it was not altered and prints to PDF.")}
            </p>
            {reports.length === 0 ? (
              <p className="hint-text" style={{ margin: 0 }}>{t("compliance.no_reports", "No report yet.")}</p>
            ) : (
              <table>
                <tbody>
                  {reports.map((rp) => (
                    <tr key={rp.id}>
                      <td style={{ fontSize: 12, whiteSpace: "nowrap" }}>{new Date(rp.created_at).toLocaleString()}</td>
                      <td style={{ fontSize: 12 }}>
                        {Object.values(rp.summary).map((s) => `${s.name} ${s.score ?? "—"}%`).join(" · ")}
                      </td>
                      <td className="mono hint-text" style={{ fontSize: 11 }}>{rp.sha256.slice(0, 12)}…</td>
                      <td><Link href={`/compliance/report/${rp.id}`} className="btn btn-sm">{t("compliance.open", "Open")}</Link></td>
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
