"use client";

import Link from "next/link";
import React, { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { useTranslation } from "react-i18next";
import { STATUS_PILL, complianceError, getReport, type ComplianceResult } from "@/lib/compliance_api";

type Loaded = { id: number; created_at: string; sha256: string; integrity_ok: boolean; content: ComplianceResult };

export default function ComplianceReportPage() {
  const params = useParams();
  const id = Number(params?.id);
  const { t } = useTranslation();
  const [rep, setRep] = useState<Loaded | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!Number.isFinite(id)) return;
    getReport(id).then(setRep).catch((e) => setError(complianceError(e, t("compliance.load_failed", "Could not load."))));
  }, [id, t]);

  function downloadJson() {
    if (!rep) return;
    const blob = new Blob([JSON.stringify({ sha256: rep.sha256, ...rep.content }, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `provenza-compliance-report-${rep.id}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  if (!rep) return <div className="content"><div className="hint-text">{error ?? t("common.loading", "Loading…")}</div></div>;
  const c = rep.content;

  return (
    <div className="content compliance-report" style={{ maxWidth: 1000 }}>
      <style>{`@media print { nav, aside, header, .no-print { display: none !important; } .compliance-report { max-width: none !important; } .compliance-report .panel { break-inside: avoid; } }`}</style>
      <div className="no-print" style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <Link href="/compliance" className="btn btn-sm">← {t("compliance.back", "Back")}</Link>
        <button className="btn btn-sm btn-primary" onClick={() => window.print()}>{t("compliance.print", "Print / save as PDF")}</button>
        <button className="btn btn-sm" onClick={downloadJson}>{t("compliance.json", "Download JSON")}</button>
      </div>

      <h1 style={{ marginBottom: 4 }}>{t("compliance.report_title", "AI compliance report")} #{rep.id}</h1>
      <div className="hint-text" style={{ fontSize: 13 }}>
        {t("compliance.generated", "Generated")} {new Date(c.generated_at).toLocaleString()} · {t("compliance.catalog", "catalog")} {c.catalog_version}
      </div>
      <div style={{ fontSize: 12, margin: "6px 0 16px" }}>
        SHA-256 <span className="mono">{rep.sha256}</span>{" "}
        {rep.integrity_ok ? (
          <span className="pill pill-low">{t("compliance.integrity_ok", "unaltered")}</span>
        ) : (
          <span className="pill pill-critical">{t("compliance.integrity_bad", "CONTENT DOES NOT MATCH ITS FINGERPRINT")}</span>
        )}
      </div>

      <table style={{ marginBottom: 20 }}>
        <thead>
          <tr>
            <th>{t("compliance.framework", "Framework")}</th>
            <th>{t("compliance.score", "Score")}</th>
            {(["pass", "partial", "fail", "manual", "na"] as const).map((k) => <th key={k}>{t(`compliance.status_${k}`, k)}</th>)}
          </tr>
        </thead>
        <tbody>
          {Object.entries(c.summary).map(([fid, s]) => (
            <tr key={fid}>
              <td><strong>{s.name}</strong><div className="hint-text" style={{ fontSize: 11 }}>{s.ref}</div></td>
              <td><strong>{s.score == null ? "—" : `${s.score}%`}</strong></td>
              {(["pass", "partial", "fail", "manual", "na"] as const).map((k) => <td key={k}>{s.counts[k]}</td>)}
            </tr>
          ))}
        </tbody>
      </table>

      {c.frameworks.map((fid) => (
        <div key={fid} className="panel" style={{ marginBottom: 16 }}>
          <div className="panel-header"><h2>{c.summary[fid]?.name}</h2></div>
          <div className="panel-body">
            <table>
              <tbody>
                {c.requirements.filter((r) => r.framework === fid).map((r) => (
                  <tr key={r.id} style={{ verticalAlign: "top" }}>
                    <td style={{ width: 90 }}><span className={`pill ${STATUS_PILL[r.status]}`}>{t(`compliance.status_${r.status}`, r.status)}</span></td>
                    <td style={{ width: 110 }} className="mono">{r.ref}</td>
                    <td>
                      <strong>{t(`compliance.req.${r.id}`, r.title)}</strong>
                      <div style={{ fontSize: 12 }}>{r.detail}</div>
                      {r.evidence.length > 0 && (
                        <div className="hint-text" style={{ fontSize: 11 }}>
                          {r.evidence.map((e) => `${e.label}: ${e.value ?? "—"}`).join(" · ")}
                        </div>
                      )}
                      {r.attestation && (
                        <div className="hint-text" style={{ fontSize: 11 }}>
                          {t("compliance.attested_on", "Attested")} {String(r.attestation.attested_at).slice(0, 10)} ({r.attestation.status})
                          {r.attestation.evidence_url ? ` · ${r.attestation.evidence_url}` : ""}
                          {r.attestation.note ? ` · ${r.attestation.note}` : ""}
                        </div>
                      )}
                      {(r.systems ?? []).map((s) => (
                        <div key={s.system_id} style={{ fontSize: 12, marginTop: 4 }}>
                          <span className={`pill ${STATUS_PILL[s.status]}`}>{t(`compliance.status_${s.status}`, s.status)}</span>{" "}
                          {s.system} — {s.detail}
                          {s.attestation?.evidence_url ? ` · ${s.attestation.evidence_url}` : ""}
                        </div>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ))}
      <p className="hint-text" style={{ fontSize: 11 }}>
        {t("compliance.disclaimer", "Generated by Provenza from its own records and recorded attestations. References are pointers for orientation, not legal advice.")}
      </p>
    </div>
  );
}
