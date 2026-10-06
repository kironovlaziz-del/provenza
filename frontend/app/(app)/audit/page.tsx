"use client";

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import { translateApiError } from "@/lib/errors";
import { downloadEvidence } from "@/lib/ed25519_verify";
import {
  checkCheckpoint,
  createCheckpoint,
  getIntegrity,
  verifyChain,
  type ChainReportT,
  type IntegrityT,
  type ProofCheck,
} from "@/lib/audit_api";
import { AuditConsole } from "./AuditConsole";
import { KeyPanel } from "./KeyPanel";

const short = (s: string | null | undefined, n = 12) => (s ? (s.length > n ? s.slice(0, n) + "…" : s) : "—");

function IntegrityPanel({ isAdmin }: { isAdmin: boolean }) {
  const { t, i18n } = useTranslation();
  const [data, setData] = useState<IntegrityT | null>(null);
  const [sig, setSig] = useState<ProofCheck | null>(null);
  const [report, setReport] = useState<ChainReportT | null>(null);
  const [busy, setBusy] = useState<"" | "sign" | "verify">("");
  const [error, setError] = useState("");
  const [rev, setRev] = useState(0); // bumps on every reload so the key block follows

  function load() {
    setRev((r) => r + 1);
    getIntegrity()
      .then((d) => {
        setData(d);
        setSig(null);
        if (d.checkpoint) checkCheckpoint(d.checkpoint).then(setSig);
      })
      .catch((e) => setError(translateApiError(e?.response?.data?.detail, t, t("audit.load_failed"))));
  }

  useEffect(load, []); // eslint-disable-line react-hooks/exhaustive-deps

  async function signNow() {
    setBusy("sign");
    setError("");
    try {
      await createCheckpoint();
      load();
    } catch (e: unknown) {
      const err = e as { response?: { data?: { detail?: unknown } } };
      setError(translateApiError(err?.response?.data?.detail, t, t("audit.action_failed")));
    } finally {
      setBusy("");
    }
  }

  async function verifyAll() {
    setBusy("verify");
    setError("");
    setReport(null);
    try {
      setReport(await verifyChain());
      load(); // the verification itself is a new audit record
    } catch (e: unknown) {
      const err = e as { response?: { data?: { detail?: unknown } } };
      setError(translateApiError(err?.response?.data?.detail, t, t("audit.action_failed")));
    } finally {
      setBusy("");
    }
  }

  const cp = data?.checkpoint ?? null;
  return (
    <div className="panel" style={{ marginBottom: 16 }}>
      <div className="panel-header" style={{ flexWrap: "wrap", gap: 8 }}>
        <h2>{t("audit.integrity_title")}</h2>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {cp && (
            <button type="button" className="btn btn-sm" onClick={() => downloadEvidence(cp, `provenza-checkpoint-${cp.org_id}-${cp.tree_size}.json`)}>
              {t("audit.download_checkpoint")}
            </button>
          )}
          {isAdmin && (
            <>
              <button type="button" className="btn btn-sm" disabled={!!busy} onClick={signNow}>
                {busy === "sign" ? t("audit.working") : t("audit.sign_now")}
              </button>
              <button type="button" className="btn btn-sm btn-primary" disabled={!!busy} onClick={verifyAll}>
                {busy === "verify" ? t("audit.verifying") : t("audit.verify_all")}
              </button>
            </>
          )}
        </div>
      </div>
      <div style={{ padding: "14px 18px 16px", display: "grid", gap: 8, fontSize: 13 }}>
        {error && <div className="error-text">{error}</div>}
        {data && <div>{t("audit.integrity_records", { count: data.head_seq })}</div>}
        {data && !cp && <div className="hint-text">{t("audit.integrity_none")}</div>}
        {cp && (
          <>
            <div>
              {t("audit.integrity_checkpoint", { size: cp.tree_size, time: new Date(cp.issued_at).toLocaleString(i18n.language) })}
              {data && data.unsigned_records > 0 && (
                <span className="hint-text"> · {t("audit.integrity_unsigned", { count: data.unsigned_records })}</span>
              )}
            </div>
            <div className="mono" style={{ overflowWrap: "anywhere" }}>
              {t("audit.root")}: {short(cp.root_hash, 24)} · {t("audit.key")}: {cp.key_fingerprint} ({cp.algorithm})
            </div>
            <div>
              {sig === null ? (
                <span className="hint-text">{t("audit.verifying")}</span>
              ) : sig.ok ? (
                <span className="pill pill-low">✓ {t("audit.sig_verified")}</span>
              ) : (
                <span className="pill pill-critical">✗ {t(`audit.proof_fail_${sig.reason}`, { defaultValue: t("audit.sig_failed") })}</span>
              )}
            </div>
          </>
        )}
        {report && (
          <div style={{ marginTop: 4 }}>
            {report.ok ? (
              <span className="pill pill-low">
                ✓ {t("audit.verify_ok", { records: report.records, roots: report.checkpoint_roots_checked, sigs: report.checkpoint_signatures_checked })}
              </span>
            ) : (
              <>
                <span className="pill pill-critical">✗ {t("audit.verify_bad", { count: report.problem_count })}</span>
                <ul style={{ margin: "6px 0 0 18px" }}>
                  {report.problems.map((p, i) => (
                    <li key={i} className="mono">
                      {t(`audit.problem_${p.kind}`, { seq: p.seq, size: p.tree_size, defaultValue: p.kind })}
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
        )}
        <KeyPanel isAdmin={isAdmin} onChange={load} rev={rev} />
        <div className="hint-text">{t("audit.offline_hint")}</div>
      </div>
    </div>
  );
}

export default function AuditLogsPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  return (
    <>
      <PageHeader title={t("audit.title")} />
      <div className="content">
        <IntegrityPanel isAdmin={isAdmin} />
        <AuditConsole />
      </div>
    </>
  );
}
