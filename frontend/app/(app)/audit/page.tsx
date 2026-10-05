"use client";

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { listAuditLogs } from "@/lib/api";
import type { AuditLog } from "@/lib/types";
import { useAuth } from "@/lib/auth";
import { translateApiError } from "@/lib/errors";
import { downloadEvidence } from "@/lib/ed25519_verify";
import { KeyPanel } from "./KeyPanel";
import {
  checkCheckpoint,
  checkProof,
  createCheckpoint,
  getIntegrity,
  getProof,
  verifyChain,
  type ChainReportT,
  type IntegrityT,
  type ProofCheck,
} from "@/lib/audit_api";

const ENTITY_TYPES = [
  "organization",
  "user",
  "policy",
  "policy_version",
  "use_case",
  "provider",
  "request",
  "approval",
  "incident",
  "agent",
  "discovered_agent",
  "audit_log",
];

const ACTION_CLASS: Record<string, string> = {
  created: "pill-accent",
  registered: "pill-accent",
  updated: "pill-medium",
  approved: "pill-low",
  rejected: "pill-critical",
  blocked: "pill-critical",
};

function ActionPill({ action }: { action: string }) {
  return (
    <span className={`pill ${ACTION_CLASS[action] ?? "pill-neutral"}`}>{action}</span>
  );
}

const short = (s: string | null | undefined, n = 12) => (s ? (s.length > n ? s.slice(0, n) + "…" : s) : "—");

type RowProof = { state: "checking" } | { state: "done"; check: ProofCheck; proof: unknown } | { state: "error"; message: string };

function IntegrityPanel({ isAdmin }: { isAdmin: boolean }) {
  const { t, i18n } = useTranslation();
  const [data, setData] = useState<IntegrityT | null>(null);
  const [sig, setSig] = useState<ProofCheck | null>(null);
  const [report, setReport] = useState<ChainReportT | null>(null);
  const [busy, setBusy] = useState<"" | "sign" | "verify">("");
  const [error, setError] = useState("");

  function load() {
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
      <div style={{ padding: "4px 4px 12px", display: "grid", gap: 6, fontSize: 13 }}>
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
        <KeyPanel isAdmin={isAdmin} onChange={load} />
        <div className="hint-text">{t("audit.offline_hint")}</div>
      </div>
    </div>
  );
}

export default function AuditLogsPage() {
  const { t, i18n } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [entityType, setEntityType] = useState("");
  const [auditPage, setAuditPage] = useState(0);
  const [proofs, setProofs] = useState<Record<number, RowProof>>({});
  const AUDIT_PAGE_SIZE = 12;

  function refresh(filterType: string) {
    setLoading(true);
    listAuditLogs(filterType ? { entity_type: filterType } : undefined)
      .then((data) => { setLogs(data); setAuditPage(0); })
      .finally(() => setLoading(false));
  }

  useEffect(() => refresh(entityType), [entityType]);

  async function check(id: number) {
    setProofs((p) => ({ ...p, [id]: { state: "checking" } }));
    try {
      const proof = await getProof(id);
      const res = await checkProof(proof);
      setProofs((p) => ({ ...p, [id]: { state: "done", check: res, proof } }));
    } catch (e: unknown) {
      const err = e as { response?: { data?: { detail?: unknown } } };
      setProofs((p) => ({ ...p, [id]: { state: "error", message: translateApiError(err?.response?.data?.detail, t, t("audit.action_failed")) } }));
    }
  }

  function ProofCell({ log }: { log: AuditLog }) {
    const st = proofs[log.id];
    if (!st) {
      return (
        <button type="button" className="btn btn-sm" onClick={() => check(log.id)}>
          {t("audit.proof_check")}
        </button>
      );
    }
    if (st.state === "checking") return <span className="hint-text">{t("audit.verifying")}</span>;
    if (st.state === "error") return <span className="error-text">{st.message}</span>;
    return (
      <span style={{ display: "inline-flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
        {st.check.ok ? (
          <span className="pill pill-low" title={st.check.fingerprint}>✓ {t("audit.proof_ok")}</span>
        ) : (
          <span className="pill pill-critical">✗ {t(`audit.proof_fail_${st.check.reason}`, { defaultValue: st.check.reason })}</span>
        )}
        <button type="button" className="btn btn-sm" onClick={() => downloadEvidence(st.proof as object, `provenza-audit-proof-${log.id}.json`)}>
          {t("audit.proof_download")}
        </button>
      </span>
    );
  }

  return (
    <>
      <PageHeader title={t("audit.title")} />
      <div className="content">
        <IntegrityPanel isAdmin={isAdmin} />
        <div className="panel">
          <div className="panel-header">
            <h2>{t("audit.table_title")}</h2>
            <select
              value={entityType}
              onChange={(e) => setEntityType(e.target.value)}
              style={{
                border: "1px solid var(--border-strong)",
                borderRadius: 4,
                padding: "5px 8px",
              }}
            >
              <option value="">{t("audit.filter_all")}</option>
              {ENTITY_TYPES.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </div>
          <div style={{ overflowX: "auto" }}>
            <table className="table-cards">
              <thead>
                <tr>
                  <th>{t("audit.col_seq")}</th>
                  <th>{t("audit.col_time")}</th>
                  <th>{t("audit.col_entity")}</th>
                  <th>{t("audit.col_id")}</th>
                  <th>{t("audit.col_action")}</th>
                  <th>{t("audit.col_user")}</th>
                  <th>{t("audit.col_details")}</th>
                  <th>{t("audit.col_proof")}</th>
                </tr>
              </thead>
              <tbody>
                {loading && (
                  <tr className="empty-row">
                    <td colSpan={8}>{t("audit.loading")}</td>
                  </tr>
                )}
                {!loading && logs.length === 0 && (
                  <tr className="empty-row">
                    <td colSpan={8}>{t("audit.empty")}</td>
                  </tr>
                )}
                {logs.slice(auditPage * AUDIT_PAGE_SIZE, auditPage * AUDIT_PAGE_SIZE + AUDIT_PAGE_SIZE).map((log) => (
                  <tr key={log.id}>
                    <td data-label={t("audit.col_seq")} className="mono" title={log.record_hash ?? undefined}>{log.seq ?? "—"}</td>
                    <td data-label={t("audit.col_time")} className="mono">
                      {new Date(log.created_at).toLocaleString(i18n.language)}
                    </td>
                    <td data-label={t("audit.col_entity")} className="mono">{log.entity_type}</td>
                    <td data-label={t("audit.col_id")} className="mono">{log.entity_id ?? "—"}</td>
                    <td data-label={t("audit.col_action")}>
                      <ActionPill action={log.action} />
                    </td>
                    <td data-label={t("audit.col_user")} className="mono">
                      {log.actor_user_id != null
                        ? `#${log.actor_user_id}`
                        : t("audit.system_user")}
                    </td>
                    <td data-label={t("audit.col_details")} className="mono" style={{ maxWidth: 360, overflowWrap: "anywhere" }}>
                      {log.metadata_json ? JSON.stringify(log.metadata_json) : "—"}
                    </td>
                    <td data-label={t("audit.col_proof")}>
                      <ProofCell log={log} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {logs.length > AUDIT_PAGE_SIZE && (
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 4px", fontSize: 13 }}>
              <button type="button" className="btn btn-sm" disabled={auditPage === 0} onClick={() => setAuditPage((p) => Math.max(0, p - 1))}>{t("common.prev")}</button>
              <span className="hint-text">{auditPage * AUDIT_PAGE_SIZE + 1}-{Math.min((auditPage + 1) * AUDIT_PAGE_SIZE, logs.length)} / {logs.length}</span>
              <button type="button" className="btn btn-sm" disabled={(auditPage + 1) * AUDIT_PAGE_SIZE >= logs.length} onClick={() => setAuditPage((p) => p + 1)}>{t("common.next")}</button>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
