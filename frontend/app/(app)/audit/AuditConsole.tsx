"use client";

// The audit log as a console: one compact line per record, newest first, in
// a scrolling pane. A click opens the record - its details as formatted JSON,
// its place in the hash chain, and a proof checked in this browser.

import React, { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { listAuditLogs } from "@/lib/api";
import type { AuditLog } from "@/lib/types";
import { translateApiError } from "@/lib/errors";
import { downloadEvidence } from "@/lib/ed25519_verify";
import { checkProof, getProof, type ProofCheck } from "@/lib/audit_api";

const PAGE = 100;

const ENTITY_TYPES = [
  "organization", "user", "policy", "policy_version", "use_case", "provider", "request", "approval",
  "incident", "agent", "ai_system", "discovered_agent", "audit_log", "audit_key",
];

/** Colour family of an action, by the words it contains. */
function tone(action: string): string {
  const a = action.toLowerCase();
  if (/(reject|block|denied|deny|fail|revok|delete|remov|disabl|cancel|incident|kill|breach)/.test(a)) return "bad";
  if (/(approv|resolv|verif|complet|restor|enabl|allow)/.test(a)) return "good";
  if (/(creat|regist|discover|found|add|connect|propos|invit|login)/.test(a)) return "new";
  if (/(updat|chang|edit|rotat|ignor|link|set|sign)/.test(a)) return "change";
  return "plain";
}

const pad = (n: number) => String(n).padStart(2, "0");
function stamp(iso: string): string {
  const d = new Date(iso);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function scalar(v: unknown): string {
  if (v === null || v === undefined) return "null";
  if (typeof v === "string") return /\s/.test(v) || v === "" ? JSON.stringify(v) : v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (Array.isArray(v)) return `[${v.length}]`;
  return "{…}";
}

/** key=value pairs of the metadata, nested objects one level deep. */
function summary(meta: Record<string, unknown> | null | undefined): string {
  if (!meta) return "";
  const parts: string[] = [];
  for (const [k, v] of Object.entries(meta)) {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      for (const [k2, v2] of Object.entries(v as Record<string, unknown>)) parts.push(`${k}.${k2}=${scalar(v2)}`);
    } else {
      parts.push(`${k}=${scalar(v)}`);
    }
  }
  return parts.join(" · ");
}

/** Pretty JSON with keys, strings and numbers marked for colour. */
function JsonView({ value }: { value: unknown }) {
  const text = JSON.stringify(value, null, 2) ?? "null";
  const out: React.ReactNode[] = [];
  const re = /("(?:[^"\\]|\\.)*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    if (m[1] && m[2]) out.push(<span key={i++} className="ac-k">{m[1]}</span>, m[2]);
    else if (m[1]) out.push(<span key={i++} className="ac-s">{m[1]}</span>);
    else if (m[3]) out.push(<span key={i++} className="ac-b">{m[3]}</span>);
    else out.push(<span key={i++} className="ac-n">{m[4]}</span>);
    last = re.lastIndex;
  }
  out.push(text.slice(last));
  return <pre className="ac-json">{out}</pre>;
}

type RowProof = { state: "checking" } | { state: "done"; check: ProofCheck; proof: object } | { state: "error"; message: string };

export function AuditConsole() {
  const { t } = useTranslation();
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [more, setMore] = useState(false);
  const [entityType, setEntityType] = useState("");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<number | null>(null);
  const [proofs, setProofs] = useState<Record<number, RowProof>>({});
  const [error, setError] = useState("");

  function fetchPage(skip: number) {
    setLoading(true);
    setError("");
    listAuditLogs({ ...(entityType ? { entity_type: entityType } : {}), skip, limit: PAGE })
      .then((data) => {
        setLogs((prev) => (skip === 0 ? data : [...prev, ...data]));
        setMore(data.length === PAGE);
      })
      .catch((e) => setError(translateApiError(e?.response?.data?.detail, t, t("audit.load_failed"))))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    setOpen(null);
    fetchPage(0);
  }, [entityType]); // eslint-disable-line react-hooks/exhaustive-deps

  // Esc collapses the open record
  useEffect(() => {
    if (open === null) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(null); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return logs;
    return logs.filter((l) =>
      `${l.seq ?? ""} ${l.entity_type} ${l.entity_id ?? ""} ${l.action} ${l.actor_user_id ?? ""} ${JSON.stringify(l.metadata_json ?? "")}`
        .toLowerCase()
        .includes(needle),
    );
  }, [logs, q]);

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

  function Proof({ log }: { log: AuditLog }) {
    const st = proofs[log.id];
    if (!st) {
      return (
        <button type="button" className="btn btn-sm" onClick={() => check(log.id)}>
          {t("audit.proof_check")}
        </button>
      );
    }
    if (st.state === "checking") return <span className="ac-muted">{t("audit.verifying")}</span>;
    if (st.state === "error") return <span className="error-text">{st.message}</span>;
    return (
      <>
        {st.check.ok ? (
          <span className="ac-ok">✓ {t("audit.proof_ok")} · {st.check.fingerprint}</span>
        ) : (
          <span className="ac-bad">✗ {t(`audit.proof_fail_${st.check.reason}`, { defaultValue: st.check.reason })}</span>
        )}
        <button type="button" className="btn btn-sm" onClick={() => downloadEvidence(st.proof, `provenza-audit-proof-${log.id}.json`)}>
          {t("audit.proof_download")}
        </button>
      </>
    );
  }

  return (
    <div className="panel">
      <div className="panel-header" style={{ gap: 10, flexWrap: "wrap" }}>
        <h2>{t("audit.table_title")}</h2>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", flex: "1 1 320px", justifyContent: "flex-end" }}>
          <input
            type="search"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={t("audit.search")}
            aria-label={t("audit.search")}
            style={{ flex: "1 1 200px", maxWidth: 320, minWidth: 0 }}
          />
          <select value={entityType} onChange={(e) => setEntityType(e.target.value)} aria-label={t("audit.filter_all")} style={{ width: "auto" }}>
            <option value="">{t("audit.filter_all")}</option>
            {ENTITY_TYPES.map((type) => (
              <option key={type} value={type}>{type}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="audit-console" role="log" aria-live="off">
        <div className="ac-head" aria-hidden="true">
          <span>{t("audit.col_seq")}</span>
          <span>{t("audit.col_time")}</span>
          <span>{t("audit.col_action")}</span>
          <span>{t("audit.col_entity")}</span>
          <span>{t("audit.col_user")}</span>
          <span>{t("audit.col_details")}</span>
        </div>
        {error && <div className="ac-line ac-bad">{error}</div>}
        {!loading && shown.length === 0 && <div className="ac-empty">{t(q ? "audit.no_match" : "audit.empty")}</div>}
        {shown.map((log) => {
          const isOpen = open === log.id;
          return (
            <div key={log.id} className={`ac-entry${isOpen ? " ac-open" : ""}`}>
              <button type="button" className="ac-row" aria-expanded={isOpen} onClick={() => setOpen(isOpen ? null : log.id)}>
                <span className="ac-seq"><span className="ac-caret" aria-hidden="true">{isOpen ? "▾" : "▸"}</span>{log.seq ?? "—"}</span>
                <span className="ac-time">{stamp(log.created_at)}</span>
                <span className={`ac-act ac-${tone(log.action)}`}>{log.action}</span>
                <span className="ac-ent">
                  {log.entity_type}
                  {log.entity_id != null && <span className="ac-muted">#{log.entity_id}</span>}
                </span>
                <span className="ac-user">{log.actor_user_id != null ? `#${log.actor_user_id}` : t("audit.system_user")}</span>
                <span className="ac-sum">{summary(log.metadata_json)}</span>
              </button>
              {isOpen && (
                <div className="ac-detail">
                  <div className="ac-kv">
                    <span>{t("audit.detail_time")}</span><span>{new Date(log.created_at).toISOString()}</span>
                    <span>record_hash</span><span>{log.record_hash ?? "—"}</span>
                    <span>prev_hash</span><span>{log.prev_hash ?? "—"}</span>
                  </div>
                  {log.metadata_json ? <JsonView value={log.metadata_json} /> : <div className="ac-muted">{t("audit.no_details")}</div>}
                  <div className="ac-actions">
                    <Proof log={log} />
                    <button type="button" className="btn btn-sm ac-close" onClick={() => setOpen(null)} title="Esc">
                      {t("audit.collapse")}
                    </button>
                  </div>
                </div>
              )}
            </div>
          );
        })}
        {loading && <div className="ac-empty">{t("audit.loading")}</div>}
        {!loading && more && !q && (
          <div className="ac-empty">
            <button type="button" className="btn btn-sm" onClick={() => fetchPage(logs.length)}>
              {t("audit.load_older")}
            </button>
          </div>
        )}
      </div>
      <div className="ac-foot">
        {t("audit.shown", { shown: shown.length, loaded: logs.length })}
      </div>
    </div>
  );
}
