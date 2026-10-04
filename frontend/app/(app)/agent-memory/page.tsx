"use client";

import React, { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import {
  getMemoryOverview,
  memoryError,
  saveMemorySettings,
  setEntryTrust,
  type EntryStatus,
  type MemFinding,
  type MemoryMode,
  type MemoryOverview,
  type MemorySettings,
} from "@/lib/memory_api";

const MODES: MemoryMode[] = ["off", "monitor", "enforce"];
const STATUS_PILL: Record<string, string> = {
  trusted: "pill-low",
  quarantined: "pill-critical",
  revoked: "pill-neutral",
  rejected: "pill-high",
};
const LIST: React.CSSProperties = { maxHeight: 420, overflowY: "auto", overflowX: "auto" };
const NS_GLOB = /^[A-Za-z0-9_.:\-/*?]{1,200}$/;

export default function AgentMemoryPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [data, setData] = useState<MemoryOverview | null>(null);
  const [form, setForm] = useState<MemorySettings | null>(null);
  const [nsText, setNsText] = useState("");
  const [statusFilter, setStatusFilter] = useState<EntryStatus | "">("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    getMemoryOverview(statusFilter)
      .then((d) => {
        setData(d);
        setForm({ ...d.settings });
        setNsText(d.settings.shared_namespaces.join("\n"));
      })
      .catch((e) => setError(memoryError(e, t("memory.load_failed", "Could not load memory integrity."))));
  }, [t, statusFilter]);

  useEffect(load, [load]);

  async function run(action: () => Promise<unknown>, ok?: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const r = await action();
      if (ok) setNotice(ok);
      load();
      return r;
    } catch (e) {
      setError(memoryError(e, t("memory.failed", "Could not save.")));
    } finally {
      setBusy(false);
    }
  }

  const namespaces = nsText.split("\n").map((s) => s.trim()).filter(Boolean);
  const badNs = namespaces.filter((g) => !NS_GLOB.test(g));

  function save() {
    if (!form || !data) return;
    if (form.mode === "enforce" && data.settings.mode !== "enforce") {
      const ok = window.confirm(
        t(
          "memory.confirm_enforce",
          "Switch to enforce? Poisoned memory entries will be quarantined and kept out of prompts, and writes into foreign namespaces will be rejected.",
        ),
      );
      if (!ok) return;
    }
    run(() => saveMemorySettings({ ...form, shared_namespaces: namespaces }), t("memory.saved", "Saved"));
  }

  const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "—");
  const lab = (f: MemFinding) => t(`memory.label_${f.label}`, t(`injection.label_${f.label}`, t(`codeexec.label_${f.label}`, f.label)));

  if (!data || !form) {
    return (
      <>
        <PageHeader title={t("memory.title", "Memory Integrity")} />
        <div className="content"><div className="hint-text">{error ?? t("common.loading", "Loading…")}</div></div>
      </>
    );
  }

  const c = data.entry_counts;

  return (
    <>
      <PageHeader title={t("memory.title", "Memory Integrity")} />
      <div className="content">
        <p className="hint-text" style={{ marginTop: 0 }}>
          {t(
            "memory.hint",
            "Whatever lands in an agent's memory comes back into prompts later (OWASP ASI06). Agents attest each memory write and verify retrieved memory before using it; content is scanned for injections and code. Only trusted memory reaches a prompt.",
          )}
        </p>
        {error && <div className="panel" style={{ marginBottom: 16, borderColor: "#ef4444" }}><div className="panel-body" style={{ color: "#ef4444" }}>{error}</div></div>}
        {notice && <div className="hint-text" style={{ marginBottom: 16 }}>{notice}</div>}

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12, marginBottom: 20 }}>
          {(["trusted", "quarantined", "revoked", "rejected"] as const).map((k) => (
            <div className="panel" key={k}><div className="panel-body">
              <div className="hint-text" style={{ fontSize: 12 }}>{t("memory.entries", "Memory entries")} · {t(`memory.status_${k}`, k)}</div>
              <div style={{ fontSize: 24, fontWeight: 600 }}>{c[k] ?? 0}</div>
            </div></div>
          ))}
        </div>

        {/* ---- agent memory ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <h2>{t("memory.entries_title", "Agent memory")}</h2>
            <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value as EntryStatus | "")} style={{ width: "auto" }}>
              <option value="">{t("memory.filter_all", "All statuses")}</option>
              {(["quarantined", "trusted", "revoked", "rejected"] as const).map((s) => (
                <option key={s} value={s}>{t(`memory.status_${s}`, s)}</option>
              ))}
            </select>
          </div>
          <div className="panel-body" style={LIST}>
            {data.entries.length === 0 ? (
              <p className="hint-text" style={{ margin: 0 }}>{t("memory.entries_empty", "No memory writes attested yet.")}</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>{t("memory.col_time", "Time")}</th>
                    <th>{t("memory.col_agent", "Agent")}</th>
                    <th>{t("memory.col_namespace", "Namespace")}</th>
                    <th>{t("memory.col_reasons", "Reasons")}</th>
                    <th>{t("memory.col_status", "Status")}</th>
                    {isAdmin && <th />}
                  </tr>
                </thead>
                <tbody>
                  {data.entries.map((e) => (
                    <tr key={e.id}>
                      <td style={{ fontSize: 12, whiteSpace: "nowrap" }}>
                        {fmt(e.created_at)}
                        <div className="hint-text" style={{ fontSize: 11 }}>{t("memory.expires", "expires")} {fmt(e.expires_at)}</div>
                      </td>
                      <td>
                        {e.agent_name}
                        {e.chain_id ? <span className="hint-text" style={{ fontSize: 11 }}> · #{e.chain_id}</span> : null}
                        <div className="hint-text" style={{ fontSize: 11 }}>{t(`memory.source_${e.source}`, e.source)}{e.source_ref ? ` · ${e.source_ref}` : ""}</div>
                      </td>
                      <td className="mono" style={{ fontSize: 12 }}>
                        {e.namespace}{e.key ? ` / ${e.key}` : ""}
                        <div className="hint-text" style={{ fontSize: 10 }} title={e.sha256}>{e.sha256.slice(0, 16)}…</div>
                      </td>
                      <td style={{ fontSize: 12, maxWidth: 360 }}>
                        {e.reasons.length === 0 ? <span className="hint-text">—</span> : e.reasons.map((r, i) => <div key={i}>{r}</div>)}
                        {e.findings.slice(0, 2).map((f, i) => (
                          <div key={`f${i}`} className="hint-text mono" style={{ fontSize: 11, wordBreak: "break-word" }}>{lab(f)}: {f.snippet}</div>
                        ))}
                      </td>
                      <td><span className={`pill ${STATUS_PILL[e.status]}`}>{t(`memory.status_${e.status}`, e.status)}</span></td>
                      {isAdmin && (
                        <td style={{ whiteSpace: "nowrap" }}>
                          {e.status !== "rejected" && e.status !== "trusted" && (
                            <button className="btn btn-sm btn-primary" disabled={busy}
                              onClick={() => run(() => setEntryTrust(e.id, true), t("memory.saved", "Saved"))}>
                              {t("memory.trust", "Trust")}
                            </button>
                          )}{" "}
                          {e.status !== "rejected" && e.status !== "revoked" && (
                            <button className="btn btn-sm" disabled={busy}
                              onClick={() => {
                                if (window.confirm(t("memory.confirm_revoke_entry", "Revoke this memory entry? Agents will stop using it at their next verification.")))
                                  run(() => setEntryTrust(e.id, false), t("memory.saved", "Saved"));
                              }}>
                              {t("memory.revoke", "Revoke")}
                            </button>
                          )}
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* ---- settings ---- */}
        <div className="panel">
          <div className="panel-header"><h2>{t("memory.settings_title", "Settings")}</h2></div>
          <div className="panel-body">
            <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 14 }}>
              {MODES.map((m) => (
                <label key={m} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                  <input type="radio" name="mem-mode" checked={form.mode === m} disabled={!isAdmin}
                    onChange={() => setForm({ ...form, mode: m })} style={{ width: "auto", marginTop: 3 }} />
                  <span>
                    <strong>{t(`memory.mode_${m}`, m)}</strong>
                    <span className="hint-text" style={{ display: "block", fontSize: 12 }}>{t(`memory.mode_${m}_hint`, "")}</span>
                  </span>
                </label>
              ))}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 12 }}>
              <div className="field" style={{ margin: 0 }}>
                <label htmlFor="mem-ns">{t("memory.shared_namespaces", "Shared namespaces (one pattern per line)")}</label>
                <textarea id="mem-ns" rows={4} value={nsText} disabled={!isAdmin} onChange={(e) => setNsText(e.target.value)}
                  style={{ width: "100%", fontFamily: "monospace", fontSize: 13 }} />
                <div className="hint-text" style={{ fontSize: 12 }}>
                  {t("memory.shared_hint", "Every agent may write and read these. Its own namespace agent.<id> is always allowed.")}
                </div>
                {badNs.length > 0 && <div style={{ color: "#ef4444", fontSize: 12 }}>{t("memory.bad_ns", "Invalid patterns")}: {badNs.join(", ")}</div>}
              </div>
              <div className="field" style={{ margin: 0 }}>
                <label htmlFor="mem-ttl">{t("memory.ttl", "Memory lifetime, days")}</label>
                <input id="mem-ttl" type="number" min={1} max={365} disabled={!isAdmin} value={form.default_ttl_days}
                  onChange={(e) => setForm({ ...form, default_ttl_days: Number(e.target.value) })} />
                <div className="hint-text" style={{ fontSize: 12 }}>{t("memory.ttl_hint", "After this an entry verifies as expired (1–365)")}</div>
              </div>
            </div>
            {isAdmin && (
              <button className="btn btn-primary btn-sm" style={{ marginTop: 12 }}
                disabled={busy || badNs.length > 0 || namespaces.length > 50 || form.default_ttl_days < 1 || form.default_ttl_days > 365}
                onClick={save}>
                {t("memory.save", "Save")}
              </button>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
