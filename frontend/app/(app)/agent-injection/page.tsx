"use client";

import React, { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import {
  clearTaint,
  getInjectionOverview,
  injectionError,
  saveInjectionSettings,
  scanText,
  type Finding,
  type InjectionMode,
  type InjectionOverview,
  type InjectionSettings,
  type ScanResult,
  type Verdict,
} from "@/lib/injection_api";

const MODES: InjectionMode[] = ["off", "monitor", "enforce"];
const VERDICT_PILL: Record<Verdict, string> = { clean: "pill-low", suspicious: "pill-medium", injection: "pill-critical" };
const OUTCOME_PILL: Record<string, string> = { flagged: "pill-medium", blocked: "pill-critical", tainted: "pill-critical" };
const LIST: React.CSSProperties = { maxHeight: 420, overflowY: "auto", overflowX: "auto" };

export default function AgentInjectionPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [data, setData] = useState<InjectionOverview | null>(null);
  const [form, setForm] = useState<InjectionSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [sample, setSample] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [filter, setFilter] = useState<"all" | "argument" | "output">("all");

  const load = useCallback(() => {
    getInjectionOverview()
      .then((d) => {
        setData(d);
        setForm({ ...d.settings });
      })
      .catch((e) => setError(injectionError(e, t("injection.load_failed", "Could not load the injection guard."))));
  }, [t]);

  useEffect(load, [load]);

  async function run(action: () => Promise<unknown>, ok?: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await action();
      if (ok) setNotice(ok);
      load();
    } catch (e) {
      setError(injectionError(e, t("injection.failed", "Could not save.")));
    } finally {
      setBusy(false);
    }
  }

  function save() {
    if (!form || !data) return;
    if (form.mode === "enforce" && data.settings.mode !== "enforce") {
      const ok = window.confirm(
        t(
          "injection.confirm_enforce",
          "Switch to enforce? Tool calls whose arguments contain an injection will be refused, and every chain that receives an injected tool output will need human approval for each further action until an admin clears it.",
        ),
      );
      if (!ok) return;
    }
    run(() => saveInjectionSettings(form), t("injection.saved", "Saved"));
  }

  async function test() {
    if (!sample.trim()) return;
    setBusy(true);
    setError(null);
    try {
      setResult(await scanText(sample));
    } catch (e) {
      setError(injectionError(e, t("injection.failed", "Could not save.")));
    } finally {
      setBusy(false);
    }
  }

  const fmt = (iso: string) => new Date(iso).toLocaleString();
  const label = (f: Finding) => t(`injection.label_${f.label}`, f.label);

  if (!data || !form) {
    return (
      <>
        <PageHeader title={t("injection.title", "Prompt Injection")} />
        <div className="content"><div className="hint-text">{error ?? t("common.loading", "Loading…")}</div></div>
      </>
    );
  }

  const [minT, maxT] = data.bounds.threshold;
  const badThreshold = form.threshold < minT || form.threshold > maxT;
  const detections = data.detections.filter((d) => filter === "all" || d.source === filter);
  const c = data.counts_24h;

  return (
    <>
      <PageHeader title={t("injection.title", "Prompt Injection")} />
      <div className="content">
        <p className="hint-text" style={{ marginTop: 0 }}>
          {t(
            "injection.hint",
            "Instructions hidden in data can hijack an agent's goal (OWASP ASI01). Tool arguments are scanned on every check, tool outputs on every record. In enforce mode an injected argument is refused, and an injected output taints its chain: further actions in it need a human approval until an admin clears the taint.",
          )}
        </p>
        {error && <div className="panel" style={{ marginBottom: 16, borderColor: "#ef4444" }}><div className="panel-body" style={{ color: "#ef4444" }}>{error}</div></div>}
        {notice && <div className="hint-text" style={{ marginBottom: 16 }}>{notice}</div>}

        {/* ---- last 24h ---- */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12, marginBottom: 20 }}>
          {(["flagged", "blocked", "tainted"] as const).map((k) => (
            <div className="panel" key={k}>
              <div className="panel-body">
                <div className="hint-text" style={{ fontSize: 12 }}>{t(`injection.count_${k}`, k)} · 24h</div>
                <div style={{ fontSize: 24, fontWeight: 600 }}>{c[k] ?? 0}</div>
              </div>
            </div>
          ))}
          <div className="panel">
            <div className="panel-body">
              <div className="hint-text" style={{ fontSize: 12 }}>{t("injection.tainted_now", "Tainted chains")}</div>
              <div style={{ fontSize: 24, fontWeight: 600 }}>{data.tainted_chains.length}</div>
            </div>
          </div>
        </div>

        {/* ---- tainted chains ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header"><h2>☣ {t("injection.tainted_title", "Tainted chains")} ({data.tainted_chains.length})</h2></div>
          <div className="panel-body" style={LIST}>
            {data.tainted_chains.length === 0 ? (
              <p className="hint-text" style={{ margin: 0 }}>{t("injection.tainted_empty", "No chain is tainted.")}</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>{t("injection.col_chain", "Chain")}</th>
                    <th>{t("injection.col_time", "Time")}</th>
                    <th>{t("injection.col_source", "Source")}</th>
                    <th>{t("injection.col_findings", "Findings")}</th>
                    {isAdmin && <th />}
                  </tr>
                </thead>
                <tbody>
                  {data.tainted_chains.map((ch) => (
                    <tr key={ch.chain_id}>
                      <td>#{ch.chain_id}{ch.root_agent ? <span className="hint-text"> · {ch.root_agent}</span> : null}</td>
                      <td style={{ fontSize: 12 }}>{fmt(ch.tainted_at)}</td>
                      <td className="mono" style={{ fontSize: 11 }}>
                        {ch.details.tool_name ?? "—"}{ch.details.path ? ` → ${ch.details.path}` : ""}
                      </td>
                      <td style={{ fontSize: 12 }}>{(ch.details.findings ?? []).map((f) => label(f)).join(", ") || "—"}</td>
                      {isAdmin && (
                        <td>
                          <button
                            className="btn btn-sm btn-primary"
                            disabled={busy}
                            onClick={() => {
                              if (window.confirm(t("injection.confirm_clear", "Clear the taint? Actions in this chain will no longer need a human approval because of the injected output.")))
                                run(() => clearTaint(ch.chain_id), t("injection.cleared", "Taint cleared"));
                            }}
                          >
                            {t("injection.clear", "Clear")}
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* ---- detections ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <h2>{t("injection.detections_title", "Detections")}</h2>
            <select value={filter} onChange={(e) => setFilter(e.target.value as typeof filter)} style={{ width: "auto" }}>
              <option value="all">{t("injection.filter_all", "All sources")}</option>
              <option value="argument">{t("injection.source_argument", "Argument")}</option>
              <option value="output">{t("injection.source_output", "Tool output")}</option>
            </select>
          </div>
          <div className="panel-body" style={LIST}>
            {detections.length === 0 ? (
              <p className="hint-text" style={{ margin: 0 }}>{t("injection.detections_empty", "Nothing detected.")}</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>{t("injection.col_time", "Time")}</th>
                    <th>{t("injection.col_agent", "Agent")}</th>
                    <th>{t("injection.col_source", "Source")}</th>
                    <th>{t("injection.col_findings", "Findings")}</th>
                    <th>{t("injection.col_score", "Score")}</th>
                    <th>{t("injection.col_outcome", "Outcome")}</th>
                  </tr>
                </thead>
                <tbody>
                  {detections.map((d) => (
                    <tr key={d.id}>
                      <td style={{ fontSize: 12, whiteSpace: "nowrap" }}>{fmt(d.detected_at)}</td>
                      <td>
                        {d.agent_name ?? "—"}
                        {d.chain_id ? <span className="hint-text" style={{ fontSize: 11 }}> · #{d.chain_id}</span> : null}
                      </td>
                      <td style={{ fontSize: 12 }}>
                        {t(`injection.source_${d.source}`, d.source)}
                        <div className="hint-text mono" style={{ fontSize: 11 }}>
                          {d.tool_name ?? ""}{d.path ? ` → ${d.path}` : ""}
                        </div>
                      </td>
                      <td style={{ fontSize: 12, maxWidth: 360 }}>
                        {d.findings.map((f) => (
                          <div key={f.label}>
                            <strong>{label(f)}</strong>{" "}
                            <span className="hint-text mono" style={{ fontSize: 11, wordBreak: "break-word" }}>{f.snippet}</span>
                          </div>
                        ))}
                      </td>
                      <td>
                        <span className={`pill ${VERDICT_PILL[d.verdict]}`}>{d.score}</span>
                      </td>
                      <td>
                        <span className={`pill ${OUTCOME_PILL[d.outcome] ?? "pill-medium"}`}>
                          {t(`injection.outcome_${d.outcome}`, d.outcome)}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* ---- tester ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header"><h2>{t("injection.tester_title", "Test a text")}</h2></div>
          <div className="panel-body">
            <textarea
              rows={5}
              value={sample}
              maxLength={100000}
              placeholder={t("injection.tester_placeholder", "Paste a web page, e-mail or tool output…")}
              onChange={(e) => setSample(e.target.value)}
              style={{ width: "100%", fontFamily: "monospace", fontSize: 13 }}
            />
            <button className="btn btn-sm btn-primary" style={{ marginTop: 8 }} disabled={busy || !sample.trim()} onClick={test}>
              {t("injection.scan", "Scan")}
            </button>
            {result && (
              <div style={{ marginTop: 12 }}>
                <span className={`pill ${VERDICT_PILL[result.verdict]}`}>{t(`injection.verdict_${result.verdict}`, result.verdict)}</span>{" "}
                <span className="hint-text">{t("injection.col_score", "Score")} {result.score} / {data.settings.threshold}</span>
                {result.findings.map((f) => (
                  <div key={f.label} style={{ fontSize: 13, marginTop: 4 }}>
                    <strong>{label(f)}</strong> <span className="hint-text">+{f.weight}</span>{" "}
                    <span className="mono" style={{ fontSize: 12, wordBreak: "break-word" }}>{f.snippet}</span>
                  </div>
                ))}
                {result.truncated && <div className="hint-text" style={{ fontSize: 12 }}>{t("injection.truncated", "Only the first 100,000 characters were scanned.")}</div>}
              </div>
            )}
          </div>
        </div>

        {/* ---- settings ---- */}
        <div className="panel">
          <div className="panel-header"><h2>{t("injection.settings_title", "Settings")}</h2></div>
          <div className="panel-body">
            <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 14 }}>
              {MODES.map((m) => (
                <label key={m} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                  <input
                    type="radio"
                    name="pi-mode"
                    checked={form.mode === m}
                    disabled={!isAdmin}
                    onChange={() => setForm({ ...form, mode: m })}
                    style={{ width: "auto", marginTop: 3 }}
                  />
                  <span>
                    <strong>{t(`injection.mode_${m}`, m)}</strong>
                    <span className="hint-text" style={{ display: "block", fontSize: 12 }}>{t(`injection.mode_${m}_hint`, "")}</span>
                  </span>
                </label>
              ))}
            </div>
            <div className="field" style={{ margin: 0, maxWidth: 260 }}>
              <label htmlFor="pi-threshold">{t("injection.field_threshold", "Injection threshold (score)")}</label>
              <input
                id="pi-threshold"
                type="number"
                min={minT}
                max={maxT}
                disabled={!isAdmin}
                value={form.threshold}
                onChange={(e) => setForm({ ...form, threshold: Number(e.target.value) })}
              />
              <div className="hint-text" style={{ fontSize: 12 }}>
                {t("injection.help_threshold", "Lower catches more, with more false positives")} ({minT}–{maxT})
              </div>
            </div>
            <div className="hint-text" style={{ fontSize: 12, marginTop: 10 }}>
              {t("injection.weights", "Signal weights")}:{" "}
              {Object.entries(data.weights).map(([k, v]) => `${t(`injection.label_${k}`, k)} ${v}`).join(" · ")}
            </div>
            {isAdmin && (
              <button className="btn btn-primary btn-sm" style={{ marginTop: 12 }} disabled={busy || badThreshold} onClick={save}>
                {t("injection.save", "Save")}
              </button>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
