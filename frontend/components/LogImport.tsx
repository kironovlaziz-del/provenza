"use client";

// Shadow AI -> Import logs: an administrator gives a DNS or proxy log file;
// the lines that reach an AI service become sightings and show who uses what
// (backend: app/services/log_import.py).

import React, { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { importAILogs } from "@/lib/api";
import { apiErrorMessage } from "@/lib/inventory_api";
import type { LogImportResult } from "@/lib/types";

export function LogImport({ onDone }: { onDone?: () => void }) {
  const { t, i18n } = useTranslation();
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<LogImportResult | null>(null);
  const n = (v: number) => v.toLocaleString(i18n.language);

  async function run(e: React.FormEvent) {
    e.preventDefault();
    if (!file) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await importAILogs(file));
      onDone?.();
    } catch (err) {
      setError(apiErrorMessage(err, t("log_import.failed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel" style={{ marginBottom: 20 }}>
      <div className="panel-header">
        <h2>{t("log_import.title")}</h2>
      </div>
      <div className="panel-body">
        <p className="hint-text" style={{ marginTop: 0 }}>{t("log_import.hint")}</p>
        <form onSubmit={run} className="form-row" style={{ alignItems: "center" }}>
          <input
            ref={input}
            type="file"
            aria-label={t("log_import.file")}
            onChange={(e) => { setFile(e.target.files?.[0] ?? null); setResult(null); setError(null); }}
            style={{ flex: 1, minWidth: 0 }}
          />
          <button className="btn btn-primary btn-sm" type="submit" disabled={!file || busy}>
            {busy ? t("log_import.reading") : t("log_import.import")}
          </button>
        </form>
        <p className="hint-text">{t("log_import.formats")}</p>
        {error && <p className="error-text">{error}</p>}
        {result && (
          <div style={{ marginTop: 12 }}>
            <p>
              {result.ai_lines > 0
                ? t("log_import.found", {
                    lines: n(result.lines), ai: n(result.ai_lines), services: n(result.services),
                    people: n(result.people), computers: n(result.computers),
                  })
                : t("log_import.nothing", { lines: n(result.lines), recognized: n(result.recognized) })}
            </p>
            {result.top.length > 0 && (
              <table>
                <thead>
                  <tr>
                    <th>{t("log_import.col_service")}</th>
                    <th style={{ textAlign: "right" }}>{t("log_import.col_lines")}</th>
                  </tr>
                </thead>
                <tbody>
                  {result.top.map((r) => (
                    <tr key={r.domain}>
                      <td className="mono">{r.domain}</td>
                      <td className="mono" style={{ textAlign: "right" }}>{n(r.hits)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <p className="hint-text">
              {result.recognized < result.lines && t("log_import.unrecognized", { count: result.lines - result.recognized }) + " "}
              {result.truncated && t("log_import.truncated") + " "}
              {result.ai_lines > 0 && t("log_import.after")}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
