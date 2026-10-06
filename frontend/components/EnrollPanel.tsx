"use client";

// Two ways to use an enrollment token: right here in the browser (keys made
// on this page, downloaded as provenza-agent.json, never sent to the server),
// or with the Python tool where the agent runs.
import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { translateApiError } from "@/lib/errors";
import { browserCanEnroll, downloadKeysFile, enrollInBrowser, type AgentKeysFile } from "@/lib/browser_enroll";
import { enrollCommand } from "@/lib/enrollment_api";

export function EnrollPanel({ token, hybrid, rekey = false }: { token: string; hybrid: boolean; rekey?: boolean }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<AgentKeysFile | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const cmd = enrollCommand(token, hybrid, rekey);
  const supported = browserCanEnroll();

  async function run() {
    setBusy(true);
    setError(null);
    try {
      const file = await enrollInBrowser(token, { hybrid });
      downloadKeysFile(file);
      setDone(file);
    } catch (e) {
      const err = e as { message?: string; response?: { data?: { detail?: unknown } } };
      const detail = err?.response?.data?.detail;
      setError(detail ? translateApiError(detail, t, t("enroll.browser_failed"))
        : t(err?.message?.startsWith("enroll.") ? err.message : "enroll.browser_failed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ display: "grid", gap: 14 }}>
      <div className="field" style={{ margin: 0 }}>
        <label>{t("enroll.browser_title")}</label>
        {done ? (
          <div style={{ display: "grid", gap: 6 }}>
            <span className="pill pill-low">✓ {t(rekey ? "enroll.browser_rekeyed" : "enroll.browser_done", { id: done.agent_id })}</span>
            <code className="mono" style={{ fontSize: 12 }}>{done.key_fingerprint}</code>
            <p className="hint-text" style={{ color: "#f59e0b" }}>{t("enroll.browser_file_warning")}</p>
            <div>
              <button type="button" className="btn btn-sm" onClick={() => downloadKeysFile(done)}>{t("enroll.browser_download_again")}</button>
            </div>
          </div>
        ) : supported ? (
          <>
            <div>
              <button type="button" className="btn btn-primary btn-sm" disabled={busy} onClick={run}>
                {busy ? t("enroll.browser_working") : t("enroll.browser_button")}
              </button>
            </div>
            <p className="hint-text">{t("enroll.browser_hint")}</p>
          </>
        ) : (
          <p className="hint-text" style={{ color: "#f59e0b" }}>{t("enroll.browser_unsupported")}</p>
        )}
        {error && <p className="error-text">{error}</p>}
      </div>
      {!done && (
        <div className="field" style={{ margin: 0 }}>
          <label>{t("enroll.command")}</label>
          <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
            <code className="mono" style={{ wordBreak: "break-all", flex: 1, fontSize: 12 }}>{cmd}</code>
            <button type="button" className="btn btn-sm" onClick={() => navigator.clipboard?.writeText(cmd).then(() => setCopied(true), () => undefined)}>
              {copied ? t("agents.copied") : t("agents.copy")}
            </button>
          </div>
          <p className="hint-text" style={{ color: "#f59e0b" }}>⚠ {t("enroll.cli_requires")}</p>
          <code className="mono" style={{ fontSize: 12 }}>{hybrid ? 'pip install "cryptography>=48"' : "pip install cryptography"}</code>
          <p className="hint-text">{t("enroll.command_hint")}</p>
        </div>
      )}
    </div>
  );
}
