"use client";

// OpenTelemetry export of PVP decisions (backend app/services/otel_export.py):
// every policy check, recorded action, LLM call, delegation and incident goes
// to the organization's collector as an OTLP log record - metadata only. The
// endpoint is outbound traffic to the host shown here. Switched on, the
// collector gets a test record first; settings it does not accept are not
// saved. The header's value is never shown again.

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { errorMessage } from "@/lib/errors";
import { getOtelExport, setOtelExport, testOtelExport, type OtelExportT } from "@/lib/otel_export_api";

export function OtelPanel() {
  const { t, i18n } = useTranslation();
  const [st, setSt] = useState<OtelExportT | null>(null);
  const [editing, setEditing] = useState(false);
  const [endpoint, setEndpoint] = useState("");
  const [headerName, setHeaderName] = useState("");
  const [headerValue, setHeaderValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const show = (s: OtelExportT) => {
    setSt(s);
    setEndpoint(s.endpoint ?? "");
    setHeaderName(s.header_name ?? "");
    setHeaderValue("");
  };
  useEffect(() => {
    getOtelExport().then(show).catch(() => setSt(null));
  }, []);

  const fmt = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString(i18n.language) : "—");

  async function run(fn: () => Promise<string>) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      setNotice(await fn());
    } catch (e) {
      setError(errorMessage(e, t, t("otel.failed")));
    } finally {
      setBusy(false);
    }
  }

  function save(enabled: boolean) {
    const name = headerName.trim();
    // switching off keeps what is stored, whatever was typed meanwhile
    const input = enabled
      ? { enabled, endpoint: endpoint.trim() || null, header_name: name || null,
          header_value: name ? headerValue.trim() || null : null }
      : { enabled, endpoint: st?.endpoint ?? null, header_name: st?.header_name ?? null, header_value: null };
    return run(async () => {
      const s = await setOtelExport(input);
      show(s);
      setEditing(false);
      return enabled ? t("otel.saved_on") : t("otel.saved_off");
    });
  }

  function sendTest() {
    return run(async () => {
      const r = await testOtelExport();
      return r.note ? `${t("otel.test_sent")} ${r.note}` : t("otel.test_sent");
    });
  }

  if (!st) return null;
  // a header name that is new, or another one than stored, needs its value
  const sameHeader = !!st.header_set && headerName.trim().toLowerCase() === (st.header_name ?? "").toLowerCase();
  const ready = !!endpoint.trim() && (!headerName.trim() || !!headerValue.trim() || sameHeader);

  return (
    <div className="panel u-mb-16" id="opentelemetry">
      <div className="panel-header">
        <h2>{t("otel.title")}</h2>
      </div>
      <div className="panel-body">
        <p className="hint-text">{t("otel.hint")}</p>

        <table className="u-mb-12">
          <tbody>
            <tr>
              <td style={{ width: 200 }}>{t("otel.state")}</td>
              <td>
                <span className={`pill ${st.enabled ? "pill-low" : "pill-neutral"}`}>
                  {st.enabled ? t("otel.on") : st.endpoint ? t("otel.off") : t("otel.not_set_up")}
                </span>
              </td>
            </tr>
            <tr>
              <td>{t("otel.col_outbound")}</td>
              <td className="mono" style={{ fontSize: 12, overflowWrap: "anywhere" }}>
                {st.outbound_host ? <>→ {st.outbound_host} <span className="hint-text">({st.logs_url})</span></> : "—"}
              </td>
            </tr>
            <tr>
              <td>{t("otel.col_last")}</td>
              <td style={{ fontSize: 12 }}>
                {st.last_success_at ? fmt(st.last_success_at) : <span className="hint-text">{t("otel.never")}</span>}
                {" "}<span className="hint-text">· {t("otel.sent_total", { count: st.exported_total })}</span>
                {st.last_error && (
                  <div className="error-text">{t("otel.last_error", { time: fmt(st.last_error_at) })}: {st.last_error}</div>
                )}
              </td>
            </tr>
            {st.header_name && (
              <tr>
                <td>{t("otel.header")}</td>
                <td className="mono" style={{ fontSize: 12 }}>
                  {st.header_name}{st.header_set ? <span className="hint-text"> · {t("otel.header_stored")}</span> : null}
                </td>
              </tr>
            )}
          </tbody>
        </table>

        {error && <p className="error-text">{error}</p>}
        {notice && <p className="hint-text">{notice}</p>}

        {!editing && (
          <div className="u-btn-row">
            <button className="btn btn-sm" onClick={() => { show(st); setEditing(true); setError(null); setNotice(null); }}>
              {st.endpoint ? t("otel.change") : t("otel.set_up")}
            </button>
            {st.enabled && (
              <button className="btn btn-sm" disabled={busy} onClick={() => sendTest()}>
                {busy ? t("common.loading") : t("otel.test")}
              </button>
            )}
          </div>
        )}

        {editing && (
          <div style={{ display: "grid", gap: 12 }}>
            <div className="field" style={{ margin: 0 }}>
              <label htmlFor="otel-endpoint">{t("otel.endpoint")}</label>
              <input id="otel-endpoint" className="mono" value={endpoint} placeholder="https://otel-collector.example.com:4318"
                onChange={(e) => setEndpoint(e.target.value)} />
              <p className="hint-text">{t("otel.endpoint_hint")}</p>
            </div>
            <div style={{ display: "grid", gap: 12, gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))" }}>
              <div className="field" style={{ margin: 0 }}>
                <label htmlFor="otel-header-name">{t("otel.header_name")}</label>
                <input id="otel-header-name" className="mono" value={headerName} placeholder="Authorization"
                  autoComplete="off" onChange={(e) => setHeaderName(e.target.value)} />
                <p className="hint-text">{t("otel.header_name_hint")}</p>
              </div>
              <div className="field" style={{ margin: 0 }}>
                <label htmlFor="otel-header-value">{t("otel.header_value")}</label>
                <input id="otel-header-value" className="mono" type="password" value={headerValue}
                  autoComplete="new-password" placeholder={sameHeader ? t("otel.header_kept") : ""}
                  onChange={(e) => setHeaderValue(e.target.value)} />
              </div>
            </div>
            <div className="u-btn-row">
              <button className="btn btn-sm btn-primary" disabled={busy || !ready} onClick={() => save(true)}>
                {busy ? t("common.loading") : t("otel.save")}
              </button>
              {st.enabled && (
                <button className="btn btn-sm btn-danger" disabled={busy} onClick={() => save(false)}>
                  {t("otel.switch_off")}
                </button>
              )}
              <button className="btn btn-sm" onClick={() => { setEditing(false); show(st); }}>{t("common.cancel")}</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
