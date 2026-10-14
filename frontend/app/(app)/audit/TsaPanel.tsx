"use client";

// RFC 3161 witness of the audit log: every checkpoint's statement is
// time-stamped by the organization's Time-Stamp Authority. A checkpoint with
// its token, kept outside the server, proves that state of the log existed
// at that time - tools/provenza_audit.py checks it with --tsa-ca.

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { errorMessage } from "@/lib/errors";
import { getTsa, listCheckpoints, setTsa, stampNow, type CheckpointT, type TsaSettingsT } from "@/lib/audit_api";

export function TsaPanel({ isAdmin, rev }: { isAdmin: boolean; rev?: unknown }) {
  const { t, i18n } = useTranslation();
  const [st, setSt] = useState<TsaSettingsT | null>(null);
  const [cps, setCps] = useState<CheckpointT[]>([]);
  const [editing, setEditing] = useState(false);
  const [url, setUrl] = useState("");
  const [pem, setPem] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = () => {
    getTsa().then((s) => { setSt(s); setUrl(s.url ?? ""); }).catch(() => setSt(null));
    listCheckpoints(5).then(setCps).catch(() => setCps([]));
  };
  useEffect(load, [rev]);

  const fmt = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString(i18n.language) : "—");

  async function act(fn: () => Promise<unknown>, ok: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await fn();
      setNotice(ok);
      load();
    } catch (e) {
      setError(errorMessage(e, t, t("audit.tsa_failed")));
    } finally {
      setBusy(false);
    }
  }

  function download(cp: CheckpointT) {
    const blob = new Blob([JSON.stringify(cp, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `checkpoint-${cp.org_id}-${cp.tree_size}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  if (!st) return null;
  return (
    <div className="panel u-mb-16">
      <div className="panel-header"><h2>{t("audit.tsa_title")}</h2></div>
      <div className="panel-body">
        <p className="hint-text">{t("audit.tsa_hint")}</p>
        {st.enabled ? (
          <div className="ag-small u-mb-12">
            <span className="pill pill-low">{t("audit.tsa_on")}</span> <code className="mono">{st.url}</code>
            <div className="hint-text">{t("audit.tsa_trust")}: {st.trust_subjects.join("; ")}</div>
            {st.last_error && (
              <div className="error-text">{t("audit.tsa_last_error", { time: fmt(st.last_error_at) })}: {st.last_error}</div>
            )}
          </div>
        ) : (
          <p className="hint-text"><span className="pill pill-neutral">{t("audit.tsa_off")}</span></p>
        )}
        {error && <p className="error-text">{error}</p>}
        {notice && <p className="hint-text">{notice}</p>}

        {isAdmin && !editing && (
          <div className="u-btn-row u-mb-12">
            <button className="btn btn-sm" onClick={() => setEditing(true)}>{st.enabled ? t("audit.tsa_change") : t("audit.tsa_setup")}</button>
            {st.enabled && (
              <button className="btn btn-sm" disabled={busy} onClick={() => act(stampNow, t("audit.tsa_stamped"))}>
                {t("audit.tsa_stamp_now")}
              </button>
            )}
          </div>
        )}
        {isAdmin && editing && (
          <div className="ag-stack u-mb-12">
            <div className="field">
              <label htmlFor="tsa-url">{t("audit.tsa_url")}</label>
              <input id="tsa-url" className="mono" value={url} placeholder="https://freetsa.org/tsr" onChange={(e) => setUrl(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="tsa-pem">{t("audit.tsa_pem")}</label>
              <textarea id="tsa-pem" className="mono" rows={5} style={{ fontSize: 11 }} value={pem}
                placeholder="-----BEGIN CERTIFICATE-----" onChange={(e) => setPem(e.target.value)} />
              <p className="hint-text">{t("audit.tsa_pem_hint")}</p>
            </div>
            <div className="u-btn-row">
              <button className="btn btn-sm btn-primary" disabled={busy || !url.trim() || !pem.trim()}
                onClick={() => act(async () => { await setTsa({ enabled: true, url: url.trim(), trust_pem: pem }); setEditing(false); setPem(""); },
                                   t("audit.tsa_saved"))}>
                {busy ? t("common.loading") : t("audit.tsa_save")}
              </button>
              {st.enabled && (
                <button className="btn btn-sm btn-danger" disabled={busy}
                  onClick={() => act(async () => { await setTsa({ enabled: false, url: st.url ?? url, trust_pem: pem.trim() || undefined }); setEditing(false); },
                                     t("audit.tsa_saved"))}>
                  {t("audit.tsa_disable")}
                </button>
              )}
              <button className="btn btn-sm" onClick={() => setEditing(false)}>{t("common.cancel")}</button>
            </div>
          </div>
        )}

        {cps.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>{t("audit.tsa_col_checkpoint")}</th>
                <th>{t("audit.tsa_col_stamped")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {cps.map((cp) => (
                <tr key={cp.tree_size}>
                  <td className="mono" style={{ fontSize: 12 }}>{cp.tree_size} · {cp.root_hash.slice(0, 12)}…</td>
                  <td style={{ fontSize: 12 }}>
                    {cp.timestamps?.length
                      ? cp.timestamps.map((s) => <div key={s.tsa_url}>{fmt(s.gen_time)} <span className="hint-text">#{s.serial}</span></div>)
                      : <span className="hint-text">{t("audit.tsa_not_yet")}</span>}
                  </td>
                  <td><button className="btn btn-sm" onClick={() => download(cp)}>{t("audit.tsa_download")}</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="hint-text ag-small" style={{ marginTop: 8 }}>
          <code className="mono">python tools/provenza_audit.py checkpoint checkpoint.json --tsa-ca tsa.pem</code>
        </p>
      </div>
    </div>
  );
}
