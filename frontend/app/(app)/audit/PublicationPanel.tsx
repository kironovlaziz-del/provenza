"use client";

// Publication of the audit log outside the server (backend
// app/services/audit_publish.py): every interval the latest checkpoint goes
// to each target switched on - Sigstore Rekor by default. Each target is
// outbound traffic to the host shown here, and can be switched off.

import React, { useEffect, useState } from "react";
import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import { errorMessage } from "@/lib/errors";
import {
  getPublication, publishNow, setPublication, type PublicationSettingsT, type PublicationTargetT,
} from "@/lib/audit_api";

const PRESETS = [5, 15, 30, 60, 180, 360, 720, 1440];

export function every(t: TFunction, minutes: number): string {
  return minutes % 60 === 0
    ? t("audit.pub_every_hours", { count: minutes / 60 })
    : t("audit.pub_every_minutes", { count: minutes });
}

export function PublicationPanel({ isAdmin, rev }: { isAdmin: boolean; rev?: unknown }) {
  const { t, i18n } = useTranslation();
  const [st, setSt] = useState<PublicationSettingsT | null>(null);
  const [editing, setEditing] = useState(false);
  const [minutes, setMinutes] = useState(60);
  const [rekorOn, setRekorOn] = useState(true);
  const [customUrl, setCustomUrl] = useState("");
  const [customPem, setCustomPem] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const rekorOf = (s: PublicationSettingsT | null) => s?.targets.find((x) => x.target === "rekor");

  const show = (s: PublicationSettingsT) => {
    setSt(s);
    setMinutes(s.interval_minutes);
    const r = rekorOf(s);
    setRekorOn(!!r?.enabled);
    setCustomUrl(r && !r.public_instance ? r.destination ?? "" : "");
  };
  const load = () => { getPublication().then(show).catch(() => setSt(null)); };
  useEffect(load, [rev]); // eslint-disable-line react-hooks/exhaustive-deps

  const fmt = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString(i18n.language) : "—");

  async function act(fn: () => Promise<PublicationSettingsT>, ok: (s: PublicationSettingsT) => string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const s = await fn();
      show(s);
      setNotice(ok(s));
    } catch (e) {
      setError(errorMessage(e, t, t("audit.pub_failed")));
    } finally {
      setBusy(false);
    }
  }

  function save() {
    const custom = customUrl.trim();
    return act(async () => {
      const s = await setPublication({
        interval_minutes: minutes,
        rekor_enabled: rekorOn,
        rekor_url: custom || null,
        rekor_public_key: custom ? customPem.trim() || null : null,
      });
      setEditing(false);
      setCustomPem("");
      return s;
    }, () => t("audit.pub_saved"));
  }

  if (!st) return null;
  const presets = PRESETS.includes(st.interval_minutes) ? PRESETS : [...PRESETS, st.interval_minutes].sort((a, b) => a - b);
  // S3 appears once it is set up
  const shown = st.targets.filter((x) => x.target === "rekor" || x.configured);

  return (
    <div className="panel u-mb-16" id="publication">
      <div className="panel-header"><h2>{t("audit.pub_title")}</h2></div>
      <div className="panel-body">
        <p className="hint-text">{t("audit.pub_hint")}</p>
        <p className="ag-small u-mb-12">
          {shown.some((x) => x.enabled)
            ? <>{every(t, st.interval_minutes)} · {t("audit.pub_count", { count: st.publications })}</>
            : <span className="pill pill-neutral">{t("audit.pub_all_off")}</span>}
        </p>

        <table className="u-mb-12">
          <thead>
            <tr>
              <th>{t("audit.pub_col_target")}</th>
              <th>{t("audit.pub_col_outbound")}</th>
              <th>{t("audit.pub_col_last")}</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((x) => <TargetRow key={x.target} x={x} fmt={fmt} />)}
          </tbody>
        </table>

        {st.publishing_key && (
          <p className="hint-text ag-small" style={{ overflowWrap: "anywhere" }}>
            {t("audit.pub_key")}: <code className="mono">{st.publishing_key.fingerprint}</code>
          </p>
        )}
        {error && <p className="error-text">{error}</p>}
        {notice && <p className="hint-text">{notice}</p>}

        {isAdmin && !editing && (
          <div className="u-btn-row">
            <button className="btn btn-sm" onClick={() => setEditing(true)}>{t("audit.pub_change")}</button>
            {shown.some((x) => x.enabled) && (
              <button className="btn btn-sm" disabled={busy}
                onClick={() => act(publishNow, (s) => {
                  const states = Object.values(s.result ?? {});
                  if (states.includes("failed")) return t("audit.pub_run_failed");
                  return states.includes("published") ? t("audit.pub_run_done") : t("audit.pub_run_nothing");
                })}>
                {t("audit.pub_run")}
              </button>
            )}
          </div>
        )}
        {isAdmin && editing && (
          <div style={{ display: "grid", gap: 12 }}>
            <div className="field" style={{ margin: 0, maxWidth: 260 }}>
              <label htmlFor="pub-interval">{t("audit.pub_interval")}</label>
              <select id="pub-interval" value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
                {presets.map((m) => <option key={m} value={m}>{every(t, m)}</option>)}
              </select>
            </div>
            <label style={{ display: "flex", gap: 8, alignItems: "flex-start", fontWeight: 400 }}>
              <input type="checkbox" checked={rekorOn} onChange={(e) => setRekorOn(e.target.checked)}
                style={{ width: "auto", marginTop: 3 }} />
              <span>
                {t("audit.pub_rekor_on")}
                <span className="hint-text" style={{ display: "block", fontSize: 12 }}>{t("audit.pub_rekor_on_hint")}</span>
              </span>
            </label>
            <details>
              <summary className="hint-text" style={{ cursor: "pointer" }}>{t("audit.pub_rekor_other")}</summary>
              <div style={{ display: "grid", gap: 10, marginTop: 10 }}>
                <div className="field" style={{ margin: 0 }}>
                  <label htmlFor="pub-rekor-url">{t("audit.pub_rekor_url")}</label>
                  <input id="pub-rekor-url" className="mono" value={customUrl} placeholder="https://rekor.example.com"
                    onChange={(e) => setCustomUrl(e.target.value)} />
                </div>
                <div className="field" style={{ margin: 0 }}>
                  <label htmlFor="pub-rekor-pem">{t("audit.pub_rekor_pem")}</label>
                  <textarea id="pub-rekor-pem" className="mono" rows={4} style={{ fontSize: 11 }} value={customPem}
                    placeholder="-----BEGIN PUBLIC KEY-----" onChange={(e) => setCustomPem(e.target.value)} />
                  <p className="hint-text">{t("audit.pub_rekor_pem_hint")}</p>
                </div>
              </div>
            </details>
            <div className="u-btn-row">
              <button className="btn btn-sm btn-primary" disabled={busy} onClick={() => save()}>
                {busy ? t("common.loading") : t("audit.pub_save")}
              </button>
              <button className="btn btn-sm" onClick={() => { setEditing(false); if (st) show(st); }}>{t("common.cancel")}</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function TargetRow({ x, fmt }: { x: PublicationTargetT; fmt: (iso: string | null | undefined) => string }) {
  const { t } = useTranslation();
  return (
    <tr>
      <td>
        <strong>{t(`audit.pub_target_${x.target}`)}</strong>{" "}
        <span className={`pill ${x.enabled ? "pill-low" : "pill-neutral"}`}>
          {x.enabled ? t("audit.pub_on") : t("audit.pub_off")}
        </span>
      </td>
      <td className="mono" style={{ fontSize: 12, overflowWrap: "anywhere" }}>
        {x.host ? <>→ {x.host}</> : "—"}
      </td>
      <td style={{ fontSize: 12 }}>
        {x.last_published_at ? (
          <>
            {fmt(x.last_published_at)}{" "}
            <span className="hint-text">· {t("audit.pub_records", { count: x.last_tree_size ?? 0 })}</span>
            {x.last_location && /^https:\/\//.test(x.last_location) && (
              <> · <a href={x.last_location} target="_blank" rel="noopener noreferrer">{t("audit.pub_view")}</a></>
            )}
          </>
        ) : (
          <span className="hint-text">{t("audit.pub_never")}</span>
        )}
        {x.last_error && (
          <div className="error-text">{t("audit.pub_last_error", { time: fmt(x.last_error_at) })}: {x.last_error}</div>
        )}
      </td>
    </tr>
  );
}
