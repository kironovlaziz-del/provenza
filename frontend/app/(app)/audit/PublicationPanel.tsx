"use client";

// Publication of the audit log outside the server (backend
// app/services/audit_publish.py): every interval the latest checkpoint goes
// to each target switched on - Sigstore Rekor by default, and an S3 bucket
// with Object Lock once an admin sets one up. Each target is outbound
// traffic to the host shown here, and can be switched off.

import React, { useEffect, useState } from "react";
import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import { errorMessage } from "@/lib/errors";
import {
  getPublication, publishNow, setPublication, setPublicationS3, type PublicationSettingsT, type PublicationTargetT,
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
  const [editingS3, setEditingS3] = useState(false);
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
  // S3 is listed for admins, who can set it up, and for everyone once it is
  const shown = st.targets.filter((x) => x.target === "rekor" || x.configured || isAdmin);
  const s3 = st.targets.find((x) => x.target === "s3");

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

        {isAdmin && !editing && !editingS3 && (
          <div className="u-btn-row">
            <button className="btn btn-sm" onClick={() => setEditing(true)}>{t("audit.pub_change")}</button>
            <button className="btn btn-sm" onClick={() => setEditingS3(true)}>
              {s3?.configured ? t("audit.pub_s3_change") : t("audit.pub_s3_setup")}
            </button>
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
        {isAdmin && editingS3 && s3 && (
          <S3Form x={s3} busy={busy} onCancel={() => setEditingS3(false)}
            onSave={(input) => act(async () => { const r = await setPublicationS3(input); setEditingS3(false); return r; },
                                   () => t("audit.pub_saved"))} />
        )}
      </div>
    </div>
  );
}

type S3Input = Parameters<typeof setPublicationS3>[0];

function S3Form({ x, busy, onSave, onCancel }: {
  x: PublicationTargetT; busy: boolean; onSave: (input: S3Input) => void; onCancel: () => void;
}) {
  const { t } = useTranslation();
  const cur = x.settings;
  const [endpoint, setEndpoint] = useState(cur?.endpoint ?? "");
  const [region, setRegion] = useState(cur?.region ?? "");
  const [bucket, setBucket] = useState(cur?.bucket ?? "");
  const [prefix, setPrefix] = useState(cur?.prefix ?? "provenza-audit/");
  const [accessKey, setAccessKey] = useState(cur?.access_key ?? "");
  const [secret, setSecret] = useState("");
  const [days, setDays] = useState(cur?.retention_days ?? 365);
  const input = (enabled: boolean): S3Input => ({
    enabled, endpoint: endpoint.trim() || null, region: region.trim(), bucket: bucket.trim(),
    prefix: prefix.trim(), access_key: accessKey.trim(), secret_key: secret.trim() || null, retention_days: days,
  });
  const ready = region.trim() && bucket.trim() && accessKey.trim() && (secret.trim() || cur);
  const field = (id: string, label: string, el: React.ReactNode, hint?: string) => (
    <div className="field" style={{ margin: 0 }}>
      <label htmlFor={id}>{label}</label>
      {el}
      {hint && <p className="hint-text">{hint}</p>}
    </div>
  );
  return (
    <div style={{ display: "grid", gap: 12 }}>
      <p className="hint-text" style={{ margin: 0 }}>{t("audit.pub_s3_hint")}</p>
      <div style={{ display: "grid", gap: 12, gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))" }}>
        {field("s3-endpoint", t("audit.pub_s3_endpoint"),
          <input id="s3-endpoint" className="mono" value={endpoint} placeholder="https://s3.eu-central-003.backblazeb2.com"
            onChange={(e) => setEndpoint(e.target.value)} />, t("audit.pub_s3_endpoint_hint"))}
        {field("s3-region", t("audit.pub_s3_region"),
          <input id="s3-region" className="mono" value={region} placeholder="eu-central-1" onChange={(e) => setRegion(e.target.value)} />)}
        {field("s3-bucket", t("audit.pub_s3_bucket"),
          <input id="s3-bucket" className="mono" value={bucket} onChange={(e) => setBucket(e.target.value)} />)}
        {field("s3-prefix", t("audit.pub_s3_prefix"),
          <input id="s3-prefix" className="mono" value={prefix} onChange={(e) => setPrefix(e.target.value)} />)}
        {field("s3-access", t("audit.pub_s3_access_key"),
          <input id="s3-access" className="mono" value={accessKey} autoComplete="off" onChange={(e) => setAccessKey(e.target.value)} />)}
        {field("s3-secret", t("audit.pub_s3_secret"),
          <input id="s3-secret" className="mono" type="password" value={secret} autoComplete="new-password"
            placeholder={cur ? t("audit.pub_s3_secret_kept") : ""} onChange={(e) => setSecret(e.target.value)} />)}
        {field("s3-days", t("audit.pub_s3_days"),
          <input id="s3-days" type="number" min={1} max={3650} value={days} onChange={(e) => setDays(Number(e.target.value))} />,
          t("audit.pub_s3_days_hint"))}
      </div>
      <div className="u-btn-row">
        <button className="btn btn-sm btn-primary" disabled={busy || !ready} onClick={() => onSave(input(true))}>
          {busy ? t("common.loading") : t("audit.pub_s3_save")}
        </button>
        {x.enabled && (
          <button className="btn btn-sm btn-danger" disabled={busy || !ready} onClick={() => onSave(input(false))}>
            {t("audit.pub_s3_off")}
          </button>
        )}
        <button className="btn btn-sm" onClick={onCancel}>{t("common.cancel")}</button>
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
          {x.enabled ? t("audit.pub_on") : x.configured ? t("audit.pub_off") : t("audit.pub_not_set_up")}
        </span>
        {x.target === "s3" && x.settings && (
          <div className="hint-text" style={{ fontSize: 12 }}>
            {t("audit.pub_s3_locked_for", { count: x.settings.retention_days })}
          </div>
        )}
      </td>
      <td className="mono" style={{ fontSize: 12, overflowWrap: "anywhere" }}>
        {x.host ? <>→ {x.host}{x.target === "s3" && x.destination ? <span className="hint-text"> ({x.destination})</span> : null}</> : "—"}
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
