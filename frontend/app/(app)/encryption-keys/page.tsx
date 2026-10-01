"use client";

import React, { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import {
  byokError,
  checkKey,
  disableByok,
  getByok,
  newKey,
  retryJob,
  shredKeys,
  type ByokOverview,
  type KeyConfig,
  type KeyProvider,
} from "@/lib/byok_api";

const STATUS_PILL: Record<string, string> = { active: "pill-low", retired: "pill-neutral", shredded: "pill-critical" };
const JOB_PILL: Record<string, string> = { done: "pill-low", running: "pill-medium", queued: "pill-neutral", failed: "pill-critical" };
const PROVIDERS: KeyProvider[] = ["local", "vault_transit", "aws_kms"];

export default function EncryptionKeysPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [data, setData] = useState<ByokOverview | null>(null);
  const [cfg, setCfg] = useState<KeyConfig>({ provider: "local", mount: "transit" });
  const [shredWord, setShredWord] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    getByok()
      .then(setData)
      .catch((e) => setError(byokError(e, t("byok.load_failed", "Could not load encryption keys."))));
  }, [t]);

  useEffect(load, [load]);

  async function run(action: () => Promise<any>, ok: (r: any) => string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const r = await action();
      setNotice(ok(r));
      load();
    } catch (e) {
      setError(byokError(e, t("byok.failed", "The operation failed.")));
    } finally {
      setBusy(false);
    }
  }

  const jobMsg = (r: any) =>
    r.inline
      ? `${t("byok.reencrypted", "Re-encrypted")}: ${r.done}${r.failed ? `, ${t("byok.failed_rows", "failed")}: ${r.failed}` : ""}`
      : t("byok.queued", "Re-encryption runs in the background; refresh to follow it.");

  const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "—");
  const set = (k: keyof KeyConfig) => (e: React.ChangeEvent<HTMLInputElement>) => setCfg({ ...cfg, [k]: e.target.value });

  if (!data) {
    return (
      <>
        <PageHeader title={t("byok.title", "Encryption Keys")} />
        <div className="content"><div className="hint-text">{error ?? t("common.loading", "Loading…")}</div></div>
      </>
    );
  }

  const active = data.keys.find((k) => k.status === "active");
  const missing =
    (cfg.provider === "vault_transit" && (!cfg.addr || !cfg.key_name || !cfg.token)) ||
    (cfg.provider === "aws_kms" && (!cfg.region || !cfg.key_id || !!cfg.access_key_id !== !!cfg.secret_access_key));

  return (
    <>
      <PageHeader title={t("byok.title", "Encryption Keys")} />
      <div className="content">
        <p className="hint-text" style={{ marginTop: 0 }}>
          {t(
            "byok.hint",
            "Connection keys, raw prompts and directory passwords are encrypted. With BYOK the organization gets its own data key, wrapped by a key you control - the server master key, your HashiCorp Vault or your AWS KMS. Revoke it on your side and Provenza can no longer read the data within 5 minutes; shred it here and nobody can.",
          )}
        </p>
        {error && <div className="panel" style={{ marginBottom: 16, borderColor: "#ef4444" }}><div className="panel-body" style={{ color: "#ef4444" }}>{error}</div></div>}
        {notice && <div className="hint-text" style={{ marginBottom: 16 }}>{notice}</div>}

        {/* ---- status ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <h2>
              {data.enabled ? `🔐 ${t("byok.enabled", "Organization key active")}` : t("byok.disabled", "Server key (BYOK off)")}
            </h2>
            {isAdmin && active && (
              <div style={{ display: "flex", gap: 8 }}>
                <button className="btn btn-sm" disabled={busy}
                  onClick={() => run(checkKey, (r) => (r.ok ? t("byok.check_ok", "The key provider answered correctly.") : `${t("byok.check_fail", "Check failed")}: ${r.error}`))}>
                  {t("byok.check", "Check key")}
                </button>
                <button className="btn btn-sm" disabled={busy}
                  onClick={() => {
                    if (window.confirm(t("byok.confirm_disable", "Turn BYOK off? All secrets are re-encrypted with the server key; the organization keys are retired.")))
                      run(disableByok, jobMsg);
                  }}>
                  {t("byok.disable", "Turn off")}
                </button>
              </div>
            )}
          </div>
          <div className="panel-body" style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>{t("byok.col_data", "Data")}</th>
                  <th>{t("byok.col_total", "Encrypted values")}</th>
                  <th>{t("byok.col_active", "On the active key")}</th>
                  <th>{t("byok.col_older", "On older keys")}</th>
                  <th>{t("byok.col_server", "On the server key")}</th>
                </tr>
              </thead>
              <tbody>
                {data.data.map((d) => (
                  <tr key={d.table}>
                    <td>{t(`byok.table_${d.table}`, d.table)}</td>
                    <td>{d.total}</td>
                    <td>{d.active_key}</td>
                    <td style={d.older_keys ? { color: "#f59e0b" } : undefined}>{d.older_keys}</td>
                    <td style={data.enabled && d.server_key ? { color: "#f59e0b" } : undefined}>{d.server_key}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* ---- keys ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header"><h2>{t("byok.keys_title", "Keys")}</h2></div>
          <div className="panel-body" style={{ maxHeight: 360, overflowY: "auto", overflowX: "auto" }}>
            {data.keys.length === 0 ? (
              <p className="hint-text" style={{ margin: 0 }}>{t("byok.no_keys", "No organization key yet.")}</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>{t("byok.col_version", "Version")}</th>
                    <th>{t("byok.col_provider", "Key encryption key")}</th>
                    <th>{t("byok.col_status", "Status")}</th>
                    <th>{t("byok.col_check", "Last check")}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.keys.map((k) => (
                    <tr key={k.id}>
                      <td>v{k.version}<div className="hint-text" style={{ fontSize: 11 }}>{fmt(k.created_at)}</div></td>
                      <td>
                        {t(`byok.provider_${k.provider}`, k.provider)}
                        <div className="hint-text mono" style={{ fontSize: 11 }}>
                          {Object.entries(k.config).map(([a, b]) => `${a}=${b}`).join(" · ")}
                          {k.has_secret ? " · 🔒" : ""}
                        </div>
                      </td>
                      <td><span className={`pill ${STATUS_PILL[k.status]}`}>{t(`byok.status_${k.status}`, k.status)}</span></td>
                      <td style={{ fontSize: 12 }}>
                        {k.last_check_ok == null ? "—" : k.last_check_ok ? `✔ ${fmt(k.last_check_at)}` : <span style={{ color: "#ef4444" }}>✖ {k.last_error}</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* ---- new key ---- */}
        {isAdmin && (
          <div className="panel" style={{ marginBottom: 20 }}>
            <div className="panel-header"><h2>{data.enabled ? t("byok.rotate_title", "Rotate the key") : t("byok.enable_title", "Enable BYOK")}</h2></div>
            <div className="panel-body">
              <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 12 }}>
                {PROVIDERS.map((p) => (
                  <label key={p} style={{ display: "flex", gap: 10, alignItems: "flex-start", opacity: p === "aws_kms" && !data.aws_available ? 0.5 : 1 }}>
                    <input type="radio" name="kek" checked={cfg.provider === p} disabled={p === "aws_kms" && !data.aws_available}
                      onChange={() => setCfg({ provider: p, mount: "transit" })} style={{ width: "auto", marginTop: 3 }} />
                    <span>
                      <strong>{t(`byok.provider_${p}`, p)}</strong>
                      <span className="hint-text" style={{ display: "block", fontSize: 12 }}>
                        {p === "aws_kms" && !data.aws_available ? t("byok.aws_missing", "Needs boto3 on the server (pip install boto3).") : t(`byok.provider_${p}_hint`, "")}
                      </span>
                    </span>
                  </label>
                ))}
              </div>
              {cfg.provider === "vault_transit" && (
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 10 }}>
                  <input placeholder="https://vault.example.com:8200" value={cfg.addr ?? ""} onChange={set("addr")} />
                  <input placeholder={t("byok.mount", "mount (transit)")} value={cfg.mount ?? ""} onChange={set("mount")} />
                  <input placeholder={t("byok.key_name", "key name")} value={cfg.key_name ?? ""} onChange={set("key_name")} />
                  <input placeholder={t("byok.token", "token")} type="password" autoComplete="off" value={cfg.token ?? ""} onChange={set("token")} />
                  <input placeholder={t("byok.namespace", "namespace (optional)")} value={cfg.namespace ?? ""} onChange={set("namespace")} />
                </div>
              )}
              {cfg.provider === "aws_kms" && (
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 10 }}>
                  <input placeholder="eu-central-1" value={cfg.region ?? ""} onChange={set("region")} />
                  <input placeholder="arn:aws:kms:… / alias/…" value={cfg.key_id ?? ""} onChange={set("key_id")} />
                  <input placeholder={t("byok.access_key_id", "access key id (optional)")} autoComplete="off" value={cfg.access_key_id ?? ""} onChange={set("access_key_id")} />
                  <input placeholder={t("byok.secret_access_key", "secret access key (optional)")} type="password" autoComplete="off" value={cfg.secret_access_key ?? ""} onChange={set("secret_access_key")} />
                </div>
              )}
              <div className="hint-text" style={{ fontSize: 12, marginTop: 10 }}>
                {t("byok.new_key_hint", "A new data key is created, wrapped and unwrapped once to prove the key provider works, then every existing secret of the organization is re-encrypted with it. Secrets are stored encrypted; they are never shown again.")}
              </div>
              <button className="btn btn-primary btn-sm" style={{ marginTop: 10 }} disabled={busy || missing}
                onClick={() => {
                  const msg = data.enabled
                    ? t("byok.confirm_rotate", "Create a new data key and re-encrypt all secrets with it? The current key is retired but stays readable.")
                    : t("byok.confirm_enable", "Enable BYOK and re-encrypt all secrets of the organization with its own key?");
                  if (window.confirm(msg)) run(() => newKey(cfg), jobMsg);
                }}>
                {data.enabled ? t("byok.rotate", "Rotate") : t("byok.enable", "Enable")}
              </button>
            </div>
          </div>
        )}

        {/* ---- jobs ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header"><h2>{t("byok.jobs_title", "Re-encryption runs")}</h2></div>
          <div className="panel-body" style={{ maxHeight: 300, overflowY: "auto", overflowX: "auto" }}>
            {data.jobs.length === 0 ? (
              <p className="hint-text" style={{ margin: 0 }}>{t("byok.no_jobs", "None yet.")}</p>
            ) : (
              <table>
                <tbody>
                  {data.jobs.map((j) => (
                    <tr key={j.id}>
                      <td style={{ fontSize: 12, whiteSpace: "nowrap" }}>{fmt(j.created_at)}</td>
                      <td>{t(`byok.kind_${j.kind}`, j.kind)}</td>
                      <td><span className={`pill ${JOB_PILL[j.status]}`}>{t(`byok.job_${j.status}`, j.status)}</span></td>
                      <td style={{ fontSize: 12 }}>
                        {j.done}/{j.total}{j.failed ? ` · ${t("byok.failed_rows", "failed")} ${j.failed}` : ""}
                        {j.error && <div className="hint-text mono" style={{ fontSize: 11 }}>{j.error}</div>}
                      </td>
                      <td>
                        {isAdmin && j.status === "failed" && (
                          <button className="btn btn-sm" disabled={busy} onClick={() => run(() => retryJob(j.id), jobMsg)}>
                            {t("byok.retry", "Retry")}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* ---- shred ---- */}
        {isAdmin && data.keys.some((k) => k.status !== "shredded") && (
          <div className="panel" style={{ borderColor: "#ef4444" }}>
            <div className="panel-header"><h2 style={{ color: "#ef4444" }}>{t("byok.shred_title", "Crypto-shredding")}</h2></div>
            <div className="panel-body">
              <p className="hint-text" style={{ marginTop: 0 }}>
                {t("byok.shred_hint", "Wipes every wrapped data key of the organization. Everything encrypted with them - connection keys, raw prompts, directory passwords - becomes unreadable for good. Values still on the server key are not affected. This cannot be undone.")}
              </p>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <input placeholder={t("byok.type_shred", 'type "SHRED"')} value={shredWord} onChange={(e) => setShredWord(e.target.value)} style={{ width: 180 }} />
                <button className="btn btn-sm" style={{ background: "#ef4444", color: "#fff" }} disabled={busy || shredWord !== "SHRED"}
                  onClick={() => {
                    if (window.confirm(t("byok.confirm_shred", "Last chance: shred all organization keys? The data they protect will be lost permanently.")))
                      run(() => shredKeys(shredWord), () => { setShredWord(""); return t("byok.shredded", "Organization keys shredded."); });
                  }}>
                  {t("byok.shred", "Shred keys")}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
