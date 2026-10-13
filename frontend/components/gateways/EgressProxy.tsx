"use client";

// Egress proxy (proxy/ in the repository): agents reach external APIs only
// through a proxy that holds the credentials. Routes say what may be reached
// and with which credential; proxies are the deployed instances (a key each);
// an open redemption is a request a proxy forwarded and never reported back.

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useDialog } from "@/components/Dialog";
import { Form } from "@/components/Form";
import { EgressLockdown } from "@/components/gateways/EgressLockdown";
import { errorMessage } from "@/lib/errors";
import {
  createEgressProxy,
  createEgressRoute,
  CredentialSource,
  deleteEgressRoute,
  EGRESS_METHODS,
  EgressProxy as Proxy,
  EgressRedemption,
  EgressRoute,
  listEgressProxies,
  listEgressRedemptions,
  listEgressRoutes,
  revokeEgressProxy,
  updateEgressRoute,
} from "@/lib/gateways_api";

const EMPTY = {
  slug: "", name: "", upstream_url: "", methods: ["GET", "POST"] as string[], prefixes: "/",
  credential_source: "server" as CredentialSource, auth_header: "Authorization", secret: "", max_mb: 8,
};

function lines(text: string) {
  return text.split("\n").map((l) => l.trim()).filter(Boolean);
}

function Routes() {
  const { t } = useTranslation();
  const { dialog, confirm } = useDialog();
  const [routes, setRoutes] = useState<EgressRoute[]>([]);
  const [form, setForm] = useState(EMPTY);
  const [showForm, setShowForm] = useState(false);
  const [busy, setBusy] = useState<number | "new" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => listEgressRoutes().then(setRoutes);
  useEffect(() => { refresh(); }, []);

  async function act(id: number | "new", fn: () => Promise<unknown>) {
    setBusy(id);
    setError(null);
    try {
      await fn();
      await refresh();
    } catch (e) {
      setError(errorMessage(e, t, t("gw.failed")));
    } finally {
      setBusy(null);
    }
  }

  const toggleMethod = (m: string) =>
    setForm({ ...form, methods: form.methods.includes(m) ? form.methods.filter((x) => x !== m) : [...form.methods, m] });

  return (
    <div className="panel u-mb-16">
      {dialog}
      <div className="panel-header u-flex u-justify-between u-items-center">
        <h2>{t("gw.egress.routes")}</h2>
        <button className="btn btn-primary btn-sm" onClick={() => setShowForm((v) => !v)}>
          {showForm ? t("common.cancel") : t("gw.egress.add_route")}
        </button>
      </div>
      <div className="panel-body">
        <p className="hint-text">{t("gw.egress.routes_hint")}</p>
        {showForm && (
          <Form onSubmit={(e) => {
            e.preventDefault();
            act("new", async () => {
              await createEgressRoute({
                slug: form.slug, name: form.name, upstream_url: form.upstream_url, methods: form.methods,
                path_prefixes: lines(form.prefixes), credential_source: form.credential_source,
                auth_header: form.auth_header, max_body_bytes: Math.round(form.max_mb * 1024 * 1024),
                ...(form.credential_source === "server" && form.secret ? { secret: form.secret } : {}),
              });
              setForm(EMPTY);
              setShowForm(false);
            });
          }}>
            <div className="form-row">
              <div className="field">
                <label htmlFor="eg-name">{t("gw.name")}</label>
                <input id="eg-name" required maxLength={255} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
              </div>
              <div className="field">
                <label htmlFor="eg-slug">{t("gw.slug")}</label>
                <input id="eg-slug" required pattern="[a-z0-9][a-z0-9-]{0,39}" value={form.slug} placeholder="stripe"
                       onChange={(e) => setForm({ ...form, slug: e.target.value })} />
              </div>
              <div className="field" style={{ flex: 2 }}>
                <label htmlFor="eg-upstream">{t("gw.egress.upstream")}</label>
                <input id="eg-upstream" required type="url" maxLength={500} value={form.upstream_url} placeholder="https://api.stripe.com"
                       onChange={(e) => setForm({ ...form, upstream_url: e.target.value })} />
              </div>
            </div>
            <div className="field">
              <label>{t("gw.egress.methods")}</label>
              <div className="u-row-tight">
                {EGRESS_METHODS.map((m) => (
                  <label key={m} className="u-flex u-items-center u-gap-4">
                    <input type="checkbox" style={{ width: "auto" }} checked={form.methods.includes(m)} onChange={() => toggleMethod(m)} />
                    <span className="u-mono">{m}</span>
                  </label>
                ))}
              </div>
            </div>
            <div className="form-row">
              <div className="field">
                <label htmlFor="eg-prefixes">{t("gw.egress.prefixes")}</label>
                <textarea id="eg-prefixes" rows={3} value={form.prefixes} placeholder={"/v1/charges\n/v1/customers"}
                          onChange={(e) => setForm({ ...form, prefixes: e.target.value })} />
                <p className="hint-text">{t("gw.egress.prefixes_hint")}</p>
              </div>
              <div className="field">
                <label htmlFor="eg-source">{t("gw.egress.credential")}</label>
                <select id="eg-source" value={form.credential_source}
                        onChange={(e) => setForm({ ...form, credential_source: e.target.value as CredentialSource })}>
                  {(["server", "local", "none"] as CredentialSource[]).map((c) => (
                    <option key={c} value={c}>{t(`gw.egress.cred_${c}`)}</option>
                  ))}
                </select>
                <p className="hint-text">{t(`gw.egress.cred_${form.credential_source}_hint`)}</p>
              </div>
            </div>
            {form.credential_source !== "none" && (
              <div className="form-row">
                <div className="field">
                  <label htmlFor="eg-header">{t("gw.auth_header")}</label>
                  <input id="eg-header" maxLength={100} value={form.auth_header} onChange={(e) => setForm({ ...form, auth_header: e.target.value })} />
                </div>
                {form.credential_source === "server" && (
                  <div className="field">
                    <label htmlFor="eg-secret">{t("gw.secret")}</label>
                    <input id="eg-secret" type="password" autoComplete="new-password" maxLength={8000} value={form.secret}
                           placeholder={t("gw.secret_placeholder")} onChange={(e) => setForm({ ...form, secret: e.target.value })} />
                  </div>
                )}
                <div className="field" style={{ maxWidth: 160 }}>
                  <label htmlFor="eg-body">{t("gw.egress.max_body")}</label>
                  <input id="eg-body" type="number" min={0} max={64} step={1} value={form.max_mb}
                         onChange={(e) => setForm({ ...form, max_mb: Number(e.target.value) })} />
                </div>
              </div>
            )}
            <button className="btn btn-primary" type="submit" disabled={busy === "new" || form.methods.length === 0}>
              {busy === "new" ? t("common.loading") : t("common.create")}
            </button>
          </Form>
        )}
        {error && <p className="error-text">{error}</p>}
      </div>
      <table>
        <thead>
          <tr>
            <th>{t("gw.name")}</th>
            <th>{t("gw.egress.upstream")}</th>
            <th>{t("gw.egress.allowed")}</th>
            <th>{t("gw.egress.credential")}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {routes.length === 0 && <tr className="empty-row"><td colSpan={5}>{t("gw.egress.no_routes")}</td></tr>}
          {routes.map((r) => (
            <tr key={r.id} style={r.enabled ? undefined : { opacity: 0.6 }}>
              <td>
                <strong>{r.name}</strong>
                <div className="hint-text u-mono">{r.tool_name}</div>
              </td>
              <td className="u-mono" style={{ wordBreak: "break-all" }}>{r.upstream_url}</td>
              <td className="u-mono">
                <div>{r.methods.join(" ")}</div>
                <div className="hint-text">{r.path_prefixes.join(", ")}</div>
              </td>
              <td>
                {t(`gw.egress.cred_${r.credential_source}`)}
                {r.credential_source === "server" && (
                  <div className="hint-text">{r.has_secret ? t("gw.has_secret") : t("gw.egress.no_secret")}</div>
                )}
              </td>
              <td className="u-nowrap">
                <div className="u-btn-row">
                  <button className="btn btn-sm" disabled={busy === r.id}
                          onClick={() => act(r.id, () => updateEgressRoute(r.id, { enabled: !r.enabled }))}>
                    {r.enabled ? t("gw.disable") : t("gw.enable")}
                  </button>
                  <button className="btn btn-sm btn-danger" disabled={busy === r.id}
                          onClick={async () => {
                            if (await confirm(t("gw.confirm_delete", { name: r.name }), { danger: true })) {
                              act(r.id, () => deleteEgressRoute(r.id));
                            }
                          }}>
                    {t("common.delete")}
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Proxies() {
  const { t, i18n } = useTranslation();
  const { dialog, confirm } = useDialog();
  const [proxies, setProxies] = useState<Proxy[]>([]);
  const [name, setName] = useState("");
  const [revealed, setRevealed] = useState<string | null>(null); // the key exists only here, once
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => listEgressProxies().then(setProxies);
  useEffect(() => { refresh(); }, []);

  return (
    <div className="panel u-mb-16">
      {dialog}
      <div className="panel-header"><h2>{t("gw.egress.proxies")}</h2></div>
      <div className="panel-body">
        <p className="hint-text">{t("gw.egress.proxies_hint")}</p>
        {revealed && (
          <div className="panel u-mb-12" style={{ borderColor: "var(--risk-critical)" }}>
            <div className="panel-body">
              <p className="error-text">{t("gw.key_once")}</p>
              <code className="u-mono" style={{ wordBreak: "break-all" }}>{revealed}</code>
              <div className="u-btn-row u-mt-8">
                <button className="btn btn-sm" onClick={() => navigator.clipboard?.writeText(revealed).catch(() => undefined)}>
                  {t("gw.copy")}
                </button>
                <button className="btn btn-sm" onClick={() => setRevealed(null)}>{t("gw.saved_it")}</button>
              </div>
            </div>
          </div>
        )}
        <Form onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            const created = await createEgressProxy(name);
            setRevealed(created.key);
            setName("");
            refresh();
          } catch (err) {
            setError(errorMessage(err, t, t("gw.failed")));
          } finally {
            setBusy(false);
          }
        }}>
          <div className="form-row" style={{ alignItems: "flex-end" }}>
            <div className="field">
              <label htmlFor="px-name">{t("gw.name")}</label>
              <input id="px-name" required maxLength={255} value={name} placeholder="billing-host"
                     onChange={(e) => setName(e.target.value)} />
            </div>
            <button className="btn btn-primary" type="submit" disabled={busy}>{t("gw.egress.new_proxy")}</button>
          </div>
        </Form>
        {error && <p className="error-text">{error}</p>}
      </div>
      <table>
        <thead>
          <tr>
            <th>{t("gw.name")}</th>
            <th>{t("gw.egress.key")}</th>
            <th>{t("gw.status")}</th>
            <th>{t("gw.egress.last_seen")}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {proxies.length === 0 && <tr className="empty-row"><td colSpan={5}>{t("gw.egress.no_proxies")}</td></tr>}
          {proxies.map((p) => (
            <tr key={p.id}>
              <td>{p.name}</td>
              <td className="u-mono">{p.key_prefix}…</td>
              <td>
                <span className={`pill ${p.enabled ? "pill-low" : "pill-neutral"}`}>
                  {p.enabled ? t("gw.enabled") : t("gw.egress.revoked")}
                </span>
              </td>
              <td className="u-mono u-nowrap">{p.last_seen_at ? new Date(p.last_seen_at).toLocaleString(i18n.language) : t("gw.never")}</td>
              <td>
                {p.enabled && (
                  <button className="btn btn-sm btn-danger"
                          onClick={async () => {
                            if (await confirm(t("gw.egress.confirm_revoke", { name: p.name }), { danger: true })) {
                              await revokeEgressProxy(p.id);
                              refresh();
                            }
                          }}>
                    {t("gw.egress.revoke")}
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function OpenRedemptions() {
  const { t, i18n } = useTranslation();
  const [rows, setRows] = useState<EgressRedemption[] | null>(null);
  useEffect(() => { listEgressRedemptions(true).then(setRows).catch(() => setRows([])); }, []);
  return (
    <div className="panel">
      <div className="panel-header"><h2>{t("gw.egress.open")}</h2></div>
      <div className="panel-body"><p className="hint-text">{t("gw.egress.open_hint")}</p></div>
      <table>
        <thead>
          <tr>
            <th>{t("gw.egress.reserved")}</th>
            <th>{t("gw.egress.request")}</th>
            <th>{t("gw.egress.agent")}</th>
            <th>{t("gw.egress.proxy")}</th>
          </tr>
        </thead>
        <tbody>
          {rows === null && <tr className="empty-row"><td colSpan={4}>{t("common.loading")}</td></tr>}
          {rows?.length === 0 && <tr className="empty-row"><td colSpan={4}>{t("gw.egress.none_open")}</td></tr>}
          {rows?.map((r) => (
            <tr key={r.id}>
              <td className="u-mono u-nowrap">{new Date(r.reserved_at).toLocaleString(i18n.language)}</td>
              <td className="u-mono">
                {String(r.descriptor.method ?? "")} {String(r.descriptor.route ?? "")}{String(r.descriptor.path ?? "")}
              </td>
              <td>#{r.agent_id}</td>
              <td>#{r.proxy_id}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function EgressProxy() {
  const { t } = useTranslation();
  return (
    <>
      <p className="hint-text u-mb-16">{t("gw.egress.hint")}</p>
      <EgressLockdown />
      <Routes />
      <Proxies />
      <OpenRedemptions />
    </>
  );
}
