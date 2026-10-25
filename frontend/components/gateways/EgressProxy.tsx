"use client";

// Egress proxy (proxy/ in the repository): agents reach external APIs only
// through a proxy that holds the credentials. Routes say what may be reached
// and with which credential; proxies are the deployed instances (a key each);
// an open redemption is a request a proxy forwarded and never reported back.

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useDialog } from "@/components/Dialog";
import { Form } from "@/components/Form";
import { SealedCredential, sealNew } from "@/components/gateways/SealedCredential";
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
  getKillSwitch,
  type KillSwitch,
  listEgressProxies,
  signKillSwitchLift,
  listEgressRedemptions,
  listEgressRoutes,
  revokeEgressProxy,
  updateEgressRoute,
} from "@/lib/gateways_api";
import { getLegacyCredentials, sealLegacyCredentials } from "@/lib/sealing";

const EMPTY = {
  slug: "", name: "", upstream_url: "", methods: ["GET", "POST"] as string[], prefixes: "/",
  credential_source: "sealed" as CredentialSource, auth_header: "Authorization", secret: "", max_mb: 8,
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
              const route = await createEgressRoute({
                slug: form.slug, name: form.name, upstream_url: form.upstream_url, methods: form.methods,
                path_prefixes: lines(form.prefixes), credential_source: form.credential_source,
                auth_header: form.auth_header, max_body_bytes: Math.round(form.max_mb * 1024 * 1024),
              });
              // sealed here, to the proxies' keys: the server never receives it in clear text
              if (form.credential_source === "sealed") await sealNew("route", route.id, form.secret);
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
                  {(["sealed", "local", "none"] as CredentialSource[]).map((c) => (
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
                {form.credential_source === "sealed" && (
                  <div className="field">
                    <label htmlFor="eg-secret">{t("gw.secret")}</label>
                    <input id="eg-secret" type="password" autoComplete="new-password" maxLength={8000} value={form.secret}
                           placeholder={t("sealed.placeholder", "Sealed in this browser; the server never sees it")}
                           onChange={(e) => setForm({ ...form, secret: e.target.value })} />
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
                <SealedCredential obj="route" id={r.id} onChange={() => act(r.id, async () => undefined)} />
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

/** A proxy stopped by its local kill switch: its reconciliation report, lifted
 *  by the passkeys of the quorum of the release it held before the outage. */
function KillSwitchRow({ proxy, onChange }: { proxy: Proxy; onChange: () => void }) {
  const { t, i18n } = useTranslation();
  const [ks, setKs] = useState<KillSwitch | null>(null);
  const [accept, setAccept] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { getKillSwitch(proxy.id).then(setKs).catch(() => setKs(null)); }, [proxy.id, proxy.last_seen_at]);
  if (!ks) return null;
  const all = ks.unsigned.every((id) => accept[id]);
  return (
    <tr>
      <td colSpan={5}>
        <div className="panel" style={{ borderColor: "var(--risk-critical)" }}>
          <div className="panel-body">
            <p className="error-text">
              {t("gw.ks.stopped", { when: new Date(ks.engaged_at).toLocaleString(i18n.language), reason: ks.reason || "",
                defaultValue: `Stopped by its local kill switch since ${ks.engaged_at} (${ks.reason || ""}): it refuses every request.` })}
            </p>
            <p className="hint-text">
              {t("gw.ks.hint", { n: ks.release_before, defaultValue: `Its reconciliation report compares what this server states now with release #${ks.release_before}, which it held before the outage. A difference no signed release explains must be accepted here, or undone (the proxy then sends a new report). The quorum of release #${ks.release_before} lifts it.` })}
            </p>
            <table className="table-cards" style={{ fontSize: 12 }}>
              <thead><tr><th>{t("gw.ks.item", "Item")}</th><th>{t("gw.status")}</th><th></th></tr></thead>
              <tbody>
                {ks.differences.length === 0 && <tr><td colSpan={3}>{t("gw.ks.none", "Nothing changed.")}</td></tr>}
                {ks.differences.map((d) => (
                  <tr key={d.id}>
                    <td>{d.area} · {d.section} · <strong>{d.label}</strong>
                      <div className="hint-text u-mono">{d.before ? d.before.slice(0, 12) : "—"} → {d.now ? d.now.slice(0, 12) : "—"}</div>
                    </td>
                    <td>
                      <span className={`pill ${d.signed ? "pill-low" : "pill-high"}`}>
                        {d.signed ? t("gw.ks.signed", "signed release") : t("gw.ks.unsigned", "not signed")}
                      </span>
                    </td>
                    <td>
                      {!d.signed && (
                        <label style={{ fontSize: 12 }}>
                          <input type="checkbox" checked={!!accept[d.id]}
                                 onChange={(e) => setAccept({ ...accept, [d.id]: e.target.checked })} />{" "}
                          {t("gw.ks.accept", "I accept it")}
                        </label>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="hint-text u-mono" style={{ fontSize: 12 }}>
              {t("gw.ks.report", "Report")} {ks.report_sha256.slice(0, 16)}… · {t("gw.ks.signatures", {
                n: ks.signers.length, q: ks.quorum, defaultValue: `${ks.signers.length} of ${ks.quorum} signatures` })}
              {ks.signers.length > 0 && ` (${ks.signers.map((s) => s.email).join(", ")})`}
            </p>
            {ks.can_sign && (
              <button className="btn btn-sm btn-primary" disabled={busy || !all} onClick={async () => {
                setBusy(true);
                setError(null);
                try {
                  setKs(await signKillSwitchLift(proxy.id, ks.unsigned.filter((id) => accept[id])));
                  onChange();
                } catch (err) {
                  setError(errorMessage(err, t, t("gw.failed")));
                } finally {
                  setBusy(false);
                }
              }}>{t("gw.ks.sign", "Lift: sign with passkey")}</button>
            )}
            <p className="hint-text" style={{ fontSize: 12 }}>
              {t("gw.ks.after", "The proxy checks the signatures itself and starts again; then sign a new policy release.")}
            </p>
            {error && <p className="error-text">{error}</p>}
          </div>
        </div>
      </td>
    </tr>
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

  const [legacy, setLegacy] = useState<{ count: number; proxies_with_keys: number } | null>(null);

  const refresh = () => {
    listEgressProxies().then(setProxies);
    getLegacyCredentials().then(setLegacy).catch(() => setLegacy(null));
  };
  useEffect(() => { refresh(); }, []);

  return (
    <div className="panel u-mb-16">
      {dialog}
      <div className="panel-header"><h2>{t("gw.egress.proxies")}</h2></div>
      <div className="panel-body">
        <p className="hint-text">{t("gw.egress.proxies_hint")}</p>
        {legacy && legacy.count > 0 && (
          <div className="panel u-mb-12" style={{ borderColor: "var(--risk-high)" }}>
            <div className="panel-body">
              <p>{t("sealed.legacy", { n: legacy.count, defaultValue: `This server still holds ${legacy.count} credentials from before. Nothing uses them until they are sealed to the proxies; then they are erased here.` })}</p>
              {legacy.proxies_with_keys === 0
                ? <p className="hint-text">{t("sealed.no_keys", "No egress proxy has registered its key yet: start one first.")}</p>
                : (
                  <button className="btn btn-sm btn-primary" disabled={busy} onClick={async () => {
                    if (!(await confirm(t("sealed.legacy_confirm", { n: legacy.proxies_with_keys, defaultValue: `Seal them to the ${legacy.proxies_with_keys} proxies with a key and erase them here? A proxy added later needs them entered again.` })))) return;
                    setBusy(true);
                    setError(null);
                    try {
                      await sealLegacyCredentials();
                      refresh();
                    } catch (err) {
                      setError(errorMessage(err, t, t("gw.failed")));
                    } finally {
                      setBusy(false);
                    }
                  }}>{t("sealed.legacy_seal", "Seal and erase")}</button>
                )}
            </div>
          </div>
        )}
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
            <React.Fragment key={p.id}>
            <tr>
              <td>{p.name}</td>
              <td className="u-mono">
                {p.key_prefix}…
                {p.key_fingerprint && (
                  <div className="hint-text" title={t("gw.egress.signing_key_hint", "The proxy's own signing key: its receipts are checked with it")}>
                    {p.key_fingerprint}
                  </div>
                )}
                {p.encryption_key_fingerprint && (
                  <div className="hint-text" title={t("gw.egress.encryption_key_hint", "The key credentials are sealed to: compare it with what the proxy logs on its host")}>
                    🔒 {p.encryption_key_fingerprint}
                  </div>
                )}
              </td>
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
            {p.enabled && <KillSwitchRow proxy={p} onChange={refresh} />}
            </React.Fragment>
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
