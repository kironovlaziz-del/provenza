"use client";

// HTTP tools: an external API as a tool the agent can only reach through
// Provenza. The address and the credential stay here; the agent sends the
// tool name and arguments (agent.invoke in the SDKs), Provenza checks, calls
// and records. Saving a tool pins its definition in the Tool Registry.

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Form } from "@/components/Form";
import { errorMessage } from "@/lib/errors";
import {
  apiUrl,
  createHttpTool,
  HttpMethod,
  HttpTool,
  listHttpTools,
  updateHttpTool,
} from "@/lib/gateways_api";

const METHODS: HttpMethod[] = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const EMPTY = {
  name: "", description: "", method: "POST" as HttpMethod, url: "", input_schema: "",
  auth_header: "Authorization", auth_secret: "", timeout_seconds: 30, send_permit: true,
};

export function HttpTools() {
  const { t } = useTranslation();
  const [tools, setTools] = useState<HttpTool[]>([]);
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState(EMPTY);
  const [showForm, setShowForm] = useState(false);
  const [busy, setBusy] = useState<number | "new" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [secretFor, setSecretFor] = useState<number | null>(null);
  const [newSecret, setNewSecret] = useState("");

  const refresh = () => listHttpTools().then(setTools).finally(() => setLoading(false));
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

  function schemaOf(text: string): Record<string, unknown> | null {
    if (!text.trim()) return null;
    try {
      return JSON.parse(text);
    } catch {
      throw new Error(t("gw.http.schema_invalid"));
    }
  }

  return (
    <>
      <p className="hint-text u-mb-16">{t("gw.http.hint", { url: apiUrl("/http-tools/call") })}</p>
      <div className="u-btn-row u-mb-16">
        <button className="btn btn-primary btn-sm" onClick={() => setShowForm((v) => !v)}>
          {showForm ? t("common.cancel") : t("gw.http.add")}
        </button>
      </div>

      {showForm && (
        <div className="panel u-mb-16">
          <div className="panel-header"><h2>{t("gw.http.add")}</h2></div>
          <div className="panel-body">
            <Form onSubmit={(e) => {
              e.preventDefault();
              let schema: Record<string, unknown> | null;
              try {
                schema = schemaOf(form.input_schema);
              } catch (err) {
                setError((err as Error).message);
                return;
              }
              act("new", async () => {
                await createHttpTool({ ...form, input_schema: schema, description: form.description || undefined,
                                       auth_secret: form.auth_secret || undefined });
                setForm(EMPTY);
                setShowForm(false);
              });
            }}>
              <div className="form-row">
                <div className="field">
                  <label htmlFor="ht-name">{t("gw.http.name")}</label>
                  <input id="ht-name" required pattern="[a-z0-9][a-z0-9_.\-]{0,99}" value={form.name}
                         placeholder="crm.set_tier" onChange={(e) => setForm({ ...form, name: e.target.value })} />
                </div>
                <div className="field" style={{ maxWidth: 140 }}>
                  <label htmlFor="ht-method">{t("gw.http.method")}</label>
                  <select id="ht-method" value={form.method} onChange={(e) => setForm({ ...form, method: e.target.value as HttpMethod })}>
                    {METHODS.map((m) => <option key={m} value={m}>{m}</option>)}
                  </select>
                </div>
              </div>
              <div className="field">
                <label htmlFor="ht-url">{t("gw.http.url")}</label>
                <input id="ht-url" required type="text" maxLength={500} value={form.url}
                       placeholder="https://crm.example.com/api/customers/{id}"
                       onChange={(e) => setForm({ ...form, url: e.target.value })} />
                <p className="hint-text">{t("gw.http.url_hint")}</p>
              </div>
              <div className="field">
                <label htmlFor="ht-desc">{t("gw.http.description")}</label>
                <input id="ht-desc" maxLength={4000} value={form.description}
                       onChange={(e) => setForm({ ...form, description: e.target.value })} />
              </div>
              <div className="field">
                <label htmlFor="ht-schema">{t("gw.http.schema")}</label>
                <textarea id="ht-schema" className="u-mono" rows={5} value={form.input_schema}
                          placeholder='{"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}'
                          onChange={(e) => setForm({ ...form, input_schema: e.target.value })} />
                <p className="hint-text">{t("gw.http.schema_hint")}</p>
              </div>
              <div className="form-row">
                <div className="field">
                  <label htmlFor="ht-header">{t("gw.auth_header")}</label>
                  <input id="ht-header" maxLength={100} value={form.auth_header} onChange={(e) => setForm({ ...form, auth_header: e.target.value })} />
                </div>
                <div className="field">
                  <label htmlFor="ht-secret">{t("gw.secret")}</label>
                  <input id="ht-secret" type="password" autoComplete="new-password" maxLength={4000} value={form.auth_secret}
                         placeholder={t("gw.secret_placeholder")} onChange={(e) => setForm({ ...form, auth_secret: e.target.value })} />
                </div>
                <div className="field" style={{ maxWidth: 140 }}>
                  <label htmlFor="ht-timeout">{t("gw.timeout")}</label>
                  <input id="ht-timeout" type="number" min={1} max={120} value={form.timeout_seconds}
                         onChange={(e) => setForm({ ...form, timeout_seconds: Number(e.target.value) })} />
                </div>
              </div>
              <label className="u-flex u-items-center u-gap-6 u-mb-16">
                <input type="checkbox" style={{ width: "auto" }} checked={form.send_permit}
                       onChange={(e) => setForm({ ...form, send_permit: e.target.checked })} />
                {t("gw.http.send_permit")}
              </label>
              <button className="btn btn-primary" type="submit" disabled={busy === "new"}>
                {busy === "new" ? t("common.loading") : t("common.create")}
              </button>
            </Form>
          </div>
        </div>
      )}

      {error && <p className="error-text">{error}</p>}
      <div className="panel">
        <table>
          <thead>
            <tr>
              <th>{t("gw.http.name")}</th>
              <th>{t("gw.http.endpoint")}</th>
              <th>{t("gw.status")}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {loading && <tr className="empty-row"><td colSpan={4}>{t("common.loading")}</td></tr>}
            {!loading && tools.length === 0 && <tr className="empty-row"><td colSpan={4}>{t("gw.http.none")}</td></tr>}
            {tools.map((h) => (
              <tr key={h.id}>
                <td>
                  <strong className="u-mono">{h.name}</strong>
                  {h.description && <div className="hint-text">{h.description.slice(0, 160)}</div>}
                </td>
                <td style={{ maxWidth: 360 }}>
                  <div className="u-mono" style={{ wordBreak: "break-all" }}><strong>{h.method}</strong> {h.url}</div>
                  <div className="hint-text">
                    {h.has_secret ? t("gw.has_secret") : t("gw.http.no_secret")}
                    {h.send_permit && ["POST", "PUT", "PATCH"].includes(h.method) ? ` · ${t("gw.http.permit_sent")}` : ""}
                  </div>
                </td>
                <td>
                  <span className={`pill ${h.enabled ? "pill-low" : "pill-neutral"}`}>
                    {h.enabled ? t("gw.served") : t("gw.disabled")}
                  </span>
                  <div className="hint-text u-mono" title={h.digest}>{h.digest.slice(0, 12)}</div>
                </td>
                <td className="u-nowrap">
                  {secretFor === h.id ? (
                    <div className="u-btn-row">
                      <input type="password" autoComplete="new-password" maxLength={4000} value={newSecret}
                             placeholder={t("gw.secret_placeholder")} onChange={(e) => setNewSecret(e.target.value)} />
                      <button className="btn btn-sm btn-primary" disabled={!newSecret || busy === h.id}
                              onClick={() => act(h.id, async () => {
                                await updateHttpTool(h.id, { auth_secret: newSecret });
                                setSecretFor(null);
                                setNewSecret("");
                              })}>
                        {t("common.save")}
                      </button>
                      <button className="btn btn-sm" onClick={() => { setSecretFor(null); setNewSecret(""); }}>{t("common.cancel")}</button>
                    </div>
                  ) : (
                    <div className="u-btn-row">
                      <button className="btn btn-sm" disabled={busy === h.id} onClick={() => setSecretFor(h.id)}>
                        {t("gw.http.replace_secret")}
                      </button>
                      <button className="btn btn-sm" disabled={busy === h.id}
                              onClick={() => act(h.id, () => updateHttpTool(h.id, { enabled: !h.enabled }))}>
                        {h.enabled ? t("gw.disable") : t("gw.enable")}
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
