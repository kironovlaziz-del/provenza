"use client";

// MCP gateway: agents connect to Provenza's /mcp with their own key and see
// only approved tools of the servers added here. A tool is approved for its
// exact definition (digest); a changed definition drifts until re-approved.

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useDialog } from "@/components/Dialog";
import { Form } from "@/components/Form";
import { SealedCredential, sealNew } from "@/components/gateways/SealedCredential";
import { errorMessage } from "@/lib/errors";
import {
  apiUrl,
  approveMcpTool,
  blockMcpTool,
  createMcpServer,
  deleteMcpServer,
  listMcpServers,
  listMcpTools,
  MCP_PROTOCOLS,
  McpProtocol,
  McpServer,
  McpSyncReport,
  McpTool,
  syncMcpServer,
  updateMcpServer,
} from "@/lib/gateways_api";

const TOOL_PILL: Record<string, string> = { approved: "pill-low", pending: "pill-medium", drifted: "pill-high", blocked: "pill-critical" };
const EMPTY = { slug: "", name: "", url: "", protocol: "auto" as McpProtocol, auth_header: "Authorization", auth_secret: "", timeout_seconds: 30 };

function when(v: string | null, lang: string, never: string) {
  return v ? new Date(v).toLocaleString(lang) : never;
}

function Tools({ server, onChange }: { server: McpServer; onChange: () => void }) {
  const { t } = useTranslation();
  const [tools, setTools] = useState<McpTool[] | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = () => listMcpTools(server.id).then(setTools).catch((e) => setError(errorMessage(e, t, t("gw.failed"))));
  useEffect(() => { load(); }, [server.id]); // eslint-disable-line react-hooks/exhaustive-deps

  async function act(tool: McpTool, fn: typeof approveMcpTool) {
    setBusy(tool.id);
    setError(null);
    try {
      await fn(server.id, tool.id);
      await load();
      onChange();
    } catch (e) {
      setError(errorMessage(e, t, t("gw.failed")));
    } finally {
      setBusy(null);
    }
  }

  if (!tools) return <div className="hint-text">{error ?? t("common.loading")}</div>;
  return (
    <div className="u-mt-8">
      {error && <p className="error-text">{error}</p>}
      <table>
        <thead>
          <tr>
            <th>{t("gw.mcp.tool")}</th>
            <th>{t("gw.status")}</th>
            <th>{t("gw.mcp.digest")}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {tools.length === 0 && <tr className="empty-row"><td colSpan={4}>{t("gw.mcp.no_tools")}</td></tr>}
          {tools.map((tool) => (
            <tr key={tool.id} style={tool.removed_at ? { opacity: 0.5 } : undefined}>
              <td>
                <span className="u-mono">{tool.exposed_name}</span>
                {(tool.title || tool.description) && (
                  <div className="hint-text">{tool.title ?? tool.description?.slice(0, 160)}</div>
                )}
              </td>
              <td>
                <span className={`pill ${TOOL_PILL[tool.status] ?? "pill-neutral"}`}>{t(`gw.tool_status.${tool.status}`, tool.status)}</span>
                {tool.served && <div className="hint-text">{t("gw.served")}</div>}
                {tool.removed_at && <div className="hint-text">{t("gw.mcp.removed")}</div>}
              </td>
              <td className="u-mono" title={tool.digest}>{tool.digest.slice(0, 12)}…</td>
              <td className="u-nowrap">
                <div className="u-btn-row">
                  {tool.status !== "approved" && !tool.removed_at && (
                    <button className="btn btn-sm btn-primary" disabled={busy === tool.id} onClick={() => act(tool, approveMcpTool)}>
                      {tool.status === "drifted" ? t("gw.approve_change") : t("gw.approve")}
                    </button>
                  )}
                  {tool.status !== "blocked" && (
                    <button className="btn btn-sm btn-danger" disabled={busy === tool.id} onClick={() => act(tool, blockMcpTool)}>
                      {t("gw.block")}
                    </button>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function McpServers() {
  const { t, i18n } = useTranslation();
  const { dialog, confirm } = useDialog();
  const [servers, setServers] = useState<McpServer[]>([]);
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState(EMPTY);
  const [showForm, setShowForm] = useState(false);
  const [busy, setBusy] = useState<number | "new" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<number | null>(null);
  const [reports, setReports] = useState<Record<number, McpSyncReport>>({});

  const refresh = () => listMcpServers().then(setServers).finally(() => setLoading(false));
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

  return (
    <>
      {dialog}
      <p className="hint-text u-mb-16">{t("gw.mcp.hint", { url: apiUrl("/mcp") })}</p>
      <div className="u-btn-row u-mb-16">
        <button className="btn btn-primary btn-sm" onClick={() => setShowForm((v) => !v)}>
          {showForm ? t("common.cancel") : t("gw.mcp.add")}
        </button>
      </div>

      {showForm && (
        <div className="panel u-mb-16">
          <div className="panel-header"><h2>{t("gw.mcp.add")}</h2></div>
          <div className="panel-body">
            <Form onSubmit={(e) => {
              e.preventDefault();
              act("new", async () => {
                const { auth_secret, ...fields } = form;
                const server = await createMcpServer(fields);
                await sealNew("mcp_server", server.id, auth_secret);   // sealed here, never sent in clear
                setForm(EMPTY);
                setShowForm(false);
              });
            }}>
              <div className="form-row">
                <div className="field">
                  <label htmlFor="mcp-name">{t("gw.name")}</label>
                  <input id="mcp-name" required maxLength={255} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
                </div>
                <div className="field">
                  <label htmlFor="mcp-slug">{t("gw.slug")}</label>
                  <input id="mcp-slug" required pattern="[a-z0-9][a-z0-9\-]{0,39}" value={form.slug}
                         placeholder="github" onChange={(e) => setForm({ ...form, slug: e.target.value })} />
                </div>
              </div>
              <div className="form-row">
                <div className="field" style={{ flex: 2 }}>
                  <label htmlFor="mcp-url">{t("gw.mcp.url")}</label>
                  <input id="mcp-url" required type="url" maxLength={500} value={form.url}
                         placeholder="https://mcp.example.com/mcp" onChange={(e) => setForm({ ...form, url: e.target.value })} />
                </div>
                <div className="field">
                  <label htmlFor="mcp-protocol">{t("gw.mcp.protocol")}</label>
                  <select id="mcp-protocol" value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value as McpProtocol })}>
                    {MCP_PROTOCOLS.map((p) => <option key={p} value={p}>{p === "auto" ? t("gw.mcp.auto") : p}</option>)}
                  </select>
                </div>
              </div>
              <div className="form-row">
                <div className="field">
                  <label htmlFor="mcp-header">{t("gw.auth_header")}</label>
                  <input id="mcp-header" maxLength={100} value={form.auth_header} onChange={(e) => setForm({ ...form, auth_header: e.target.value })} />
                </div>
                <div className="field">
                  <label htmlFor="mcp-secret">{t("gw.secret")}</label>
                  <input id="mcp-secret" type="password" autoComplete="new-password" maxLength={4000} value={form.auth_secret}
                         placeholder={t("sealed.placeholder", "Sealed in this browser; the server never sees it")}
                         onChange={(e) => setForm({ ...form, auth_secret: e.target.value })} />
                </div>
                <div className="field" style={{ maxWidth: 140 }}>
                  <label htmlFor="mcp-timeout">{t("gw.timeout")}</label>
                  <input id="mcp-timeout" type="number" min={1} max={120} value={form.timeout_seconds}
                         onChange={(e) => setForm({ ...form, timeout_seconds: Number(e.target.value) })} />
                </div>
              </div>
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
              <th>{t("gw.name")}</th>
              <th>{t("gw.mcp.url")}</th>
              <th>{t("gw.status")}</th>
              <th>{t("gw.last_sync")}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {loading && <tr className="empty-row"><td colSpan={5}>{t("common.loading")}</td></tr>}
            {!loading && servers.length === 0 && <tr className="empty-row"><td colSpan={5}>{t("gw.mcp.none")}</td></tr>}
            {servers.map((s) => (
              <React.Fragment key={s.id}>
                <tr>
                  <td>
                    <strong>{s.name}</strong>
                    <div className="hint-text u-mono">{s.slug}</div>
                    <SealedCredential obj="mcp_server" id={s.id} />
                  </td>
                  <td className="u-mono" style={{ wordBreak: "break-all" }}>
                    {s.url}
                    <div className="hint-text">{s.detected_version ?? s.protocol}</div>
                  </td>
                  <td>
                    <span className={`pill ${s.enabled ? (s.last_error ? "pill-high" : "pill-low") : "pill-neutral"}`}>
                      {!s.enabled ? t("gw.disabled") : s.last_error ? t("gw.error") : t("gw.enabled")}
                    </span>
                    {s.last_error && <div className="hint-text" style={{ maxWidth: 260 }}>{s.last_error}</div>}
                    {reports[s.id] && (
                      <div className="hint-text">
                        {t("gw.mcp.sync_report", {
                          added: reports[s.id].added.length, changed: reports[s.id].changed.length,
                          removed: reports[s.id].removed.length, skipped: reports[s.id].skipped.length,
                        })}
                      </div>
                    )}
                  </td>
                  <td className="u-mono u-nowrap">{when(s.last_synced_at, i18n.language, t("gw.never"))}</td>
                  <td className="u-nowrap">
                    <div className="u-btn-row">
                      {s.credential_source === "none" ? (
                        <button className="btn btn-sm btn-primary" disabled={busy === s.id}
                                onClick={() => act(s.id, async () => {
                                  const r = await syncMcpServer(s.id);
                                  setReports((prev) => ({ ...prev, [s.id]: r }));
                                  setOpen(s.id);
                                })}>
                          {t("gw.sync")}
                        </button>
                      ) : (
                        <span className="hint-text" title={t("gw.synced_by_proxy_hint", "Its credential is sealed to the egress proxies: they sync it every minute and agents call it through them (/_mcp).")}>
                          {t("gw.synced_by_proxy", "synced by the egress proxies")}
                        </span>
                      )}
                      <button className="btn btn-sm" onClick={() => setOpen(open === s.id ? null : s.id)}>
                        {open === s.id ? t("gw.mcp.hide_tools") : t("gw.mcp.tools")}
                      </button>
                      <button className="btn btn-sm" disabled={busy === s.id}
                              onClick={() => act(s.id, () => updateMcpServer(s.id, { enabled: !s.enabled }))}>
                        {s.enabled ? t("gw.disable") : t("gw.enable")}
                      </button>
                      <button className="btn btn-sm btn-danger" disabled={busy === s.id}
                              onClick={async () => {
                                if (await confirm(t("gw.confirm_delete", { name: s.name }), { danger: true })) {
                                  act(s.id, () => deleteMcpServer(s.id));
                                }
                              }}>
                        {t("common.delete")}
                      </button>
                    </div>
                  </td>
                </tr>
                {open === s.id && (
                  <tr>
                    <td colSpan={5}><Tools server={s} onChange={refresh} /></td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
