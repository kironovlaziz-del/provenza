"use client";

import React, { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Form } from "@/components/Form";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import {
  approveToolEntry,
  blockToolEntry,
  computeManifestDigest,
  createToolEntry,
  deleteToolEntry,
  getSupplyChainMode,
  listToolEntries,
  parseCapabilities,
  registryError,
  setSupplyChainMode,
  updateToolEntry,
  type SupplyChainMode,
  type ToolEntry,
  type ToolKind,
} from "@/lib/tool_registry_api";

const MODES: SupplyChainMode[] = ["off", "monitor", "enforce"];
const STATUS_CLASS: Record<string, string> = {
  approved: "pill-low",
  pending: "pill-medium",
  blocked: "pill-critical",
  drifted: "pill-critical",
};
const EMPTY_FORM = {
  pattern: "",
  kind: "tool" as ToolKind,
  publisher: "",
  source: "",
  pinned_version: "",
  pinned_digest: "",
  required_capabilities: "",
};

export default function ToolRegistryPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [mode, setMode] = useState<SupplyChainMode | null>(null);
  const [entries, setEntries] = useState<ToolEntry[]>([]);
  const [filter, setFilter] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);
  const [editing, setEditing] = useState<{ id: number; pinned_version: string; pinned_digest: string; caps: string } | null>(null);
  const [manifestText, setManifestText] = useState("");
  const [digest, setDigest] = useState<string | null>(null);

  const load = useCallback(() => {
    Promise.all([getSupplyChainMode(), listToolEntries()])
      .then(([m, e]) => {
        setMode(m);
        setEntries(e);
      })
      .catch((err) => setError(registryError(err, t("registry.load_failed", "Could not load the Tool Registry."))));
  }, [t]);

  useEffect(load, [load]);

  async function run(action: () => Promise<unknown>, ok?: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await action();
      if (ok) setNotice(ok);
      load();
    } catch (err) {
      setError(registryError(err, t("registry.failed", "Could not save.")));
    } finally {
      setBusy(false);
    }
  }

  function changeMode(next: SupplyChainMode) {
    if (next === "enforce") {
      const pending = entries.filter((e) => e.status !== "approved").length;
      const ok = window.confirm(
        t("registry.confirm_enforce", {
          count: pending,
          defaultValue: `Switch to enforce? Only approved tools will run. ${pending} entries are not approved yet.`,
        }),
      );
      if (!ok) return;
    }
    run(() => setSupplyChainMode(next), t("registry.saved", "Saved"));
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    await run(async () => {
      await createToolEntry({
        pattern: form.pattern.trim(),
        kind: form.kind,
        publisher: form.publisher || undefined,
        source: form.source || undefined,
        pinned_version: form.pinned_version || undefined,
        pinned_digest: form.pinned_digest || undefined,
        required_capabilities: parseCapabilities(form.required_capabilities),
        status: "approved",
      });
      setForm(EMPTY_FORM);
      setShowForm(false);
    }, t("registry.saved", "Saved"));
  }

  async function handleDigest() {
    setDigest(null);
    setError(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(manifestText);
    } catch {
      setError(t("registry.digest_invalid_json", "The manifest is not valid JSON."));
      return;
    }
    try {
      setDigest(await computeManifestDigest(parsed));
    } catch (err) {
      setError(registryError(err, t("registry.failed", "Could not save.")));
    }
  }

  const visible = filter ? entries.filter((e) => e.status === filter) : entries;
  const counts = entries.reduce<Record<string, number>>((acc, e) => ({ ...acc, [e.status]: (acc[e.status] ?? 0) + 1 }), {});
  const fmt = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : "—");

  return (
    <>
      <PageHeader
        title={t("registry.title", "Tool Registry")}
        actions={
          isAdmin ? (
            <button className="btn btn-primary btn-sm" onClick={() => setShowForm((s) => !s)}>
              {showForm ? t("registry.cancel", "Cancel") : t("registry.add", "Add tool")}
            </button>
          ) : undefined
        }
      />
      <div className="content">
        <p className="hint-text" style={{ marginTop: 0 }}>
          {t(
            "registry.hint",
            "Which tools, MCP servers and SDKs your agents may use, pinned to a version and manifest digest (OWASP ASI04). A tool that changes after approval is flagged as drifted.",
          )}
        </p>

        {error && (
          <div className="panel" style={{ marginBottom: 16, borderColor: "#ef4444" }}>
            <div className="panel-body" style={{ color: "#ef4444" }}>{error}</div>
          </div>
        )}
        {notice && <div className="hint-text" style={{ marginBottom: 16 }}>{notice}</div>}

        {/* ---- mode ---- */}
        {mode && (
          <div className="panel" style={{ marginBottom: 20 }}>
            <div className="panel-header">
              <h2>{t("registry.mode_title", "Mode")}</h2>
            </div>
            <div className="panel-body" style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {MODES.map((m) => (
                <label key={m} style={{ display: "flex", gap: 10, alignItems: "flex-start", cursor: isAdmin ? "pointer" : "default" }}>
                  <input
                    type="radio"
                    name="sc-mode"
                    checked={mode === m}
                    disabled={!isAdmin || busy}
                    onChange={() => changeMode(m)}
                    style={{ width: "auto", marginTop: 3 }}
                  />
                  <span>
                    <strong>{t(`registry.mode_${m}`, m)}</strong>
                    <span className="hint-text" style={{ display: "block", fontSize: 12 }}>
                      {t(`registry.mode_${m}_hint`, "")}
                    </span>
                  </span>
                </label>
              ))}
            </div>
          </div>
        )}

        {/* ---- add ---- */}
        {showForm && isAdmin && (
          <div className="panel" style={{ marginBottom: 20 }}>
            <div className="panel-header">
              <h2>{t("registry.form_title", "Approve a tool")}</h2>
            </div>
            <div className="panel-body">
              <Form onSubmit={handleCreate}>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="tr-pattern">{t("registry.pattern", "Tool name or pattern")}</label>
                    <input
                      id="tr-pattern"
                      required
                      maxLength={200}
                      placeholder="github.create_issue, github.*"
                      value={form.pattern}
                      onChange={(e) => setForm({ ...form, pattern: e.target.value })}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="tr-kind">{t("registry.kind", "Kind")}</label>
                    <select id="tr-kind" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value as ToolKind })}>
                      <option value="tool">{t("registry.kind_tool", "Tool")}</option>
                      <option value="mcp_server">{t("registry.kind_mcp_server", "MCP server")}</option>
                      <option value="sdk">{t("registry.kind_sdk", "SDK")}</option>
                    </select>
                  </div>
                </div>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="tr-pub">{t("registry.publisher", "Publisher")}</label>
                    <input id="tr-pub" maxLength={255} value={form.publisher} onChange={(e) => setForm({ ...form, publisher: e.target.value })} />
                  </div>
                  <div className="field">
                    <label htmlFor="tr-src">{t("registry.source", "Source (URL or package)")}</label>
                    <input id="tr-src" maxLength={500} value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })} />
                  </div>
                </div>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="tr-ver">{t("registry.pinned_version", "Pinned version")}</label>
                    <input id="tr-ver" maxLength={100} placeholder="1.4.0" value={form.pinned_version} onChange={(e) => setForm({ ...form, pinned_version: e.target.value })} />
                  </div>
                  <div className="field">
                    <label htmlFor="tr-dig">{t("registry.pinned_digest", "Pinned manifest digest")}</label>
                    <input id="tr-dig" className="mono" placeholder="sha256:…" value={form.pinned_digest} onChange={(e) => setForm({ ...form, pinned_digest: e.target.value })} />
                  </div>
                </div>
                <div className="field">
                  <label htmlFor="tr-caps">{t("registry.required_capabilities", "Required capabilities")}</label>
                  <input id="tr-caps" className="mono" placeholder="payments, email.send" value={form.required_capabilities}
                    onChange={(e) => setForm({ ...form, required_capabilities: e.target.value })} />
                  <div className="hint-text">{t("registry.required_capabilities_hint", "An agent may call this tool only if it holds these capabilities in its delegation chain. Agents can no longer declare them.")}</div>
                </div>
                <button className="btn btn-primary" type="submit" disabled={busy || !form.pattern.trim()}>
                  {t("registry.submit", "Approve tool")}
                </button>
              </Form>
            </div>
          </div>
        )}

        {/* ---- entries ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-body" style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {["", "drifted", "pending", "blocked", "approved"].map((s) => (
              <button key={s || "all"} className={`btn btn-sm${filter === s ? " btn-primary" : ""}`} onClick={() => setFilter(s)}>
                {s ? t(`registry.status_${s}`, s) : t("registry.all", "All")} ({s ? counts[s] ?? 0 : entries.length})
              </button>
            ))}
          </div>
          <div className="panel-body" style={{ overflowX: "auto", paddingTop: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>{t("registry.col_tool", "Tool")}</th>
                  <th>{t("registry.col_status", "Status")}</th>
                  <th>{t("registry.col_pins", "Pins")}</th>
                  <th>{t("registry.col_usage", "Usage")}</th>
                  {isAdmin && <th />}
                </tr>
              </thead>
              <tbody>
                {visible.map((e) => (
                  <tr key={e.id}>
                    <td>
                      <strong className="mono">{e.pattern}</strong>
                      <div className="hint-text" style={{ fontSize: 11 }}>
                        {t(`registry.kind_${e.kind}`, e.kind)}
                        {e.publisher ? ` · ${e.publisher}` : ""}
                        {e.discovered ? ` · ${t("registry.discovered", "discovered automatically")}` : ""}
                      </div>
                      {e.required_capabilities && e.required_capabilities.length > 0 && (
                        <div className="hint-text mono" style={{ fontSize: 11 }}>
                          {t("registry.requires", "requires")}: {e.required_capabilities.join(", ")}
                        </div>
                      )}
                      {e.status === "drifted" && e.drift_details?.problems && (
                        <div style={{ color: "#ef4444", fontSize: 12, marginTop: 4 }}>
                          ⚠ {e.drift_details.problems.join("; ")}
                        </div>
                      )}
                    </td>
                    <td>
                      <span className={`pill ${STATUS_CLASS[e.status] ?? "pill-neutral"}`}>{t(`registry.status_${e.status}`, e.status)}</span>
                    </td>
                    <td style={{ fontSize: 12 }}>
                      {editing?.id === e.id ? (
                        <div style={{ display: "flex", flexDirection: "column", gap: 4, minWidth: 220 }}>
                          <input
                            placeholder={t("registry.pinned_version", "Pinned version")}
                            value={editing.pinned_version}
                            onChange={(ev) => setEditing({ ...editing, pinned_version: ev.target.value })}
                          />
                          <input
                            className="mono"
                            placeholder="sha256:…"
                            value={editing.pinned_digest}
                            onChange={(ev) => setEditing({ ...editing, pinned_digest: ev.target.value })}
                          />
                          <input
                            className="mono"
                            placeholder={t("registry.required_capabilities", "Required capabilities")}
                            aria-label={t("registry.required_capabilities", "Required capabilities")}
                            value={editing.caps}
                            onChange={(ev) => setEditing({ ...editing, caps: ev.target.value })}
                          />
                          <div style={{ display: "flex", gap: 4 }}>
                            <button
                              className="btn btn-sm btn-primary"
                              disabled={busy}
                              onClick={() =>
                                run(async () => {
                                  await updateToolEntry(e.id, {
                                    pinned_version: editing.pinned_version.trim() || null,
                                    pinned_digest: editing.pinned_digest.trim() || null,
                                    required_capabilities: parseCapabilities(editing.caps),
                                  });
                                  setEditing(null);
                                }, t("registry.saved", "Saved"))
                              }
                            >
                              {t("registry.save", "Save")}
                            </button>
                            <button className="btn btn-sm" onClick={() => setEditing(null)}>{t("registry.cancel", "Cancel")}</button>
                          </div>
                        </div>
                      ) : (
                        <>
                          <div>{e.pinned_version ? `v${e.pinned_version}` : "—"}</div>
                          <div className="mono" title={e.pinned_digest ?? ""}>
                            {e.pinned_digest ? `sha256:${e.pinned_digest.slice(0, 12)}…` : ""}
                          </div>
                        </>
                      )}
                    </td>
                    <td style={{ fontSize: 12 }}>
                      {e.seen_count}×
                      <div className="hint-text">{fmt(e.last_seen_at)}</div>
                    </td>
                    {isAdmin && (
                      <td style={{ whiteSpace: "nowrap" }}>
                        {e.status !== "approved" && (
                          <button className="btn btn-sm btn-primary" disabled={busy} onClick={() => run(() => approveToolEntry(e.id), t("registry.saved", "Saved"))}>
                            {e.status === "drifted" ? t("registry.reapprove", "Re-approve") : t("registry.approve", "Approve")}
                          </button>
                        )}{" "}
                        {e.status !== "blocked" && (
                          <button className="btn btn-sm" disabled={busy} onClick={() => run(() => blockToolEntry(e.id), t("registry.saved", "Saved"))}>
                            {t("registry.block", "Block")}
                          </button>
                        )}{" "}
                        <button
                          className="btn btn-sm"
                          disabled={busy}
                          onClick={() => setEditing({ id: e.id, pinned_version: e.pinned_version ?? "", pinned_digest: e.pinned_digest ?? "", caps: (e.required_capabilities ?? []).join(", ") })}
                        >
                          {t("registry.pin", "Pin")}
                        </button>{" "}
                        <button
                          className="btn btn-sm"
                          disabled={busy}
                          onClick={() => {
                            if (window.confirm(t("registry.confirm_delete", "Remove this entry?")))
                              run(() => deleteToolEntry(e.id), t("registry.saved", "Saved"));
                          }}
                        >
                          ✕
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
                {visible.length === 0 && (
                  <tr>
                    <td colSpan={isAdmin ? 5 : 4} className="hint-text">{t("registry.empty", "No tools here yet.")}</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* ---- digest helper ---- */}
        <div className="panel">
          <div className="panel-header">
            <h2>{t("registry.digest_title", "Manifest digest")}</h2>
          </div>
          <div className="panel-body">
            <p className="hint-text" style={{ marginTop: 0 }}>
              {t(
                "registry.digest_hint",
                "Paste a tool manifest (e.g. an MCP server's tools/list result). The canonical SHA-256 ignores key order and whitespace, so your agents' runtime reports the same value.",
              )}
            </p>
            <textarea
              rows={5}
              className="mono"
              value={manifestText}
              onChange={(e) => setManifestText(e.target.value)}
              placeholder='{"tools": [{"name": "create_issue", "description": "…"}]}'
              style={{ width: "100%" }}
            />
            <button className="btn btn-sm" style={{ marginTop: 8 }} disabled={!manifestText.trim()} onClick={handleDigest}>
              {t("registry.digest_compute", "Compute digest")}
            </button>
            {digest && (
              <div className="mono" style={{ marginTop: 8, fontSize: 12, wordBreak: "break-all" }}>{digest}</div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
