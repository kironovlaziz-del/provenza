"use client";

import { Form } from "@/components/Form";
import React, { useEffect, useState, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/Pill";
import { useAuth } from "@/lib/auth";
import {
  createShadowSighting,
  listShadowSightings,
  registerShadowSighting,
  updateShadowSighting,
  getShadowAISummary,
} from "@/lib/api";
import type { ShadowSighting } from "@/lib/types";

// Renders the human-readable specifics the backend put in display_meta
// (port/service, file name+size, process name+pid, device) so the raw
// dedup key in `domain` never has to be shown to a person.
function renderDisplayMeta(s: ShadowSighting): string | null {
  const m = (s.display_meta || {}) as Record<string, unknown>;
  const kind = m.kind as string | undefined;
  const dev = m.agent_id ? ` · ${m.agent_id}` : "";
  if (kind === "network") {
    const svc = (m.service as string) || "service";
    return `${svc} · port ${m.port ?? "?"}${dev}`;
  }
  if (kind === "process") {
    const name = (m.process_name as string) || (m.ai_tool as string) || "process";
    return `${name}${m.pid ? ` · PID ${m.pid}` : ""}${dev}`;
  }
  if (kind === "model_file") {
    const name = (m.file_name as string) || "model file";
    const size = m.size_mb ? ` · ${m.size_mb} MB` : "";
    return `${name}${size}${dev}`;
  }
  if (kind === "domain") {
    return (m.category as string) ? `${m.category}${dev}` : (dev.trim() ? (m.agent_id as string) : null);
  }
  return null;
}


export default function ShadowAIPage() {
  const { t, i18n } = useTranslation();
  const [sightings, setSightings] = useState<ShadowSighting[]>([]);
  const [summary, setSummary] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);

  // Tabs & filters
  const [activeTab, setActiveTab] = useState<"active" | "resolved">("active");
  const [searchQuery, setSearchQuery] = useState("");
  const [sourceFilter, setSourceFilter] = useState("all");

  // Manual report form
  const [toolName, setToolName] = useState("");
  const [domain, setDomain] = useState("");
  const [detectedVia, setDetectedVia] = useState("manual");
  const [userHint, setUserHint] = useState("");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Modal for registering provider
  const [registerTarget, setRegisterTarget] = useState<ShadowSighting | null>(null);
  const [providerType, setProviderType] = useState("custom");

  function refresh() {
    setLoading(true);
    Promise.all([
      listShadowSightings(),
      getShadowAISummary().catch(() => ({})),
    ])
      .then(([sList, sSummary]) => {
        setSightings(sList);
        setSummary(sSummary);
      })
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    refresh();
  }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await createShadowSighting({
        tool_name: toolName,
        domain: domain || undefined,
        detected_via: detectedVia,
        user_hint: userHint || undefined,
        notes: notes || undefined,
      });
      setToolName("");
      setDomain("");
      setUserHint("");
      setNotes("");
      setDetectedVia("manual");
      setShowForm(false);
      refresh();
    } catch {
      setError(t("shadow_ai.failed"));
    } finally {
      setSubmitting(false);
    }
  }

  // what the API allows: review (take, dismiss) admin or approver, register admin
  const { user } = useAuth();
  const canReview = user?.role === "admin" || user?.role === "approver";
  const canRegister = user?.role === "admin";

  async function handleSetStatus(id: number, status: string) {
    setBusyId(id);
    try {
      await updateShadowSighting(id, { status });
      refresh();
    } finally {
      setBusyId(null);
    }
  }

  async function handleRegisterConfirm() {
    if (!registerTarget) return;
    setBusyId(registerTarget.id);
    try {
      await registerShadowSighting(registerTarget.id, { provider_type: providerType });
      setRegisterTarget(null);
      refresh();
    } finally {
      setBusyId(null);
    }
  }

  const filteredSightings = useMemo(() => {
    return sightings.filter((s) => {
      const isResolved = ["dismissed", "registered"].includes(s.status);
      if (activeTab === "active" && isResolved) return false;
      if (activeTab === "resolved" && !isResolved) return false;

      if (sourceFilter !== "all" && s.detected_via !== sourceFilter) return false;

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchName = s.tool_name.toLowerCase().includes(q);
        const matchDomain = (s.domain || "").toLowerCase().includes(q);
        const matchUser = (s.user_hint || "").toLowerCase().includes(q);
        if (!matchName && !matchDomain && !matchUser) return false;
      }

      return true;
    });
  }, [sightings, activeTab, sourceFilter, searchQuery]);

  const countTotal = sightings.length;
  const countNew = summary["new"] || sightings.filter((s) => s.status === "new").length;
  const countConfirmed =
    summary["confirmed_shadow"] || sightings.filter((s) => s.status === "confirmed_shadow").length;
  const countRegistered =
    summary["registered"] || sightings.filter((s) => s.status === "registered").length;

  const renderSourceBadge = (source: string) => {
    const style = { fontSize: "11px" } as const;
    switch (source) {
      case "browser_extension":
        return <span className="mono" style={style}>🌐 {t("shadow_ai.source_extension")}</span>;
      case "endpoint_agent":
        return <span className="mono" style={style}>🖥️ {t("shadow_ai.source_agent")}</span>;
      case "network_proxy":
        return <span className="mono" style={style}>⚡ {t("shadow_ai.source_proxy")}</span>;
      // The three event types the Go endpoint agent's collectors send
      // directly (see telemetry_service.py) - previously fell through to
      // the "Manual" default, which mislabeled every local-signal finding.
      case "process_detected":
        return <span className="mono" style={style}>🔍 {t("shadow_ai.source_process")}</span>;
      case "network_conn":
        return <span className="mono" style={style}>🔌 {t("shadow_ai.source_network")}</span>;
      case "local_model_found":
        return <span className="mono" style={style}>📦 {t("shadow_ai.source_model_file")}</span>;
      // a visit to an AI site, reported by the browser extension or the endpoint agent
      case "domain_visit":
        return <span className="mono" style={style}>🌐 {t("shadow_ai.source_domain_visit")}</span>;
      default:
        return <span className="mono" style={style}>📝 {t("shadow_ai.source_manual")}</span>;
    }
  };

  return (
    <>
      <PageHeader
        title={t("shadow_ai.title")}
        actions={
          <button className="btn btn-primary btn-sm" onClick={() => setShowForm((s) => !s)}>
            {showForm ? t("shadow_ai.cancel") : t("shadow_ai.report")}
          </button>
        }
      />

      <div className="content">
        {/* Responsive Stat Cards: Auto-scales across 1, 2, or 4 columns */}
        <div className="stat-grid" style={{ marginBottom: 20 }}>
          <div className="stat" style={{ display: "flex", flexDirection: "column", justifyContent: "space-between", minHeight: 88 }}>
            <div className="stat-label" style={{ minHeight: 28, display: "flex", alignItems: "flex-start" }}>
              {t("shadow_ai.stat_total")}
            </div>
            <div className="stat-value">{countTotal}</div>
          </div>
          <div className="stat" style={{ display: "flex", flexDirection: "column", justifyContent: "space-between", minHeight: 88 }}>
            <div className="stat-label" style={{ minHeight: 28, display: "flex", alignItems: "flex-start" }}>
              {t("shadow_ai.stat_new")}
            </div>
            <div className="stat-value" style={{ color: "var(--accent, #2451d9)" }}>
              {countNew}
            </div>
          </div>
          <div className="stat" style={{ display: "flex", flexDirection: "column", justifyContent: "space-between", minHeight: 88 }}>
            <div className="stat-label" style={{ minHeight: 28, display: "flex", alignItems: "flex-start" }}>
              {t("shadow_ai.stat_confirmed")}
            </div>
            <div className="stat-value" style={{ color: "var(--risk-critical, #c1352f)" }}>
              {countConfirmed}
            </div>
          </div>
          <div className="stat" style={{ display: "flex", flexDirection: "column", justifyContent: "space-between", minHeight: 88 }}>
            <div className="stat-label" style={{ minHeight: 28, display: "flex", alignItems: "flex-start" }}>
              {t("shadow_ai.stat_registered")}
            </div>
            <div className="stat-value" style={{ color: "var(--risk-low, #2f9e63)" }}>
              {countRegistered}
            </div>
          </div>
        </div>

        {/* Manual Report Form */}
        {showForm && (
          <div className="panel" style={{ marginBottom: 20 }}>
            <div className="panel-header">
              <h2>{t("shadow_ai.form_title")}</h2>
            </div>
            <div className="panel-body">
              <Form onSubmit={handleCreate}>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="tool_name">{t("shadow_ai.tool_name")}</label>
                    <input
                      id="tool_name"
                      required
                      value={toolName}
                      onChange={(e) => setToolName(e.target.value)}
                      placeholder={t("shadow_ai.tool_name_placeholder")}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="domain">{t("shadow_ai.domain")}</label>
                    <input
                      id="domain"
                      value={domain}
                      onChange={(e) => setDomain(e.target.value)}
                      placeholder={t("shadow_ai.domain_placeholder")}
                    />
                  </div>
                </div>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="detected_via">{t("shadow_ai.detected_via")}</label>
                    <select
                      id="detected_via"
                      value={detectedVia}
                      onChange={(e) => setDetectedVia(e.target.value)}
                    >
                      <option value="manual">{t("shadow_ai.detected.manual")}</option>
                      <option value="browser_extension">{t("shadow_ai.source_extension")}</option>
                      <option value="endpoint_agent">{t("shadow_ai.source_agent")}</option>
                      <option value="network_proxy">{t("shadow_ai.detected.network_proxy")}</option>
                      <option value="process_detected">{t("shadow_ai.source_process")}</option>
                      <option value="network_conn">{t("shadow_ai.source_network")}</option>
                      <option value="local_model_found">{t("shadow_ai.source_model_file")}</option>
                      <option value="expense_report">{t("shadow_ai.detected.expense_report")}</option>
                      <option value="other">{t("shadow_ai.detected.other")}</option>
                    </select>
                  </div>
                  <div className="field">
                    <label htmlFor="user_hint">{t("shadow_ai.user_hint")}</label>
                    <input
                      id="user_hint"
                      value={userHint}
                      onChange={(e) => setUserHint(e.target.value)}
                      placeholder={t("shadow_ai.user_hint_placeholder")}
                    />
                  </div>
                </div>
                <div className="field">
                  <label htmlFor="notes">{t("shadow_ai.notes")}</label>
                  <textarea
                    id="notes"
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    placeholder={t("shadow_ai.notes_placeholder")}
                  />
                </div>
                {error && <p className="error-text">{error}</p>}
                <button className="btn btn-primary" type="submit" disabled={submitting}>
                  {submitting ? t("shadow_ai.submitting") : t("shadow_ai.submit")}
                </button>
              </Form>
            </div>
          </div>
        )}

        {/* Responsive Main Panel */}
        <div className="panel" style={{ width: "100%", overflow: "hidden" }}>
          {/* Header with Segmented Tabs & Filters */}
          <div
            className="panel-header"
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: 12,
              padding: "12px 18px",
            }}
          >
            {/* Segmented Tabs */}
            <div
              style={{
                display: "inline-flex",
                background: "var(--bg-app, #f5f6f8)",
                padding: "3px",
                borderRadius: "8px",
                border: "1px solid var(--border)",
              }}
            >
              <button
                type="button"
                onClick={() => setActiveTab("active")}
                style={{
                  border: "none",
                  padding: "6px 14px",
                  borderRadius: "6px",
                  fontSize: "12px",
                  fontWeight: 500,
                  cursor: "pointer",
                  background: activeTab === "active" ? "var(--bg-panel, #ffffff)" : "transparent",
                  color: activeTab === "active" ? "var(--text-primary)" : "var(--text-muted)",
                  boxShadow: activeTab === "active" ? "0 1px 2px rgba(0,0,0,0.06)" : "none",
                }}
              >
                {t("shadow_ai.tab_active")}
              </button>
              <button
                type="button"
                onClick={() => setActiveTab("resolved")}
                style={{
                  border: "none",
                  padding: "6px 14px",
                  borderRadius: "6px",
                  fontSize: "12px",
                  fontWeight: 500,
                  cursor: "pointer",
                  background: activeTab === "resolved" ? "var(--bg-panel, #ffffff)" : "transparent",
                  color: activeTab === "resolved" ? "var(--text-primary)" : "var(--text-muted)",
                  boxShadow: activeTab === "resolved" ? "0 1px 2px rgba(0,0,0,0.06)" : "none",
                }}
              >
                {t("shadow_ai.tab_resolved")}
              </button>
            </div>

            {/* Filter Inputs (Auto-wraps smoothly on mobile) */}
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <input
                type="text"
                placeholder={t("shadow_ai.filter_search_ph")}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  padding: "6px 10px",
                  fontSize: "12px",
                  borderRadius: "6px",
                  border: "1px solid var(--border)",
                  minWidth: 180,
                }}
              />
              <select
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                style={{
                  padding: "6px 10px",
                  fontSize: "12px",
                  borderRadius: "6px",
                  border: "1px solid var(--border)",
                }}
              >
                <option value="all">{t("shadow_ai.source_all")}</option>
                <option value="endpoint_agent">{t("shadow_ai.source_agent")}</option>
                <option value="browser_extension">{t("shadow_ai.source_extension")}</option>
                <option value="network_proxy">{t("shadow_ai.source_proxy")}</option>
                <option value="process_detected">{t("shadow_ai.source_process")}</option>
                <option value="network_conn">{t("shadow_ai.source_network")}</option>
                <option value="local_model_found">{t("shadow_ai.source_model_file")}</option>
                <option value="domain_visit">{t("shadow_ai.source_domain_visit")}</option>
                <option value="manual">{t("shadow_ai.source_manual")}</option>
              </select>
            </div>
          </div>

          {/* Table Container: fluid on desktop, smoothly scrollable on mobile */}
          <div style={{ width: "100%", overflowX: "auto" }}>
            <table style={{ width: "100%", minWidth: 640 }}>
              <thead>
                <tr>
                  <th>{t("shadow_ai.col_tool")}</th>
                  <th>{t("shadow_ai.col_source")}</th>
                  <th>{t("shadow_ai.col_employee")}</th>
                  <th>{t("shadow_ai.col_status")}</th>
                  <th style={{ whiteSpace: "nowrap" }}>{t("shadow_ai.col_time")}</th>
                  <th style={{ width: "1%", whiteSpace: "nowrap", textAlign: "right" }}>
                    {t("common.actions")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {loading && (
                  <tr className="empty-row">
                    <td colSpan={6}>{t("common.loading")}</td>
                  </tr>
                )}
                {!loading && filteredSightings.length === 0 && (
                  <tr className="empty-row">
                    <td colSpan={6}>{t("shadow_ai.empty_open")}</td>
                  </tr>
                )}
                {filteredSightings.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <div style={{ fontWeight: 600, color: "var(--text-primary)" }}>{s.tool_name}</div>
                      {(() => {
                        const meta = renderDisplayMeta(s);
                        if (meta) {
                          return (
                            <div className="text-muted" style={{ fontSize: "11px", marginTop: 2 }}>
                              {meta}
                            </div>
                          );
                        }
                        // Fall back to showing the domain only when it is a
                        // real domain, never the internal "local:..." key.
                        if (s.domain && s.domain !== s.tool_name && !s.domain.startsWith("local:")) {
                          return (
                            <div className="mono text-muted" style={{ fontSize: "11px", marginTop: 2 }}>
                              {s.domain}
                            </div>
                          );
                        }
                        return null;
                      })()}
                      {(s.seen_count ?? 1) > 1 && (
                        <div style={{ fontSize: "11px", marginTop: 2, color: "var(--accent, #2451d9)" }}>
                          {t("shadow_ai.seen_times", { count: s.seen_count })}
                        </div>
                      )}
                      {s.notes && (
                        <div
                          className="hint-text"
                          style={{
                            fontSize: "11px",
                            maxWidth: 360,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                            marginTop: 2,
                          }}
                        >
                          {s.notes}
                        </div>
                      )}
                    </td>
                    <td>{renderSourceBadge(s.detected_via)}</td>
                    <td style={{ fontSize: "12px" }}>{s.user_hint || "—"}</td>
                    <td>
                      <StatusPill status={s.status} />
                    </td>
                    <td className="mono" style={{ fontSize: "11px", whiteSpace: "nowrap" }}>
                      {new Date(s.created_at).toLocaleString(i18n.language, {
                        year: "numeric",
                        month: "numeric",
                        day: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </td>
                    <td style={{ width: "1%", whiteSpace: "nowrap", textAlign: "right" }}>
                      <div
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          justifyContent: "flex-end",
                          gap: 6,
                        }}
                      >
                        {canReview && s.status === "new" && (
                          <button
                            className="btn btn-sm"
                            disabled={busyId === s.id}
                            onClick={() => handleSetStatus(s.id, "reviewing")}
                            style={{ padding: "4px 8px", fontSize: "11px" }}
                          >
                            {t("shadow_ai.action_take")}
                          </button>
                        )}
                        {canRegister && s.status !== "registered" && (
                          <button
                            className="btn btn-sm btn-primary"
                            disabled={busyId === s.id}
                            onClick={() => setRegisterTarget(s)}
                            style={{ padding: "4px 8px", fontSize: "11px" }}
                          >
                            {t("shadow_ai.action_register")}
                          </button>
                        )}
                        {canReview && s.status !== "dismissed" && s.status !== "registered" && (
                          <button
                            className="btn btn-sm"
                            disabled={busyId === s.id}
                            onClick={() => handleSetStatus(s.id, "dismissed")}
                            style={{ padding: "4px 7px", fontSize: "11px" }}
                          >
                            {t("shadow_ai.action_dismiss")}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Modal for Sanctioning */}
        {registerTarget && (
          <div
            style={{
              position: "fixed",
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              backgroundColor: "rgba(0,0,0,0.4)",
              backdropFilter: "blur(2px)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              zIndex: 1000,
            }}
          >
            <div className="panel" style={{ width: 440, maxWidth: "90vw", margin: 0, boxShadow: "0 8px 30px rgba(0,0,0,0.12)" }}>
              <div className="panel-header">
                <h2>{t("shadow_ai.confirm_register_title")}</h2>
              </div>
              <div className="panel-body">
                <p style={{ marginBottom: 14, fontSize: "13px" }}>
                  {t("shadow_ai.confirm_register_msg")}{" "}
                  <strong>{registerTarget.tool_name}</strong> {registerTarget.domain && `(${registerTarget.domain})`}
                </p>

                <div className="field" style={{ marginBottom: 16 }}>
                  <label htmlFor="p_type">{t("shadow_ai.provider_type")}</label>
                  <select
                    id="p_type"
                    value={providerType}
                    onChange={(e) => setProviderType(e.target.value)}
                  >
                    <option value="custom">Custom API Provider</option>
                    <option value="openai">OpenAI Compatible</option>
                    <option value="anthropic">Anthropic</option>
                    <option value="ollama">Local Ollama / vLLM</option>
                  </select>
                </div>

                <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
                  <button
                    className="btn btn-sm"
                    onClick={() => setRegisterTarget(null)}
                    disabled={busyId !== null}
                  >
                    {t("common.cancel")}
                  </button>
                  <button
                    className="btn btn-sm btn-primary"
                    onClick={handleRegisterConfirm}
                    disabled={busyId !== null}
                  >
                    {busyId ? t("common.loading") : t("shadow_ai.register_btn")}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
