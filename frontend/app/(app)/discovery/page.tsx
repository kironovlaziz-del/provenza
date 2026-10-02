"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { Form } from "@/components/Form";
import {
  listDiscoveredServices,
  connectDiscoveredService,
  ignoreDiscoveredService,
  getServiceConnection,
  reverifyServiceConnection,
} from "@/lib/api";
import type { DiscoveredService, ServiceConnection } from "@/lib/types";
import { translateApiError } from "@/lib/errors";

const SERVICE_ICONS: Record<string, string> = {
  dns: "🌐",
  dhcp: "📡",
  active_directory: "🏛️",
  ldap: "🏛️",
  kerberos: "🔑",
  firewall: "🧱",
  unknown: "❓",
};

function statusClass(status: string): string {
  switch (status) {
    case "connected":
      return "pill-low";
    case "needs_credentials":
      return "pill-medium";
    case "error":
      return "pill-critical";
    case "ignored":
      return "pill-neutral";
    default:
      return "pill-medium"; // discovered
  }
}

export default function DiscoveryPage() {
  const { t, i18n } = useTranslation();
  const [services, setServices] = useState<DiscoveredService[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [connDetails, setConnDetails] = useState<Record<number, ServiceConnection | null>>({});

  async function toggleDetails(serviceId: number) {
    if (expandedId === serviceId) {
      setExpandedId(null);
      return;
    }
    setExpandedId(serviceId);
    if (!(serviceId in connDetails)) {
      try {
        const conn = await getServiceConnection(serviceId);
        setConnDetails((m) => ({ ...m, [serviceId]: conn }));
      } catch {
        setConnDetails((m) => ({ ...m, [serviceId]: null }));
      }
    }
  }

  async function handleReverify(serviceId: number) {
    setBusyId(serviceId);
    try {
      const conn = await reverifyServiceConnection(serviceId);
      setConnDetails((m) => ({ ...m, [serviceId]: conn }));
    } finally {
      setBusyId(null);
    }
  }

  // Connect modal
  const [connectTarget, setConnectTarget] = useState<DiscoveredService | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [caPem, setCaPem] = useState("");
  const [bindDn, setBindDn] = useState("");
  const [baseDn, setBaseDn] = useState("");
  const [apiToken, setApiToken] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [connectResult, setConnectResult] = useState<string | null>(null);

  function refresh() {
    setLoading(true);
    listDiscoveredServices()
      .then(setServices)
      .finally(() => setLoading(false));
  }

  useEffect(refresh, []);

  const summary = useMemo(() => {
    const s = { total: services.length, discovered: 0, connected: 0, needs: 0, ignored: 0 };
    for (const svc of services) {
      if (svc.connect_status === "connected") s.connected += 1;
      else if (svc.connect_status === "needs_credentials") s.needs += 1;
      else if (svc.connect_status === "ignored") s.ignored += 1;
      else if (svc.connect_status === "discovered") s.discovered += 1;
    }
    return s;
  }, [services]);

  function openConnect(svc: DiscoveredService) {
    setConnectTarget(svc);
    setCaPem("");
    setUsername("");
    setPassword("");
    setBindDn("");
    setBaseDn("");
    setApiToken("");
    setConnectResult(null);
  }

  async function handleConnect(e: React.FormEvent) {
    e.preventDefault();
    if (!connectTarget) return;
    setSubmitting(true);
    setConnectResult(null);
    try {
      const updated = await connectDiscoveredService(connectTarget.id, {
        username: username || undefined,
        password: password || undefined,
        bind_dn: bindDn || undefined,
        base_dn: baseDn || undefined,
        api_token: apiToken || undefined,
        // Credentials only go to the address shown in this dialog.
        expected_host: connectTarget.host,
        expected_port: connectTarget.port ?? null,
        tls_ca_pem: caPem.trim() || undefined,
      });
      // The backend deliberately reports honest outcomes, including
      // "needs_credentials" when a service type has no connect handler
      // yet - surface that message rather than pretending success.
      if (updated.connect_status === "connected") {
        setConnectTarget(null);
        refresh();
      } else {
        setConnectResult(updated.connect_error || t("discovery.connect_failed"));
        refresh();
      }
    } catch (err) {
      const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
      setConnectResult(translateApiError(detail, t, t("discovery.connect_failed")));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleIgnore(id: number) {
    setBusyId(id);
    try {
      await ignoreDiscoveredService(id);
      refresh();
    } finally {
      setBusyId(null);
    }
  }

  return (
    <>
      <PageHeader title={t("discovery.title")} />
      <div className="content">
        <p className="hint-text u-mb-16">{t("discovery.hint")}</p>

        <div className="stat-grid" style={{ marginBottom: 20 }}>
          <div className="stat">
            <div className="stat-label">{t("discovery.stat_total")}</div>
            <div className="stat-value">{summary.total}</div>
          </div>
          <div className="stat">
            <div className="stat-label">{t("discovery.stat_discovered")}</div>
            <div className="stat-value" style={{ color: "var(--accent, #2451d9)" }}>
              {summary.discovered}
            </div>
          </div>
          <div className="stat">
            <div className="stat-label">{t("discovery.stat_connected")}</div>
            <div className="stat-value" style={{ color: "var(--risk-low, #2f9e63)" }}>
              {summary.connected}
            </div>
          </div>
          <div className="stat">
            <div className="stat-label">{t("discovery.stat_needs")}</div>
            <div className="stat-value" style={{ color: "var(--risk-medium, #b8860b)" }}>
              {summary.needs}
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <h2>{t("discovery.table_title")}</h2>
          </div>
          <div style={{ width: "100%", overflowX: "auto" }}>
            <table style={{ width: "100%", minWidth: 640 }}>
              <thead>
                <tr>
                  <th>{t("discovery.col_service")}</th>
                  <th>{t("discovery.col_host")}</th>
                  <th>{t("discovery.col_via")}</th>
                  <th>{t("discovery.col_status")}</th>
                  <th style={{ width: "1%", whiteSpace: "nowrap", textAlign: "right" }}>
                    {t("common.actions")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {loading && (
                  <tr className="empty-row">
                    <td colSpan={5}>{t("common.loading")}</td>
                  </tr>
                )}
                {!loading && services.length === 0 && (
                  <tr className="empty-row">
                    <td colSpan={5}>{t("discovery.empty")}</td>
                  </tr>
                )}
                {services.map((svc) => (
                  <React.Fragment key={svc.id}>
                  <tr>
                    <td>
                      <div style={{ fontWeight: 600 }}>
                        {SERVICE_ICONS[svc.service_type] || "❓"}{" "}
                        {t(`discovery.type_${svc.service_type}`, svc.service_type)}
                      </div>
                      {svc.details && (svc.details as Record<string, unknown>).domain != null && (
                        <div className="mono text-muted" style={{ fontSize: "11px", marginTop: 2 }}>
                          {String((svc.details as Record<string, unknown>).domain)}
                        </div>
                      )}
                    </td>
                    <td className="mono" style={{ fontSize: "12px" }}>
                      {svc.host}
                      {svc.port ? `:${svc.port}` : ""}
                    </td>
                    <td style={{ fontSize: "12px" }}>
                      {t(`discovery.via_${svc.discovered_via}`, svc.discovered_via)}
                    </td>
                    <td>
                      <span className={`pill ${statusClass(svc.connect_status)}`}>
                        {t(`discovery.status_${svc.connect_status}`, svc.connect_status)}
                      </span>
                      {svc.connect_error && (
                        <div
                          className="hint-text"
                          style={{ fontSize: "11px", marginTop: 2, maxWidth: 280 }}
                        >
                          {svc.connect_error}
                        </div>
                      )}
                    </td>
                    <td style={{ width: "1%", whiteSpace: "nowrap", textAlign: "right" }}>
                      <div style={{ display: "inline-flex", gap: 6, justifyContent: "flex-end" }}>
                        {svc.connect_status === "connected" && (
                          <button
                            className="btn btn-sm"
                            onClick={() => toggleDetails(svc.id)}
                            style={{ padding: "4px 8px", fontSize: "11px" }}
                          >
                            {t("discovery.details_btn")}
                          </button>
                        )}
                        {svc.connect_status !== "connected" &&
                          svc.connect_status !== "ignored" && (
                            <button
                              className="btn btn-sm btn-primary"
                              disabled={busyId === svc.id}
                              onClick={() => openConnect(svc)}
                              style={{ padding: "4px 8px", fontSize: "11px" }}
                            >
                              {t("discovery.action_connect")}
                            </button>
                          )}
                        {svc.connect_status !== "ignored" && (
                          <button
                            className="btn btn-sm"
                            disabled={busyId === svc.id}
                            onClick={() => handleIgnore(svc.id)}
                            style={{ padding: "4px 8px", fontSize: "11px" }}
                          >
                            {t("discovery.action_ignore")}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                  {expandedId === svc.id && (
                    <tr>
                      <td colSpan={5} style={{ background: "var(--bg-app, #f5f6f8)" }}>
                        {(() => {
                          const conn = connDetails[svc.id];
                          if (conn === undefined) {
                            return <span className="hint-text">{t("common.loading")}</span>;
                          }
                          if (conn === null) {
                            return <span className="hint-text">{t("discovery.conn_none")}</span>;
                          }
                          const info = (conn.info || {}) as Record<string, unknown>;
                          return (
                            <div style={{ fontSize: "12px", display: "flex", flexDirection: "column", gap: 4, padding: "4px 0" }}>
                              {conn.bind_dn && (
                                <div><strong>{t("discovery.conn_bind_dn")}:</strong> <span className="mono">{conn.bind_dn}</span></div>
                              )}
                              {conn.base_dn && (
                                <div><strong>{t("discovery.conn_base_dn")}:</strong> <span className="mono">{conn.base_dn}</span></div>
                              )}
                              {typeof info.person_count === "number" && (
                                <div><strong>{t("discovery.conn_person_count")}:</strong> {String(info.person_count)}{info.person_count_capped ? "+" : ""}</div>
                              )}
                              {info.reachable === true && (
                                <div><strong>{t("discovery.conn_reachable")}:</strong> ✅</div>
                              )}
                              {conn.last_verified_at && (
                                <div>
                                  <strong>{t("discovery.conn_last_verified")}:</strong>{" "}
                                  {new Date(conn.last_verified_at).toLocaleString(i18n.language)}
                                </div>
                              )}
                              {conn.last_error && (
                                <div style={{ color: "var(--risk-critical, #c1352f)" }}>
                                  <strong>{t("discovery.conn_error")}:</strong> {conn.last_error}
                                </div>
                              )}
                              <div style={{ marginTop: 6 }}>
                                <button
                                  className="btn btn-sm"
                                  disabled={busyId === svc.id}
                                  onClick={() => handleReverify(svc.id)}
                                  style={{ padding: "4px 10px", fontSize: "11px" }}
                                >
                                  {busyId === svc.id
                                    ? t("common.loading")
                                    : t("discovery.reverify_btn")}
                                </button>
                              </div>
                            </div>
                          );
                        })()}
                      </td>
                    </tr>
                  )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {connectTarget && (
          <div
            style={{
              position: "fixed",
              inset: 0,
              backgroundColor: "rgba(0,0,0,0.4)",
              backdropFilter: "blur(2px)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              zIndex: 1000,
            }}
          >
            <div
              className="panel"
              style={{ width: 460, maxWidth: "90vw", margin: 0, boxShadow: "0 8px 30px rgba(0,0,0,0.12)" }}
            >
              <div className="panel-header">
                <h2>
                  {t("discovery.connect_title")}{" "}
                  {t(`discovery.type_${connectTarget.service_type}`, connectTarget.service_type)}
                </h2>
              </div>
              <div className="panel-body">
                <p className="hint-text" style={{ marginBottom: 8 }}>
                  {t("discovery.connect_hint", { host: connectTarget.host })}
                </p>
                <p style={{ marginBottom: 14 }}>
                  {t("discovery.connect_target")}:{" "}
                  <strong className="mono">
                    {connectTarget.host}
                    {connectTarget.port ? `:${connectTarget.port}` : ""}
                  </strong>
                  <br />
                  <span className="hint-text">
                    {t("discovery.connect_reported", {
                      source: String(connectTarget.details?.reported_by ?? "—"),
                      via: connectTarget.discovered_via,
                    })}
                  </span>
                  <br />
                  <span className="hint-text">{t("discovery.connect_target_check")}</span>
                </p>
                <Form onSubmit={handleConnect}>
                  <div className="form-row">
                    <div className="field">
                      <label>{t("discovery.field_username")}</label>
                      <input value={username} onChange={(e) => setUsername(e.target.value)} />
                    </div>
                    <div className="field">
                      <label>{t("discovery.field_password")}</label>
                      <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="field">
                    <label>{t("discovery.field_bind_dn")}</label>
                    <input
                      value={bindDn}
                      onChange={(e) => setBindDn(e.target.value)}
                      placeholder="CN=svc,DC=corp,DC=local"
                    />
                  </div>
                  <div className="field">
                    <label>{t("discovery.field_base_dn")}</label>
                    <input
                      value={baseDn}
                      onChange={(e) => setBaseDn(e.target.value)}
                      placeholder="DC=corp,DC=local"
                    />
                  </div>
                  <div className="field">
                    <label>{t("discovery.field_api_token")}</label>
                    <input value={apiToken} onChange={(e) => setApiToken(e.target.value)} />
                  </div>
                  {(connectTarget.service_type === "active_directory" || connectTarget.service_type === "ldap") && (
                    <div className="field">
                      <label>{t("discovery.field_ca_pem")}</label>
                      <textarea
                        className="mono"
                        rows={3}
                        value={caPem}
                        onChange={(e) => setCaPem(e.target.value)}
                        placeholder="-----BEGIN CERTIFICATE-----"
                      />
                      <span className="hint-text">{t("discovery.field_ca_pem_hint")}</span>
                    </div>
                  )}

                  {connectResult && (
                    <p className="error-text" style={{ marginTop: 4 }}>
                      {connectResult}
                    </p>
                  )}

                  <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", marginTop: 8 }}>
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => setConnectTarget(null)}
                      disabled={submitting}
                    >
                      {t("common.cancel")}
                    </button>
                    <button className="btn btn-sm btn-primary" type="submit" disabled={submitting}>
                      {submitting ? t("common.loading") : t("discovery.connect_submit")}
                    </button>
                  </div>
                </Form>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
