"use client";

// Incidents of the platform (AI usage, data leaks, blocked domains, ...):
// anyone reports one, reviewers (admin, approver) triage it.

import React, { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { Form } from "@/components/Form";
import { RiskPill, StatusPill } from "@/components/Pill";
import { createIncident, listIncidentsPage, updateIncidentStatus } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { Incident, RiskLevel } from "@/lib/types";

const SEVERITIES: RiskLevel[] = ["critical", "high", "medium", "low"];
const STATUSES = ["open", "investigating", "resolved"];

export function PlatformIncidents() {
  const { t, i18n } = useTranslation();
  const { user } = useAuth();
  const canTriage = user?.role === "admin" || user?.role === "approver"; // the API refuses others

  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [query, setQuery] = useState("");
  const [busyId, setBusyId] = useState<number | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ severity: "medium" as RiskLevel, category: "", summary: "", impact: "" });
  const [submitting, setSubmitting] = useState(false);

  function refresh() {
    setLoading(true);
    setError(null);
    listIncidentsPage(0, 200)
      .then((page) => setIncidents(page.items))
      .catch(() => setError(t("incidents.load_failed")))
      .finally(() => setLoading(false));
  }
  useEffect(refresh, []); // eslint-disable-line react-hooks/exhaustive-deps

  const stats = useMemo(() => ({
    total: incidents.length,
    open: incidents.filter((i) => i.status === "open").length,
    investigating: incidents.filter((i) => i.status === "investigating").length,
    severe: incidents.filter((i) => i.status !== "resolved" && (i.severity === "critical" || i.severity === "high")).length,
  }), [incidents]);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return incidents.filter((i) =>
      (status === "all" || i.status === status) &&
      (severity === "all" || i.severity === severity) &&
      (!q || [i.summary, i.category, i.impact ?? ""].some((v) => v.toLowerCase().includes(q))));
  }, [incidents, status, severity, query]);

  async function setIncidentStatus(id: number, next: string) {
    setBusyId(id);
    try {
      await updateIncidentStatus(id, next);
      refresh();
    } finally {
      setBusyId(null);
    }
  }

  async function report(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await createIncident({ severity: form.severity, category: form.category, summary: form.summary,
                             impact: form.impact || undefined });
      setForm({ severity: "medium", category: "", summary: "", impact: "" });
      setShowForm(false);
      refresh();
    } catch {
      setError(t("incidents.failed"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <div className="stat-grid u-mb-16">
        <div className="stat"><div className="stat-label">{t("incidents.stat_total")}</div><div className="stat-value">{stats.total}</div></div>
        <div className="stat"><div className="stat-label">{t("incidents.stat_open")}</div><div className="stat-value">{stats.open}</div></div>
        <div className="stat"><div className="stat-label">{t("incidents.stat_investigating")}</div><div className="stat-value">{stats.investigating}</div></div>
        <div className="stat"><div className="stat-label">{t("incidents.stat_critical")}</div><div className="stat-value">{stats.severe}</div></div>
      </div>

      {showForm && (
        <div className="panel u-mb-16">
          <div className="panel-header"><h2>{t("incidents.form_title")}</h2></div>
          <div className="panel-body">
            <Form onSubmit={report}>
              <div className="form-row">
                <div className="field">
                  <label htmlFor="inc-severity">{t("incidents.severity")}</label>
                  <select id="inc-severity" value={form.severity}
                          onChange={(e) => setForm({ ...form, severity: e.target.value as RiskLevel })}>
                    {SEVERITIES.map((s) => <option key={s} value={s}>{t(`risk.${s}`, s)}</option>)}
                  </select>
                </div>
                <div className="field">
                  <label htmlFor="inc-category">{t("incidents.category")}</label>
                  <input id="inc-category" required maxLength={100} value={form.category}
                         placeholder={t("incidents.category_placeholder")}
                         onChange={(e) => setForm({ ...form, category: e.target.value })} />
                </div>
              </div>
              <div className="field">
                <label htmlFor="inc-summary">{t("incidents.summary")}</label>
                <input id="inc-summary" required maxLength={2000} value={form.summary}
                       placeholder={t("incidents.summary_placeholder")}
                       onChange={(e) => setForm({ ...form, summary: e.target.value })} />
              </div>
              <div className="field">
                <label htmlFor="inc-impact">{t("incidents.impact")}</label>
                <textarea id="inc-impact" rows={3} maxLength={10000} value={form.impact}
                          placeholder={t("incidents.impact_placeholder")}
                          onChange={(e) => setForm({ ...form, impact: e.target.value })} />
              </div>
              <button className="btn btn-primary" type="submit" disabled={submitting}>
                {submitting ? t("incidents.submitting") : t("incidents.submit")}
              </button>
            </Form>
          </div>
        </div>
      )}

      <div className="panel">
        <div className="panel-header u-flex u-justify-between u-items-center u-flex-wrap u-gap-8">
          <h2>{t("incidents.table_title")}</h2>
          <div className="u-row-tight u-items-center">
            <input type="search" value={query} placeholder={t("incidents.search_placeholder")}
                   onChange={(e) => setQuery(e.target.value)} style={{ width: 200 }} />
            <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label={t("incidents.col_status")}>
              <option value="all">{t("incidents.filter_status_all")}</option>
              {STATUSES.map((s) => <option key={s} value={s}>{t(`incidents.filter_status_${s}`)}</option>)}
            </select>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label={t("incidents.col_severity")}>
              <option value="all">{t("incidents.filter_severity_all")}</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{t(`incidents.filter_severity_${s}`)}</option>)}
            </select>
            <button className="btn btn-sm btn-primary" onClick={() => setShowForm((v) => !v)}>
              {showForm ? t("incidents.cancel") : t("incidents.new")}
            </button>
          </div>
        </div>
        {error && <p className="error-text" style={{ padding: "0 16px" }}>{error}</p>}
        <div style={{ overflowX: "auto" }}>
          <table>
            <thead>
              <tr>
                <th>{t("incidents.col_severity")}</th>
                <th>{t("incidents.col_summary")}</th>
                <th>{t("incidents.col_category")}</th>
                <th>{t("incidents.col_status")}</th>
                <th>{t("incidents.col_detected_at")}</th>
                {canTriage && <th></th>}
              </tr>
            </thead>
            <tbody>
              {loading && <tr className="empty-row"><td colSpan={6}>{t("common.loading")}</td></tr>}
              {!loading && shown.length === 0 && <tr className="empty-row"><td colSpan={6}>{t("incidents.empty")}</td></tr>}
              {shown.map((i) => (
                <tr key={i.id}>
                  <td><RiskPill level={i.severity} /></td>
                  <td>
                    <Link href={`/incidents/${i.id}`}><strong>{i.summary}</strong></Link>
                    {i.impact && <div className="hint-text">{i.impact}</div>}
                    {i.request_id && (
                      <div className="hint-text">
                        <Link href={`/requests/${i.request_id}`}>{t("incidents.detail.linked_request")} #{i.request_id}</Link>
                      </div>
                    )}
                  </td>
                  <td className="u-mono">{i.category}</td>
                  <td><StatusPill status={i.status} /></td>
                  <td className="u-mono u-nowrap">{new Date(i.created_at).toLocaleString(i18n.language)}</td>
                  {canTriage && (
                    <td className="u-nowrap">
                      <div className="u-btn-row">
                        {i.status === "open" && (
                          <button className="btn btn-sm" disabled={busyId === i.id}
                                  onClick={() => setIncidentStatus(i.id, "investigating")}>
                            {t("incidents.btn_investigate")}
                          </button>
                        )}
                        {i.status !== "resolved" ? (
                          <button className="btn btn-sm btn-primary" disabled={busyId === i.id}
                                  onClick={() => setIncidentStatus(i.id, "resolved")}>
                            {t("incidents.btn_resolve")}
                          </button>
                        ) : (
                          <button className="btn btn-sm" disabled={busyId === i.id}
                                  onClick={() => setIncidentStatus(i.id, "open")}>
                            {t("incidents.btn_reopen")}
                          </button>
                        )}
                      </div>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
