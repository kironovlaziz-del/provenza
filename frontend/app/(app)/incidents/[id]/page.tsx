"use client";

import React, { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { RiskPill, StatusPill } from "@/components/Pill";
import { getIncident, updateIncident } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { Incident } from "@/lib/types";

export default function IncidentDetailPage() {
  const params = useParams<{ id: string }>();
  const incidentId = Number(params.id);
  const { t, i18n } = useTranslation();
  const { user } = useAuth();
  const canTriage = user?.role === "admin" || user?.role === "approver"; // the API refuses others

  const [incident, setIncident] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(true);
  const [rootCause, setRootCause] = useState("");
  const [status, setStatus] = useState("open");
  const [saving, setSaving] = useState(false);

  function refresh() {
    setLoading(true);
    getIncident(incidentId)
      .then((i) => {
        setIncident(i);
        setRootCause(i.root_cause || "");
        setStatus(i.status);
      })
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    if (!Number.isNaN(incidentId)) refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incidentId]);

  async function handleSave() {
    setSaving(true);
    try {
      const updated = await updateIncident(incidentId, { root_cause: rootCause, status });
      setIncident(updated);
    } finally {
      setSaving(false);
    }
  }

  if (loading || !incident) {
    return (
      <>
        <PageHeader title={t("incidents.title")} />
        <div className="content">
          <p className="loading-line">{t("incidents.detail.loading")}</p>
        </div>
      </>
    );
  }

  return (
    <>
      <PageHeader title={`#${incident.id}`} />
      <div className="content">
        <div className="breadcrumb">
          <Link href="/incidents">{t("incidents.detail.breadcrumb")}</Link> / #{incident.id}
        </div>

        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-body">
            <dl className="kv-grid">
              <dt>{t("incidents.detail.category")}</dt>
              <dd>{incident.category}</dd>
              <dt>{t("incidents.detail.summary")}</dt>
              <dd>{incident.summary}</dd>
              <dt>{t("incidents.detail.impact")}</dt>
              <dd>{incident.impact || "—"}</dd>
              <dt>{t("incidents.detail.severity")}</dt>
              <dd>
                <RiskPill level={incident.severity} />
              </dd>
              <dt>{t("incidents.detail.status")}</dt>
              <dd>
                <StatusPill status={incident.status} />
              </dd>
              <dt>{t("incidents.detail.linked_request")}</dt>
              <dd className="mono">
                {incident.request_id ? (
                  <Link href={`/requests/${incident.request_id}`}>
                    #{incident.request_id}
                  </Link>
                ) : (
                  "—"
                )}
              </dd>
              <dt>{t("incidents.detail.created")}</dt>
              <dd className="mono">
                {new Date(incident.created_at).toLocaleString(i18n.language)}
              </dd>
              <dt>{t("incidents.detail.closed")}</dt>
              <dd className="mono">
                {incident.resolved_at
                  ? new Date(incident.resolved_at).toLocaleString(i18n.language)
                  : "—"}
              </dd>
            </dl>
          </div>
        </div>

        {canTriage && <div className="panel">
          <div className="panel-header">
            <h2>{t("incidents.detail.investigation_title")}</h2>
          </div>
          <div className="panel-body">
            <div className="field">
              <label htmlFor="root_cause">{t("incidents.detail.root_cause")}</label>
              <textarea
                id="root_cause"
                value={rootCause}
                onChange={(e) => setRootCause(e.target.value)}
                placeholder={t("incidents.detail.root_cause_placeholder")}
              />
            </div>
            <div className="field" style={{ maxWidth: 220 }}>
              <label htmlFor="status">{t("incidents.detail.status_label")}</label>
              <select id="status" value={status} onChange={(e) => setStatus(e.target.value)}>
                <option value="open">{t("status.open")}</option>
                <option value="investigating">{t("status.investigating")}</option>
                <option value="resolved">{t("status.resolved")}</option>
              </select>
            </div>
            <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
              {saving ? t("incidents.detail.saving") : t("incidents.detail.save")}
            </button>
          </div>
        </div>}
      </div>
    </>
  );
}