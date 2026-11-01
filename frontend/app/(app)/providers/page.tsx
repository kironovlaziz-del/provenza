"use client";

import { Form } from "@/components/Form";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { LoadError } from "@/components/LoadError";
import { apiErrorMessage } from "@/lib/inventory_api";
import { StatusPill } from "@/components/Pill";
import { createProvider, listProviders, updateProvider } from "@/lib/api";
import type { Provider } from "@/lib/types";

export default function ProvidersPage() {
  const { t } = useTranslation();
  const [providers, setProviders] = useState<Provider[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [type, setType] = useState("openai");
  const [sla, setSla] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  function refresh() {
    setLoading(true);
    listProviders()
      .then((v) => { setProviders(v); setLoadError(null); })
      .catch((e) => setLoadError(apiErrorMessage(e, t("common.load_failed"))))
      .finally(() => setLoading(false));
  }

  useEffect(refresh, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await createProvider({ name, type, sla: sla || undefined });
      setName("");
      setSla("");
      setShowForm(false);
      refresh();
    } catch {
      setError(t("providers.failed"));
    } finally {
      setSubmitting(false);
    }
  }

  async function toggleStatus(p: Provider) {
    const next = p.status === "active" ? "suspended" : "active";
    await updateProvider(p.id, { status: next });
    refresh();
  }

  return (
    <>
      <PageHeader
        title={t("providers.title")}
        actions={
          <button className="btn btn-primary btn-sm" onClick={() => setShowForm((s) => !s)}>
            {showForm ? t("providers.cancel") : t("providers.new")}
          </button>
        }
      />
      <div className="content">
          <LoadError message={loadError} onRetry={refresh} />
        {showForm && (
          <div className="panel" style={{ marginBottom: 20 }}>
            <div className="panel-header">
              <h2>{t("providers.form_title")}</h2>
            </div>
            <div className="panel-body">
              <Form onSubmit={handleCreate}>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="name">{t("providers.name")}</label>
                    <input
                      id="name"
                      required
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder={t("providers.name_placeholder")}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="type">{t("providers.type")}</label>
                    <input
                      id="type"
                      required
                      value={type}
                      onChange={(e) => setType(e.target.value)}
                      placeholder={t("providers.type_placeholder")}
                    />
                  </div>
                </div>
                <div className="field">
                  <label htmlFor="sla">{t("providers.sla")}</label>
                  <input
                    id="sla"
                    value={sla}
                    onChange={(e) => setSla(e.target.value)}
                    placeholder={t("providers.sla_placeholder")}
                  />
                </div>
                {error && <p className="error-text">{error}</p>}
                <button className="btn btn-primary" type="submit" disabled={submitting}>
                  {submitting ? t("providers.submitting") : t("providers.submit")}
                </button>
              </Form>
            </div>
          </div>
        )}

        <div className="panel">
          <div className="panel-header">
            <h2>{t("providers.title")}</h2>
          </div>
          <table>
            <thead>
              <tr>
                <th>{t("providers.col_id")}</th>
                <th>{t("providers.col_name")}</th>
                <th>{t("providers.col_type")}</th>
                <th>{t("providers.col_sla")}</th>
                <th>{t("providers.col_risk")}</th>
                <th>{t("providers.col_status")}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr className="empty-row">
                  <td colSpan={7}>{t("common.loading")}</td>
                </tr>
              )}
              {!loading && providers.length === 0 && (
                <tr className="empty-row">
                  <td colSpan={7}>{t("providers.empty")}</td>
                </tr>
              )}
              {providers.map((p) => (
                <tr key={p.id}>
                  <td className="mono">#{p.id}</td>
                  <td>{p.name}</td>
                  <td className="mono">{p.type}</td>
                  <td>{p.sla || "—"}</td>
                  <td className="mono">{p.risk_score.toFixed(1)}</td>
                  <td>
                    <StatusPill status={p.status} />
                  </td>
                  <td>
                    <button className="btn btn-sm" onClick={() => toggleStatus(p)}>
                      {p.status === "active"
                        ? t("providers.suspend")
                        : t("providers.activate")}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}