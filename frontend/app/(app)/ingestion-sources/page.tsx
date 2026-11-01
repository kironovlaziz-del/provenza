"use client";

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { LoadError } from "@/components/LoadError";
import { apiErrorMessage } from "@/lib/inventory_api";
import { Form } from "@/components/Form";
import {
  createIngestionSource,
  listIngestionSources,
  revokeIngestionSource,
  updateIngestionSource,
  downloadBrowserExtension,
} from "@/lib/api";
import type { IngestionSource, IngestionSourceType } from "@/lib/types";

export default function IngestionSourcesPage() {
  const { t, i18n } = useTranslation();
  const [sources, setSources] = useState<IngestionSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [downloadingExt, setDownloadingExt] = useState(false);
  async function handleDownloadExtension() {
    setDownloadingExt(true);
    try {
      await downloadBrowserExtension();
    } catch {
      // best-effort: endpoint admin-only, 500 только если шаблон расширения отсутствует на сервере
    } finally {
      setDownloadingExt(false);
    }
  }
  const [busyId, setBusyId] = useState<number | null>(null);

  const [name, setName] = useState("");
  const [sourceType, setSourceType] = useState<IngestionSourceType>("gateway");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // The raw key only ever exists in memory, right after creation - it is
  // never returned by the API again, so there is nothing to fetch or
  // restore here on refresh.
  const [revealedKey, setRevealedKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  function refresh() {
    setLoading(true);
    listIngestionSources()
      .then((v) => { setSources(v); setLoadError(null); })
      .catch((e) => setLoadError(apiErrorMessage(e, t("common.load_failed"))))
      .finally(() => setLoading(false));
  }

  useEffect(refresh, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const created = await createIngestionSource({ name, source_type: sourceType });
      setRevealedKey(created.api_key);
      setCopied(false);
      setName("");
      setSourceType("gateway");
      setShowForm(false);
      refresh();
    } catch {
      setError(t("ingestion_sources.failed"));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleToggleEnabled(source: IngestionSource) {
    setBusyId(source.id);
    try {
      await updateIngestionSource(source.id, { enabled: !source.enabled });
      refresh();
    } finally {
      setBusyId(null);
    }
  }

  async function handleRevoke(id: number) {
    setBusyId(id);
    try {
      await revokeIngestionSource(id);
      refresh();
    } finally {
      setBusyId(null);
    }
  }

  async function handleCopy() {
    if (!revealedKey) return;
    try {
      await navigator.clipboard.writeText(revealedKey);
      setCopied(true);
    } catch {
      // Clipboard API can be unavailable (e.g. insecure context) - the
      // key is still selectable/visible in the panel either way.
    }
  }

  return (
    <>
      <PageHeader
        title={t("ingestion_sources.title")}
        actions={
          <>
          <button className="btn btn-sm" onClick={handleDownloadExtension} disabled={downloadingExt} style={{ marginRight: 8 }}>
            {downloadingExt ? t("common.loading") : t("ingestion_sources.download_extension")}
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => setShowForm((s) => !s)}>
            {showForm ? t("ingestion_sources.cancel") : t("ingestion_sources.new")}
          </button>
          </>
        }
      />
      <div className="content">
          <LoadError message={loadError} onRetry={refresh} />
        <p className="hint-text u-mb-16">{t("ingestion_sources.hint")}</p>

        {revealedKey && (
          <div className="panel" style={{ marginBottom: 20, borderColor: "var(--danger, #c0392b)" }}>
            <div className="panel-header">
              <h2>{t("ingestion_sources.key_reveal_title")}</h2>
            </div>
            <div className="panel-body">
              <p className="error-text" style={{ marginBottom: 12 }}>
                {t("ingestion_sources.key_reveal_warning")}
              </p>
              <div className="form-row" style={{ alignItems: "center" }}>
                <code className="mono" style={{ wordBreak: "break-all", flex: 1 }}>
                  {revealedKey}
                </code>
                <button type="button" className="btn btn-sm" onClick={handleCopy}>
                  {copied ? t("ingestion_sources.copied") : t("ingestion_sources.copy")}
                </button>
              </div>
              <button
                type="button"
                className="btn btn-sm"
                style={{ marginTop: 12 }}
                onClick={() => setRevealedKey(null)}
              >
                {t("ingestion_sources.dismiss")}
              </button>
            </div>
          </div>
        )}

        {showForm && (
          <div className="panel" style={{ marginBottom: 20 }}>
            <div className="panel-header">
              <h2>{t("ingestion_sources.form_title")}</h2>
            </div>
            <div className="panel-body">
              <Form onSubmit={handleCreate}>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="name">{t("ingestion_sources.name")}</label>
                    <input
                      id="name"
                      required
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder={t("ingestion_sources.name_placeholder")}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="source_type">{t("ingestion_sources.source_type")}</label>
                    <select
                      id="source_type"
                      value={sourceType}
                      onChange={(e) => setSourceType(e.target.value as IngestionSourceType)}
                    >
                      <option value="gateway">{t("ingestion_sources.type_gateway")}</option>
                      <option value="endpoint">{t("ingestion_sources.type_endpoint")}</option>
                      <option value="browser_extension">
                        {t("ingestion_sources.type_browser_extension")}
                      </option>
                    </select>
                  </div>
                </div>
                {error && <p className="error-text">{error}</p>}
                <button className="btn btn-primary" type="submit" disabled={submitting}>
                  {submitting ? t("ingestion_sources.submitting") : t("ingestion_sources.submit")}
                </button>
              </Form>
            </div>
          </div>
        )}

        <div className="panel">
          <div className="panel-header">
            <h2>{t("ingestion_sources.table_title")}</h2>
          </div>
          <table>
            <thead>
              <tr>
                <th>{t("ingestion_sources.col_name")}</th>
                <th>{t("ingestion_sources.col_type")}</th>
                <th>{t("ingestion_sources.col_status")}</th>
                <th>{t("ingestion_sources.col_last_seen")}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr className="empty-row">
                  <td colSpan={5}>{t("common.loading")}</td>
                </tr>
              )}
              {!loading && sources.length === 0 && (
                <tr className="empty-row">
                  <td colSpan={5}>{t("ingestion_sources.empty")}</td>
                </tr>
              )}
              {sources.map((source) => (
                <tr key={source.id}>
                  <td>{source.name}</td>
                  <td>
                    {t(`ingestion_sources.type_${source.source_type}`, source.source_type)}
                  </td>
                  <td>
                    <span className={`pill ${source.enabled ? "pill-low" : "pill-neutral"}`}>
                      {source.enabled
                        ? t("ingestion_sources.enabled")
                        : t("ingestion_sources.disabled")}
                    </span>
                  </td>
                  <td className="mono">
                    {source.last_seen_at
                      ? new Date(source.last_seen_at).toLocaleString(i18n.language)
                      : t("ingestion_sources.never_seen")}
                  </td>
                  <td className="u-nowrap">
                    <div className="u-btn-row">
                      <button
                        className="btn btn-sm"
                        disabled={busyId === source.id}
                        onClick={() => handleToggleEnabled(source)}
                      >
                        {source.enabled
                          ? t("ingestion_sources.disable")
                          : t("ingestion_sources.enable")}
                      </button>
                      <button
                        className="btn btn-sm btn-danger"
                        disabled={busyId === source.id || !source.enabled}
                        onClick={() => handleRevoke(source.id)}
                      >
                        {t("ingestion_sources.revoke")}
                      </button>
                    </div>
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
