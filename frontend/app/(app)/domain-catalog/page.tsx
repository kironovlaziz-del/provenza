"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { LoadError } from "@/components/LoadError";
import { apiErrorMessage } from "@/lib/inventory_api";
import { Form } from "@/components/Form";
import { StatusPill } from "@/components/Pill";
import {
  createDomainCatalogEntry,
  deleteDomainCatalogEntry,
  getDomainCatalogSeedSuggestions,
  listDomainCatalog,
  importKnownDomains,
  updateDomainCatalogEntry,
} from "@/lib/api";
import type { DomainCatalogEntry, DomainPolicyStatus, SeedDomainHint } from "@/lib/types";

function matchSeedHint(domain: string, seeds: SeedDomainHint[]): SeedDomainHint | null {
  const d = domain.trim().toLowerCase();
  if (!d) return null;
  const exact = seeds.find((s) => s.domain === d);
  if (exact) return exact;
  return seeds.find((s) => d.endsWith("." + s.domain)) ?? null;
}

export default function DomainCatalogPage() {
  const { t, i18n } = useTranslation();
  const [entries, setEntries] = useState<DomainCatalogEntry[]>([]);
  const [seeds, setSeeds] = useState<SeedDomainHint[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [page, setPage] = useState(0);
  const [importing, setImporting] = useState(false);
  const PAGE_SIZE = 10;
  async function handleImportKnown() {
    setImporting(true);
    try {
      await importKnownDomains();
      setPage(0);
      refresh();
    } finally {
      setImporting(false);
    }
  }

  const [domain, setDomain] = useState("");
  const [toolName, setToolName] = useState("");
  const [category, setCategory] = useState("");
  const [policyStatus, setPolicyStatus] = useState<DomainPolicyStatus>("unknown");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  function refresh() {
    setLoading(true);
    listDomainCatalog()
      .then((v) => { setEntries(v); setLoadError(null); })
      .catch((e) => setLoadError(apiErrorMessage(e, t("common.load_failed"))))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    refresh();
    getDomainCatalogSeedSuggestions().then(setSeeds);
  }, []);

  const seedHint = useMemo(() => matchSeedHint(domain, seeds), [domain, seeds]);
  const canApplyHint = !!seedHint && !toolName && !category;

  function applyHint() {
    if (!seedHint) return;
    setToolName(seedHint.tool_name);
    setCategory(seedHint.category);
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await createDomainCatalogEntry({
        domain,
        tool_name: toolName || undefined,
        category: category || undefined,
        policy_status: policyStatus,
      });
      setDomain("");
      setToolName("");
      setCategory("");
      setPolicyStatus("unknown");
      setShowForm(false);
      refresh();
    } catch {
      setError(t("domain_catalog.failed"));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleStatusChange(entry: DomainCatalogEntry, status: DomainPolicyStatus) {
    setBusyId(entry.id);
    try {
      await updateDomainCatalogEntry(entry.id, { policy_status: status });
      refresh();
    } finally {
      setBusyId(null);
    }
  }

  async function handleDelete(id: number) {
    setBusyId(id);
    try {
      await deleteDomainCatalogEntry(id);
      refresh();
    } finally {
      setBusyId(null);
    }
  }

  return (
    <>
      <PageHeader
        title={t("domain_catalog.title")}
        actions={
          <>
          <button type="button" className="btn btn-sm" onClick={handleImportKnown} disabled={importing} style={{ marginRight: 8 }}>
            {importing ? t("common.loading") : t("domain_catalog.import_known")}
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => setShowForm((s) => !s)}>
            {showForm ? t("domain_catalog.cancel") : t("domain_catalog.new")}
          </button>
        </>
        }
      />
      <div className="content">
          <LoadError message={loadError} onRetry={refresh} />
        <p className="hint-text u-mb-16">{t("domain_catalog.hint")}</p>

        {showForm && (
          <div className="panel" style={{ marginBottom: 20 }}>
            <div className="panel-header">
              <h2>{t("domain_catalog.form_title")}</h2>
            </div>
            <div className="panel-body">
              <Form onSubmit={handleCreate}>
                <div className="field">
                  <label htmlFor="domain">{t("domain_catalog.domain")}</label>
                  <input
                    id="domain"
                    required
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                    placeholder={t("domain_catalog.domain_placeholder")}
                  />
                  {canApplyHint && (
                    <p className="hint-text" style={{ marginTop: 6 }}>
                      {t("domain_catalog.seed_hint", {
                        tool: seedHint!.tool_name,
                        category: seedHint!.category,
                      })}{" "}
                      <button type="button" className="btn btn-sm" onClick={applyHint}>
                        {t("domain_catalog.seed_hint_apply")}
                      </button>
                    </p>
                  )}
                </div>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="tool_name">{t("domain_catalog.tool_name")}</label>
                    <input
                      id="tool_name"
                      value={toolName}
                      onChange={(e) => setToolName(e.target.value)}
                      placeholder={t("domain_catalog.tool_name_placeholder")}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="category">{t("domain_catalog.category")}</label>
                    <input
                      id="category"
                      value={category}
                      onChange={(e) => setCategory(e.target.value)}
                      placeholder={t("domain_catalog.category_placeholder")}
                    />
                  </div>
                </div>
                <div className="field">
                  <label htmlFor="policy_status">{t("domain_catalog.policy_status")}</label>
                  <select
                    id="policy_status"
                    value={policyStatus}
                    onChange={(e) => setPolicyStatus(e.target.value as DomainPolicyStatus)}
                  >
                    <option value="allowed">{t("domain_catalog.status_allowed")}</option>
                    <option value="blocked">{t("domain_catalog.status_blocked")}</option>
                    <option value="unknown">{t("domain_catalog.status_unknown")}</option>
                  </select>
                </div>
                {error && <p className="error-text">{error}</p>}
                <button className="btn btn-primary" type="submit" disabled={submitting}>
                  {submitting ? t("domain_catalog.submitting") : t("domain_catalog.submit")}
                </button>
              </Form>
            </div>
          </div>
        )}

        <div className="panel">
          <div className="panel-header">
            <h2>{t("domain_catalog.table_title")}</h2>
          </div>
          <div id="dc-scroll" style={{ overflowX: "auto", width: "100%" }}>
          <table style={{ minWidth: 720 }}>
            <thead>
              <tr>
                <th>{t("domain_catalog.col_domain")}</th>
                <th>{t("domain_catalog.col_tool")}</th>
                <th>{t("domain_catalog.col_category")}</th>
                <th>{t("domain_catalog.col_status")}</th>
                <th>{t("domain_catalog.col_added")}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr className="empty-row">
                  <td colSpan={6}>{t("common.loading")}</td>
                </tr>
              )}
              {!loading && entries.length === 0 && (
                <tr className="empty-row">
                  <td colSpan={6}>{t("domain_catalog.empty")}</td>
                </tr>
              )}
              {entries.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE).map((entry) => (
                <tr key={entry.id}>
                  <td className="mono">{entry.domain}</td>
                  <td>{entry.tool_name || "—"}</td>
                  <td>{entry.category || "—"}</td>
                  <td>
                    <StatusPill status={entry.policy_status} />
                  </td>
                  <td className="mono">
                    {new Date(entry.created_at).toLocaleDateString(i18n.language)}
                  </td>
                  <td className="u-nowrap" style={{ textAlign: "right", verticalAlign: "middle" }}>
                    <div style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
                      {entry.policy_status !== "blocked" && (
                        <button
                          className="btn btn-sm"
                          disabled={busyId === entry.id}
                          onClick={() => handleStatusChange(entry, "blocked")}
                          title={t("domain_catalog.action_block")}
                          style={{ padding: "3px 10px", fontSize: 12, color: "#dc2626", borderColor: "#dc2626" }}
                        >
                          {t("domain_catalog.action_block")}
                        </button>
                      )}
                      {entry.policy_status !== "allowed" && (
                        <button
                          className="btn btn-sm"
                          disabled={busyId === entry.id}
                          onClick={() => handleStatusChange(entry, "allowed")}
                          title={t("domain_catalog.action_allow")}
                          style={{ padding: "3px 10px", fontSize: 12, color: "#2f9e63", borderColor: "#2f9e63" }}
                        >
                          {t("domain_catalog.action_allow")}
                        </button>
                      )}
                      <button
                        className="btn btn-sm"
                        disabled={busyId === entry.id}
                        onClick={() => handleDelete(entry.id)}
                        style={{ padding: "3px 10px", fontSize: 12, color: "var(--text-muted,#64748b)" }}
                      >
                        {t("domain_catalog.delete")}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
          {entries.length > PAGE_SIZE && (
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 4px", fontSize: 13 }}>
              <button type="button" className="btn btn-sm" disabled={page === 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>{t("common.prev")}</button>
              <span className="hint-text">{page * PAGE_SIZE + 1}-{Math.min((page + 1) * PAGE_SIZE, entries.length)} / {entries.length}</span>
              <button type="button" className="btn btn-sm" disabled={(page + 1) * PAGE_SIZE >= entries.length} onClick={() => setPage((p) => p + 1)}>{t("common.next")}</button>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
