"use client";

import Link from "next/link";
import React, { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslation } from "react-i18next";
import { Form } from "@/components/Form";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import {
  apiErrorMessage,
  createSystem,
  getInventoryMeta,
  getInventorySummary,
  listSystems,
  syncInventory,
  type InventoryFilters,
} from "@/lib/inventory_api";
import {
  LIFECYCLE_STAGES,
  RISK_TIERS,
  SYSTEM_KINDS,
  type AISystemT,
  type InventoryMeta,
  type InventorySummary,
  type SystemKind,
} from "@/lib/inventory_types";
import { AttentionList, StagePill, TierPill } from "./InventoryBadges";

const NO_FILTERS: InventoryFilters = { kind: "", stage: "", tier: "", review_status: "", q: "" };
const PAGE_SIZE = 10;

function Stat({ label, value, tone }: { label: string; value: number; tone?: "warn" | "danger" }) {
  const color = value > 0 && tone === "danger" ? "#ef4444" : value > 0 && tone === "warn" ? "#d97706" : undefined;
  return (
    <div style={{ minWidth: 120 }}>
      <div className="hint-text">{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700, color }}>{value}</div>
    </div>
  );
}

export default function InventoryPage() {
  const router = useRouter();
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [meta, setMeta] = useState<InventoryMeta | null>(null);
  const [summary, setSummary] = useState<InventorySummary | null>(null);
  const [systems, setSystems] = useState<AISystemT[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [filters, setFilters] = useState<InventoryFilters>(NO_FILTERS);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);

  const [showForm, setShowForm] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [form, setForm] = useState({
    name: "",
    kind: "other" as SystemKind,
    domain: "general",
    lifecycle_stage: "idea" as "idea" | "development" | "validation",
    description: "",
  });

  const refresh = useCallback(() => {
    setLoading(true);
    Promise.all([listSystems(filters, page * PAGE_SIZE, PAGE_SIZE), getInventorySummary()])
      .then(([page, s]) => {
        setSystems(page.items);
        setTotal(page.total);
        setSummary(s);
        setError(null);
      })
      .catch((e) => setError(apiErrorMessage(e, t("inventory.load_failed", "Could not load the inventory."))))
      .finally(() => setLoading(false));
  }, [filters, page, t]);

  useEffect(() => {
    getInventoryMeta().then(setMeta).catch(() => undefined);
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // debounce the search box
  useEffect(() => {
    const id = setTimeout(() => {
      setFilters((f) => (f.q === search ? f : { ...f, q: search }));
      setPage((p) => (p === 0 ? p : 0));
    }, 300);
    return () => clearTimeout(id);
  }, [search]);

  function setFilter(key: keyof InventoryFilters, value: string) {
    setFilters((f) => ({ ...f, [key]: value }));
    setPage(0);
  }

  async function handleSync() {
    setSyncing(true);
    setNotice(null);
    try {
      const res = await syncInventory();
      setNotice(
        res.created > 0
          ? t("inventory.synced", { count: res.created, defaultValue: `${res.created} new system(s) discovered` })
          : t("inventory.synced_none", "The inventory is up to date"),
      );
      refresh();
    } catch (e) {
      setError(apiErrorMessage(e, t("inventory.failed", "Could not save.")));
    } finally {
      setSyncing(false);
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const created = await createSystem({
        name: form.name,
        kind: form.kind,
        domain: form.domain,
        lifecycle_stage: form.lifecycle_stage,
        description: form.description || undefined,
      });
      router.push(`/inventory/${created.id}`);
    } catch (err) {
      setError(apiErrorMessage(err, t("inventory.failed", "Could not save.")));
      setSubmitting(false);
    }
  }

  const domainLabel = (id: string) =>
    t(`inventory.domains.${id}`, meta?.domains.find((d) => d.id === id)?.label ?? id);

  return (
    <>
      <PageHeader
        title={t("inventory.title", "AI Inventory")}
        actions={
          isAdmin ? (
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn btn-sm" onClick={handleSync} disabled={syncing}>
                {syncing ? t("inventory.syncing", "Syncing…") : t("inventory.sync", "Sync now")}
              </button>
              <button className="btn btn-primary btn-sm" onClick={() => setShowForm((s) => !s)}>
                {showForm ? t("inventory.cancel", "Cancel") : t("inventory.new", "Add system")}
              </button>
            </div>
          ) : undefined
        }
      />
      <div className="content">
        <p className="hint-text" style={{ marginTop: 0, marginBottom: 16 }}>
          {t(
            "inventory.subtitle",
            "Every model, agent and AI service in the organization — with owner, lifecycle stage and EU AI Act risk tier.",
          )}
        </p>

        {error && (
          <div className="panel" style={{ marginBottom: 16, borderColor: "#ef4444" }}>
            <div className="panel-body" style={{ color: "#ef4444" }}>{error}</div>
          </div>
        )}
        {notice && <div className="hint-text" style={{ marginBottom: 16 }}>{notice}</div>}

        {summary && (
          <div className="panel" style={{ marginBottom: 20 }}>
            <div className="panel-body" style={{ display: "flex", gap: 32, flexWrap: "wrap", alignItems: "flex-start" }}>
              <Stat label={t("inventory.summary.total", "AI systems")} value={summary.total} />
              <Stat label={t("inventory.summary.unreviewed", "Unreviewed")} value={summary.unreviewed} tone="warn" />
              <Stat
                label={t("inventory.summary.prod_unconfirmed", "In production without confirmed risk")}
                value={summary.in_production_without_confirmed_risk}
                tone="danger"
              />
              <div>
                <div className="hint-text">{t("inventory.summary.by_tier", "By risk tier")}</div>
                <div style={{ display: "flex", gap: 12, marginTop: 6, flexWrap: "wrap" }}>
                  {RISK_TIERS.map((tier) => (
                    <button
                      key={tier}
                      type="button"
                      onClick={() => setFilter("tier", filters.tier === tier ? "" : tier)}
                      style={{
                        background: "none",
                        border: "none",
                        padding: 0,
                        cursor: "pointer",
                        display: "inline-flex",
                        gap: 6,
                        alignItems: "center",
                        color: "inherit",
                        textDecoration: filters.tier === tier ? "underline" : "none",
                      }}
                    >
                      <TierPill tier={tier} confirmed />
                      <strong>{summary.by_tier[tier] ?? 0}</strong>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {showForm && isAdmin && (
          <div className="panel" style={{ marginBottom: 20 }}>
            <div className="panel-header">
              <h2>{t("inventory.form_title", "Add an AI system manually")}</h2>
            </div>
            <div className="panel-body">
              <Form onSubmit={handleCreate}>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="inv-name">{t("inventory.name", "Name")}</label>
                    <input
                      id="inv-name"
                      required
                      maxLength={255}
                      value={form.name}
                      onChange={(e) => setForm({ ...form, name: e.target.value })}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="inv-kind">{t("inventory.kind", "Type")}</label>
                    <select
                      id="inv-kind"
                      value={form.kind}
                      onChange={(e) => setForm({ ...form, kind: e.target.value as SystemKind })}
                    >
                      {SYSTEM_KINDS.map((k) => (
                        <option key={k} value={k}>{t(`inventory.kinds.${k}`, k)}</option>
                      ))}
                    </select>
                  </div>
                </div>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="inv-domain">{t("inventory.domain", "Domain")}</label>
                    <select
                      id="inv-domain"
                      value={form.domain}
                      onChange={(e) => setForm({ ...form, domain: e.target.value })}
                    >
                      {(meta?.domains ?? [{ id: "general", label: "General", annex_iii: null }]).map((d) => (
                        <option key={d.id} value={d.id}>
                          {domainLabel(d.id)}
                          {d.annex_iii ? " · Annex III" : ""}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="field">
                    <label htmlFor="inv-stage">{t("inventory.stage", "Lifecycle stage")}</label>
                    <select
                      id="inv-stage"
                      value={form.lifecycle_stage}
                      onChange={(e) =>
                        setForm({ ...form, lifecycle_stage: e.target.value as "idea" | "development" | "validation" })
                      }
                    >
                      {(["idea", "development", "validation"] as const).map((s) => (
                        <option key={s} value={s}>{t(`inventory.stages.${s}`, s)}</option>
                      ))}
                    </select>
                  </div>
                </div>
                <div className="field">
                  <label htmlFor="inv-desc">{t("inventory.description", "Description")}</label>
                  <textarea
                    id="inv-desc"
                    rows={2}
                    value={form.description}
                    onChange={(e) => setForm({ ...form, description: e.target.value })}
                  />
                </div>
                <p className="hint-text">
                  {t("inventory.form_hint", "Risk flags and data links can be set on the system page after it is created.")}
                </p>
                <button className="btn btn-primary" type="submit" disabled={submitting}>
                  {submitting ? t("inventory.submitting", "Adding…") : t("inventory.submit", "Add system")}
                </button>
              </Form>
            </div>
          </div>
        )}

        <div className="panel" style={{ marginBottom: 16 }}>
          <div className="panel-body" style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "flex-end" }}>
            <div className="field" style={{ margin: 0, minWidth: 200 }}>
              <label htmlFor="inv-q">{t("inventory.filters.search", "Search by name")}</label>
              <input id="inv-q" value={search} onChange={(e) => setSearch(e.target.value)} />
            </div>
            <div className="field" style={{ margin: 0 }}>
              <label htmlFor="inv-f-kind">{t("inventory.filters.kind", "Type")}</label>
              <select id="inv-f-kind" value={filters.kind} onChange={(e) => setFilter("kind", e.target.value)}>
                <option value="">{t("inventory.filters.all", "All")}</option>
                {SYSTEM_KINDS.map((k) => (
                  <option key={k} value={k}>{t(`inventory.kinds.${k}`, k)}</option>
                ))}
              </select>
            </div>
            <div className="field" style={{ margin: 0 }}>
              <label htmlFor="inv-f-stage">{t("inventory.filters.stage", "Stage")}</label>
              <select id="inv-f-stage" value={filters.stage} onChange={(e) => setFilter("stage", e.target.value)}>
                <option value="">{t("inventory.filters.all", "All")}</option>
                {LIFECYCLE_STAGES.map((s) => (
                  <option key={s} value={s}>{t(`inventory.stages.${s}`, s)}</option>
                ))}
              </select>
            </div>
            <div className="field" style={{ margin: 0 }}>
              <label htmlFor="inv-f-tier">{t("inventory.filters.tier", "Risk tier")}</label>
              <select id="inv-f-tier" value={filters.tier} onChange={(e) => setFilter("tier", e.target.value)}>
                <option value="">{t("inventory.filters.all", "All")}</option>
                {RISK_TIERS.map((tier) => (
                  <option key={tier} value={tier}>{t(`inventory.tiers.${tier}`, tier)}</option>
                ))}
              </select>
            </div>
            <div className="field" style={{ margin: 0 }}>
              <label htmlFor="inv-f-review">{t("inventory.filters.review", "Review")}</label>
              <select
                id="inv-f-review"
                value={filters.review_status}
                onChange={(e) => setFilter("review_status", e.target.value)}
              >
                <option value="">{t("inventory.filters.all", "All")}</option>
                <option value="unreviewed">{t("inventory.review.unreviewed", "Unreviewed")}</option>
                <option value="reviewed">{t("inventory.review.reviewed", "Reviewed")}</option>
              </select>
            </div>
            {(filters.kind || filters.stage || filters.tier || filters.review_status || search) && (
              <button
                className="btn btn-sm"
                type="button"
                onClick={() => {
                  setSearch("");
                  setFilters(NO_FILTERS);
                  setPage(0);
                }}
              >
                {t("inventory.filters.reset", "Reset filters")}
              </button>
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-body" style={{ overflowX: "auto" }}>
            {loading && <div className="hint-text">{t("common.loading", "Loading…")}</div>}
            <table>
              <thead>
                <tr>
                  <th>{t("inventory.col_name", "Name")}</th>
                  <th>{t("inventory.col_kind", "Type")}</th>
                  <th>{t("inventory.col_stage", "Stage")}</th>
                  <th>{t("inventory.col_risk", "Risk tier")}</th>
                  <th>{t("inventory.col_review", "Review")}</th>
                  <th>{t("inventory.col_attention", "Attention")}</th>
                </tr>
              </thead>
              <tbody>
                {systems.map((s) => (
                  <tr key={s.id} style={{ cursor: "pointer" }} onClick={() => router.push(`/inventory/${s.id}`)}>
                    <td>
                      <Link href={`/inventory/${s.id}`} onClick={(e) => e.stopPropagation()}>
                        <strong>{s.name}</strong>
                      </Link>
                      <div className="hint-text" style={{ fontSize: 11 }}>
                        {domainLabel(s.domain)}
                        {s.source_key ? ` · ${s.source_key}` : ""}
                      </div>
                    </td>
                    <td>{t(`inventory.kinds.${s.kind}`, s.kind)}</td>
                    <td><StagePill stage={s.lifecycle_stage} /></td>
                    <td><TierPill tier={s.effective_risk_tier} confirmed={!!s.confirmed_risk_tier} /></td>
                    <td>{t(`inventory.review.${s.review_status}`, s.review_status)}</td>
                    <td><AttentionList items={s.attention} compact /></td>
                  </tr>
                ))}
                {!loading && systems.length === 0 && (
                  <tr>
                    <td colSpan={6} className="hint-text">{t("inventory.empty", "No AI systems match these filters.")}</td>
                  </tr>
                )}
              </tbody>
            </table>
            {total > PAGE_SIZE && (
              <div style={{ display: "flex", gap: 12, alignItems: "center", justifyContent: "flex-end", marginTop: 12 }}>
                <button
                  type="button"
                  className="btn btn-sm"
                  disabled={page === 0 || loading}
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                >
                  {t("common.prev", "Prev")}
                </button>
                <span className="hint-text">
                  {page * PAGE_SIZE + 1}-{Math.min((page + 1) * PAGE_SIZE, total)} / {total}
                </span>
                <button
                  type="button"
                  className="btn btn-sm"
                  disabled={(page + 1) * PAGE_SIZE >= total || loading}
                  onClick={() => setPage((p) => p + 1)}
                >
                  {t("common.next", "Next")}
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
