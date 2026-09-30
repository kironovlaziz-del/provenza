"use client";

import Link from "next/link";
import React, { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import {
  addDataLink,
  apiErrorMessage,
  changeStage,
  confirmRisk,
  getInventoryMeta,
  getSystem,
  getSystemMetrics,
  listDatasetOptions,
  removeDataLink,
  updateSystem,
} from "@/lib/inventory_api";
import {
  LIFECYCLE_STAGES,
  RISK_TIERS,
  type AISystemT,
  type DataLinkT,
  type DataRelation,
  type InventoryMeta,
  type RiskTier,
  type SystemMetrics,
} from "@/lib/inventory_types";
import { AttentionList, StagePill, TierPill } from "../InventoryBadges";

const SOURCE_PAGE: Record<string, string> = {
  agent: "/agents",
  llm_provider: "/providers",
  model: "/deployments",
  shadow: "/shadow-ai",
};

const FLAG_GROUPS = ["prohibited", "safety", "transparency", "modifiers"] as const;

function sameSet(a: string[], b: string[]) {
  return a.length === b.length && [...a].sort().join("|") === [...b].sort().join("|");
}

export default function InventorySystemPage() {
  const params = useParams();
  const id = Number(params?.id);
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const canConfirm = isAdmin || user?.role === "approver";

  const [system, setSystem] = useState<AISystemT | null>(null);
  const [meta, setMeta] = useState<InventoryMeta | null>(null);
  const [datasets, setDatasets] = useState<{ id: number; name: string }[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [windowDays, setWindowDays] = useState(30);

  const [details, setDetails] = useState({ name: "", description: "", business_owner: "" });
  const [domain, setDomain] = useState("general");
  const [flags, setFlags] = useState<string[]>([]);
  const [tier, setTier] = useState<RiskTier>("minimal");
  const [justification, setJustification] = useState("");
  const [link, setLink] = useState({
    relation: "accesses" as DataRelation,
    target: "external" as "external" | "dataset",
    external_name: "",
    dataset_id: "",
    contains_pii: false,
  });

  const apply = useCallback((s: AISystemT) => {
    setSystem(s);
    setDetails({ name: s.name, description: s.description ?? "", business_owner: s.business_owner ?? "" });
    setDomain(s.domain);
    setFlags(s.risk_flags ?? []);
    setTier((s.suggested_risk_tier ?? "minimal") as RiskTier);
    setJustification("");
  }, []);

  useEffect(() => {
    if (!Number.isFinite(id)) return;
    getSystem(id)
      .then(apply)
      .catch((e) => setError(apiErrorMessage(e, t("inventory.load_failed", "Could not load the inventory."))));
    getInventoryMeta().then(setMeta).catch(() => undefined);
    listDatasetOptions().then(setDatasets).catch(() => undefined);
  }, [id, apply, t]);

  useEffect(() => {
    if (!Number.isFinite(id)) return;
    getSystemMetrics(id, windowDays).then(setMetrics).catch(() => setMetrics(null));
  }, [id, windowDays]);

  async function run(action: () => Promise<AISystemT>, okMessage?: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      apply(await action());
      if (okMessage) setNotice(okMessage);
    } catch (e) {
      setError(apiErrorMessage(e, t("inventory.failed", "Could not save.")));
    } finally {
      setBusy(false);
    }
  }

  if (!system) {
    return (
      <>
        <PageHeader title={t("inventory.title", "AI Inventory")} />
        <div className="content">
          <Link href="/inventory" className="btn btn-sm" style={{ marginBottom: 16 }}>
            ← {t("inventory.detail.back", "Back to inventory")}
          </Link>
          <div className="hint-text">{error ?? t("common.loading", "Loading…")}</div>
        </div>
      </>
    );
  }

  const s = system;
  const suggested = s.suggested_risk_tier ?? null;
  const needsJustification = tier !== suggested;
  const inputsChanged = domain !== s.domain || !sameSet(flags, s.risk_flags ?? []);
  const prodBlockedReason = !s.confirmed_risk_tier
    ? t("inventory.detail.prod_needs_confirmation", "Confirm the risk tier before moving to production.")
    : s.confirmed_risk_tier === "unacceptable"
      ? t("inventory.detail.prod_unacceptable", "Unacceptable-risk systems cannot go to production.")
      : null;
  const domainLabel = (d: string) => t(`inventory.domains.${d}`, meta?.domains.find((x) => x.id === d)?.label ?? d);
  const sourcePage = SOURCE_PAGE[s.kind];
  const linkTarget = (l: DataLinkT) =>
    l.external_name ??
    (l.dataset_id != null
      ? datasets.find((d) => d.id === l.dataset_id)?.name ??
        t("inventory.detail.dataset_label", { id: l.dataset_id, defaultValue: `Dataset #${l.dataset_id}` })
      : t("inventory.detail.collection_label", { id: l.collection_id, defaultValue: `Knowledge base #${l.collection_id}` }));

  return (
    <>
      <PageHeader title={s.name} />
      <div className="content">
        <Link href="/inventory" className="btn btn-sm" style={{ marginBottom: 16 }}>
          ← {t("inventory.detail.back", "Back to inventory")}
        </Link>

        {error && (
          <div className="panel" style={{ marginBottom: 16, borderColor: "#ef4444" }}>
            <div className="panel-body" style={{ color: "#ef4444" }}>{error}</div>
          </div>
        )}
        {notice && <div className="hint-text" style={{ marginBottom: 16 }}>{notice}</div>}

        {/* ---- overview ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-body" style={{ display: "flex", gap: 28, flexWrap: "wrap" }}>
            <div>
              <div className="hint-text">{t("inventory.col_kind", "Type")}</div>
              <strong>{t(`inventory.kinds.${s.kind}`, s.kind)}</strong>
            </div>
            <div>
              <div className="hint-text">{t("inventory.col_stage", "Stage")}</div>
              <StagePill stage={s.lifecycle_stage} />
            </div>
            <div>
              <div className="hint-text">{t("inventory.col_risk", "Risk tier")}</div>
              <TierPill tier={s.effective_risk_tier} confirmed={!!s.confirmed_risk_tier} />
            </div>
            <div>
              <div className="hint-text">{t("inventory.domain", "Domain")}</div>
              <strong>{domainLabel(s.domain)}</strong>
            </div>
            <div>
              <div className="hint-text">{t("inventory.detail.source", "Source")}</div>
              {s.source_key ? (
                sourcePage ? (
                  <Link href={sourcePage} className="mono" style={{ fontSize: 12 }}>{s.source_key}</Link>
                ) : (
                  <span className="mono" style={{ fontSize: 12 }}>{s.source_key}</span>
                )
              ) : (
                <span>{t("inventory.detail.manual", "Added manually")}</span>
              )}
            </div>
          </div>
          {s.attention.length > 0 && (
            <div className="panel-body" style={{ paddingTop: 0 }}>
              <AttentionList items={s.attention} />
            </div>
          )}
        </div>

        {/* ---- activity & trust signals ---- */}
        {metrics && (
          <div className="panel" style={{ marginBottom: 20 }}>
            <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
              <h2>{t("inventory.metrics.title", "Activity")}</h2>
              <div style={{ display: "flex", gap: 6 }}>
                {[7, 30, 90].map((d) => (
                  <button
                    key={d}
                    type="button"
                    className={`btn btn-sm${d === windowDays ? " btn-primary" : ""}`}
                    onClick={() => setWindowDays(d)}
                  >
                    {t("inventory.metrics.days", { days: d, defaultValue: `${d} days` })}
                  </button>
                ))}
              </div>
            </div>
            <div className="panel-body">
              {metrics.source === null ? (
                <p className="hint-text" style={{ margin: 0 }}>
                  {t(
                    "inventory.metrics.no_source",
                    "No activity source is linked to this system. Activity is tracked for agents, LLM providers, deployed models and shadow-AI tools.",
                  )}
                </p>
              ) : (
                <>
                  <div style={{ display: "flex", gap: 28, flexWrap: "wrap" }}>
                    {Object.entries(metrics.counts).map(([key, value]) => (
                      <div key={key}>
                        <div className="hint-text">{t(`inventory.metrics.counts.${key}`, key)}</div>
                        <div style={{ fontSize: 22, fontWeight: 700 }}>{value}</div>
                      </div>
                    ))}
                    {Object.entries(metrics.rates).map(([key, value]) => (
                      <div key={key}>
                        <div className="hint-text">{t(`inventory.metrics.rates.${key}`, key)}</div>
                        <div style={{ fontSize: 22, fontWeight: 700 }}>
                          {key.endsWith("_rate") ? `${Math.round(value * 1000) / 10}%` : value}
                        </div>
                      </div>
                    ))}
                    <div>
                      <div className="hint-text">{t("inventory.metrics.last_activity", "Last activity")}</div>
                      <div style={{ fontSize: 14, fontWeight: 600, marginTop: 6 }}>
                        {metrics.last_activity_at
                          ? new Date(metrics.last_activity_at).toLocaleString()
                          : t("inventory.metrics.never", "Never")}
                      </div>
                    </div>
                  </div>
                  {metrics.signals.length > 0 && (
                    <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 14 }}>
                      {metrics.signals.map((sig) => (
                        <div
                          key={sig}
                          style={{
                            padding: "8px 12px",
                            borderRadius: 6,
                            fontSize: 13,
                            background: "rgba(245,158,11,0.12)",
                            color: "#d97706",
                          }}
                        >
                          ● {t(`inventory.metrics.signals.${sig}`, sig)}
                        </div>
                      ))}
                    </div>
                  )}
                  <p className="hint-text" style={{ marginBottom: 0, marginTop: 12 }}>
                    {t("inventory.metrics.hint", "Signals are prompts for a reviewer, not verdicts.")}
                  </p>
                </>
              )}
            </div>
          </div>
        )}

        {/* ---- risk classification ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header">
            <h2>{t("inventory.detail.risk_title", "EU AI Act risk classification")}</h2>
          </div>
          <div className="panel-body">
            <div style={{ display: "flex", gap: 28, flexWrap: "wrap", marginBottom: 12 }}>
              <div>
                <div className="hint-text">{t("inventory.detail.suggested", "Suggested")}</div>
                <TierPill tier={suggested} />
              </div>
              <div>
                <div className="hint-text">{t("inventory.detail.confirmed", "Confirmed")}</div>
                {s.confirmed_risk_tier ? (
                  <TierPill tier={s.confirmed_risk_tier} confirmed />
                ) : (
                  <span className="hint-text">{t("inventory.detail.not_confirmed", "Not confirmed")}</span>
                )}
              </div>
              {s.risk_confirmed_at && (
                <div>
                  <div className="hint-text">&nbsp;</div>
                  <span className="hint-text">
                    {t("inventory.detail.confirmed_by", {
                      id: s.risk_confirmed_by,
                      date: new Date(s.risk_confirmed_at).toLocaleString(),
                      defaultValue: `Confirmed by user #${s.risk_confirmed_by} on ${new Date(s.risk_confirmed_at).toLocaleString()}`,
                    })}
                  </span>
                </div>
              )}
            </div>

            {s.risk_justification && (
              <div style={{ marginBottom: 12 }}>
                <div className="hint-text">{t("inventory.detail.justification", "Justification")}</div>
                <div>{s.risk_justification}</div>
              </div>
            )}

            {s.risk_assessment && (
              <>
                <div className="hint-text" style={{ marginBottom: 6 }}>{t("inventory.detail.rationale", "Why")}</div>
                <ul style={{ margin: "0 0 12px 18px", padding: 0 }}>
                  {s.risk_assessment.rationale.map((r, i) => (
                    <li key={i} style={{ marginBottom: 4 }}>
                      <TierPill tier={r.tier} confirmed /> <span style={{ fontSize: 13 }}>{r.reference}</span>
                    </li>
                  ))}
                </ul>
                {s.risk_assessment.notes.length > 0 && (
                  <>
                    <div className="hint-text" style={{ marginBottom: 6 }}>{t("inventory.detail.notes", "Notes")}</div>
                    <ul style={{ margin: "0 0 12px 18px", padding: 0 }}>
                      {s.risk_assessment.notes.map((n, i) => (
                        <li key={i} className="hint-text" style={{ marginBottom: 4 }}>{n}</li>
                      ))}
                    </ul>
                  </>
                )}
              </>
            )}

            {canConfirm && (
              <div style={{ borderTop: "1px solid var(--border, #334155)", paddingTop: 12, marginTop: 8 }}>
                <h3 style={{ fontSize: 14, margin: "0 0 8px" }}>{t("inventory.detail.confirm_title", "Confirm the risk tier")}</h3>
                <p className="hint-text" style={{ marginTop: 0 }}>
                  {t(
                    "inventory.detail.disclaimer",
                    "The classifier only suggests a tier. The decision and its justification are yours and are recorded in the audit log.",
                  )}
                </p>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="confirm-tier">{t("inventory.detail.confirm_tier", "Tier")}</label>
                    <select id="confirm-tier" value={tier} onChange={(e) => setTier(e.target.value as RiskTier)}>
                      {RISK_TIERS.map((x) => (
                        <option key={x} value={x}>
                          {t(`inventory.tiers.${x}`, x)}
                          {x === suggested ? ` (${t("inventory.detail.suggested", "Suggested").toLowerCase()})` : ""}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="field" style={{ flex: 2 }}>
                    <label htmlFor="confirm-just">
                      {t("inventory.detail.confirm_justification", "Justification")}
                      {needsJustification ? " *" : ""}
                    </label>
                    <textarea
                      id="confirm-just"
                      rows={2}
                      maxLength={2000}
                      value={justification}
                      onChange={(e) => setJustification(e.target.value)}
                    />
                    {needsJustification && (
                      <div className="hint-text">
                        {t(
                          "inventory.detail.confirm_justification_required",
                          "Required because the tier differs from the suggestion.",
                        )}
                      </div>
                    )}
                  </div>
                </div>
                <button
                  className="btn btn-primary btn-sm"
                  disabled={busy || (needsJustification && !justification.trim())}
                  onClick={() =>
                    run(() => confirmRisk(s.id, tier, justification.trim() || undefined), t("inventory.detail.saved", "Saved"))
                  }
                >
                  {t("inventory.detail.confirm_submit", "Confirm tier")}
                </button>
              </div>
            )}
          </div>
        </div>

        {/* ---- classification inputs ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header">
            <h2>{t("inventory.detail.inputs_title", "Classification inputs")}</h2>
          </div>
          <div className="panel-body">
            <p className="hint-text" style={{ marginTop: 0 }}>
              {t("inventory.detail.inputs_hint", "The domain and the flags below drive the suggested tier.")}
            </p>
            <div className="field" style={{ maxWidth: 420 }}>
              <label htmlFor="inp-domain">{t("inventory.domain", "Domain")}</label>
              <select id="inp-domain" value={domain} disabled={!isAdmin} onChange={(e) => setDomain(e.target.value)}>
                {(meta?.domains ?? []).map((d) => (
                  <option key={d.id} value={d.id}>
                    {domainLabel(d.id)}
                    {d.annex_iii ? " · Annex III" : ""}
                  </option>
                ))}
              </select>
            </div>
            {meta &&
              FLAG_GROUPS.map((group) => (
                <div key={group} style={{ marginBottom: 12 }}>
                  <div style={{ fontWeight: 600, fontSize: 13, margin: "8px 0 6px" }}>
                    {t(`inventory.flag_groups.${group}`, group)}
                  </div>
                  {Object.entries(meta.flags[group]).map(([flag, reference]) => (
                    <label
                      key={flag}
                      style={{ display: "flex", gap: 8, alignItems: "flex-start", marginBottom: 6, cursor: isAdmin ? "pointer" : "default" }}
                    >
                      <input
                        type="checkbox"
                        disabled={!isAdmin}
                        checked={flags.includes(flag)}
                        onChange={(e) =>
                          setFlags((cur) => (e.target.checked ? [...cur, flag] : cur.filter((f) => f !== flag)))
                        }
                        style={{ marginTop: 3, width: "auto" }}
                      />
                      <span>
                        {t(`inventory.flags.${flag}`, flag)}
                        <span className="hint-text" style={{ display: "block", fontSize: 12 }}>{reference}</span>
                      </span>
                    </label>
                  ))}
                </div>
              ))}
            {isAdmin && (
              <>
                {inputsChanged && s.confirmed_risk_tier && (
                  <p style={{ color: "#d97706", fontSize: 13 }}>
                    {t("inventory.detail.inputs_reset_warning", "Saving will reset the current human confirmation.")}
                  </p>
                )}
                <button
                  className="btn btn-primary btn-sm"
                  disabled={busy || !inputsChanged}
                  onClick={() => run(() => updateSystem(s.id, { domain, risk_flags: flags }), t("inventory.detail.saved", "Saved"))}
                >
                  {t("inventory.detail.inputs_save", "Save and reclassify")}
                </button>
              </>
            )}
          </div>
        </div>

        {/* ---- lifecycle ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header">
            <h2>{t("inventory.detail.lifecycle_title", "Lifecycle")}</h2>
          </div>
          <div className="panel-body">
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              {LIFECYCLE_STAGES.map((stage) => {
                const current = stage === s.lifecycle_stage;
                const blocked = stage === "production" && !!prodBlockedReason;
                return (
                  <button
                    key={stage}
                    className={`btn btn-sm${current ? " btn-primary" : ""}`}
                    disabled={!isAdmin || busy || current || blocked}
                    title={blocked ? prodBlockedReason ?? undefined : undefined}
                    onClick={() => run(() => changeStage(s.id, stage), t("inventory.detail.saved", "Saved"))}
                  >
                    {t(`inventory.stages.${stage}`, stage)}
                  </button>
                );
              })}
            </div>
            {prodBlockedReason && s.lifecycle_stage !== "production" && (
              <p className="hint-text" style={{ marginBottom: 0 }}>{prodBlockedReason}</p>
            )}
          </div>
        </div>

        {/* ---- details ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header">
            <h2>{t("inventory.detail.details_title", "Details")}</h2>
          </div>
          <div className="panel-body">
            <div className="form-row">
              <div className="field">
                <label htmlFor="d-name">{t("inventory.name", "Name")}</label>
                <input
                  id="d-name"
                  disabled={!isAdmin}
                  maxLength={255}
                  value={details.name}
                  onChange={(e) => setDetails({ ...details, name: e.target.value })}
                />
              </div>
              <div className="field">
                <label htmlFor="d-owner">{t("inventory.detail.owner", "Business owner")}</label>
                <input
                  id="d-owner"
                  disabled={!isAdmin}
                  maxLength={255}
                  value={details.business_owner}
                  onChange={(e) => setDetails({ ...details, business_owner: e.target.value })}
                />
              </div>
            </div>
            <div className="field">
              <label htmlFor="d-desc">{t("inventory.description", "Description")}</label>
              <textarea
                id="d-desc"
                rows={3}
                disabled={!isAdmin}
                value={details.description}
                onChange={(e) => setDetails({ ...details, description: e.target.value })}
              />
            </div>
            {isAdmin && (
              <button
                className="btn btn-primary btn-sm"
                disabled={busy || !details.name.trim()}
                onClick={() =>
                  run(
                    () =>
                      updateSystem(s.id, {
                        name: details.name.trim(),
                        description: details.description || null,
                        business_owner: details.business_owner || null,
                      }),
                    t("inventory.detail.saved", "Saved"),
                  )
                }
              >
                {t("inventory.detail.save", "Save")}
              </button>
            )}
          </div>
        </div>

        {/* ---- data ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header">
            <h2>{t("inventory.detail.data_title", "Data")}</h2>
          </div>
          <div className="panel-body">
            {s.data_protection_notes.length > 0 && (
              <div style={{ marginBottom: 12, color: "#d97706", fontSize: 13 }}>
                {s.data_protection_notes.map((n, i) => (
                  <div key={i}>● {n}</div>
                ))}
              </div>
            )}
            {s.data_links.length === 0 ? (
              <p className="hint-text">{t("inventory.detail.data_empty", "No data links yet.")}</p>
            ) : (
              <table style={{ marginBottom: 12 }}>
                <thead>
                  <tr>
                    <th>{t("inventory.detail.relation", "Relation")}</th>
                    <th>{t("inventory.detail.target", "Data")}</th>
                    <th>{t("inventory.detail.pii", "Personal data")}</th>
                    {isAdmin && <th />}
                  </tr>
                </thead>
                <tbody>
                  {s.data_links.map((l) => (
                    <tr key={l.id}>
                      <td>{t(`inventory.detail.relations.${l.relation}`, l.relation)}</td>
                      <td>{linkTarget(l)}</td>
                      <td>{l.contains_pii ? t("inventory.detail.yes", "Yes") : t("inventory.detail.no", "No")}</td>
                      {isAdmin && (
                        <td>
                          <button className="btn btn-sm" disabled={busy} onClick={() => run(() => removeDataLink(s.id, l.id))}>
                            {t("inventory.detail.remove", "Remove")}
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {isAdmin && (
              <div style={{ borderTop: "1px solid var(--border, #334155)", paddingTop: 12 }}>
                <h3 style={{ fontSize: 14, margin: "0 0 8px" }}>{t("inventory.detail.add_link", "Add data link")}</h3>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="l-rel">{t("inventory.detail.relation", "Relation")}</label>
                    <select
                      id="l-rel"
                      value={link.relation}
                      onChange={(e) => setLink({ ...link, relation: e.target.value as DataRelation })}
                    >
                      <option value="accesses">{t("inventory.detail.relations.accesses", "Has access to")}</option>
                      <option value="trained_on">{t("inventory.detail.relations.trained_on", "Trained on")}</option>
                    </select>
                  </div>
                  <div className="field">
                    <label htmlFor="l-type">{t("inventory.detail.target_type", "Data source")}</label>
                    <select
                      id="l-type"
                      value={link.target}
                      onChange={(e) => setLink({ ...link, target: e.target.value as "external" | "dataset" })}
                    >
                      <option value="external">{t("inventory.detail.target_external", "External source")}</option>
                      <option value="dataset" disabled={datasets.length === 0}>
                        {t("inventory.detail.target_dataset", "Dataset")}
                      </option>
                    </select>
                  </div>
                  <div className="field">
                    {link.target === "external" ? (
                      <>
                        <label htmlFor="l-ext">{t("inventory.detail.external_name", "Name of the source")}</label>
                        <input
                          id="l-ext"
                          maxLength={255}
                          value={link.external_name}
                          onChange={(e) => setLink({ ...link, external_name: e.target.value })}
                        />
                      </>
                    ) : (
                      <>
                        <label htmlFor="l-ds">{t("inventory.detail.dataset", "Dataset")}</label>
                        <select
                          id="l-ds"
                          value={link.dataset_id}
                          onChange={(e) => setLink({ ...link, dataset_id: e.target.value })}
                        >
                          <option value="">—</option>
                          {datasets.map((d) => (
                            <option key={d.id} value={d.id}>{d.name}</option>
                          ))}
                        </select>
                      </>
                    )}
                  </div>
                </div>
                <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 10 }}>
                  <input
                    type="checkbox"
                    checked={link.contains_pii}
                    onChange={(e) => setLink({ ...link, contains_pii: e.target.checked })}
                    style={{ width: "auto" }}
                  />
                  {t("inventory.detail.contains_pii", "Contains personal data (PII)")}
                </label>
                <button
                  className="btn btn-primary btn-sm"
                  disabled={
                    busy ||
                    (link.target === "external" ? !link.external_name.trim() : !link.dataset_id)
                  }
                  onClick={() =>
                    run(async () => {
                      const updated = await addDataLink(s.id, {
                        relation: link.relation,
                        contains_pii: link.contains_pii,
                        ...(link.target === "external"
                          ? { external_name: link.external_name.trim() }
                          : { dataset_id: Number(link.dataset_id) }),
                      });
                      setLink({ ...link, external_name: "", dataset_id: "", contains_pii: false });
                      return updated;
                    })
                  }
                >
                  {t("inventory.detail.add_link", "Add data link")}
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
