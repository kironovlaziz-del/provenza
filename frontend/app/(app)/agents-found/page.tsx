"use client";

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import { translateApiError } from "@/lib/errors";
import {
  ago,
  getFoundSummary,
  ignoreFoundAgent,
  listFoundAgents,
  restoreFoundAgent,
  type FoundAgentT,
  type FoundStatus,
  type FoundSummaryT,
} from "@/lib/endpoints_api";

const STATUS_PILL: Record<FoundStatus, string> = {
  new: "pill-medium",
  registered: "pill-low",
  ignored: "pill-neutral",
};

function riskPill(score: number | null): string {
  if (score == null) return "pill-neutral";
  if (score >= 0.75) return "pill-high";
  if (score >= 0.6) return "pill-medium";
  return "pill-low";
}

// Why an unrecognized agent was flagged: the LLM APIs it talks to, the key
// variable names it carries, the SDKs it loaded.
function Signals({ ev }: { ev: NonNullable<FoundAgentT["evidence"]> }) {
  const { t } = useTranslation();
  const parts = [
    ev.api_hosts?.length ? t("found.sig_api", { hosts: ev.api_hosts.join(", ") }) : null,
    ev.sdks?.length ? t("found.sig_sdk", { sdks: ev.sdks.join(", ") }) : null,
    ev.env_keys?.length ? t("found.sig_env", { keys: ev.env_keys.join(", ") }) : null,
  ].filter(Boolean);
  return (
    <div style={{ fontSize: 11, marginTop: 4 }}>
      {ev.confidence && (
        <span className={`pill ${ev.confidence === "high" ? "pill-medium" : "pill-neutral"}`} style={{ marginRight: 6 }}>
          {t(`found.confidence_${ev.confidence}`)}
        </span>
      )}
      <span className="hint-text">{parts.join(" · ")}</span>
    </div>
  );
}

export default function AgentsFoundPage() {
  const { t, i18n } = useTranslation();
  const router = useRouter();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [filter, setFilter] = useState<FoundStatus | "">("new");
  const [items, setItems] = useState<FoundAgentT[] | null>(null);
  const [summary, setSummary] = useState<FoundSummaryT | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setError(null);
    listFoundAgents(filter)
      .then((p) => setItems(p.items))
      .catch((e) => setError(translateApiError(e?.response?.data?.detail, t, t("found.load_failed"))));
    getFoundSummary().then(setSummary).catch(() => undefined);
  }, [filter, t]);

  useEffect(load, [load]);

  async function act(id: number, action: () => Promise<unknown>) {
    setBusyId(id);
    setError(null);
    try {
      await action();
      load();
    } catch (e: any) {
      setError(translateApiError(e?.response?.data?.detail, t, t("found.action_failed")));
    } finally {
      setBusyId(null);
    }
  }

  function register(f: FoundAgentT) {
    const type = ({ crewai: "crewai", langgraph: "langgraph", autogen_studio: "autogen" } as Record<string, string>)[f.product] ?? "custom";
    const q = new URLSearchParams({
      found: String(f.id),
      type,
      name: `${f.product.replace(/_/g, "-")}-${f.device_host}`.slice(0, 100),
      description: t("found.register_description", {
        product: f.name,
        host: f.device_host,
        defaultValue: `${f.name} found on ${f.device_host}`,
      }),
    });
    router.push(`/agents/new?${q.toString()}`);
  }

  const tiles: { key: FoundStatus | "devices"; value?: number }[] = [
    { key: "new", value: summary?.new },
    { key: "registered", value: summary?.registered },
    { key: "ignored", value: summary?.ignored },
    { key: "devices", value: summary?.devices },
  ];

  return (
    <>
      <PageHeader title={t("found.title")} />
      <div className="content">
        <p className="hint-text u-mb-16">{t("found.hint")}</p>

        <div className="stat-grid u-mb-20">
          {tiles.map((tile) => (
            <div className="stat" key={tile.key}>
              <div className="stat-label">{t(`found.stat_${tile.key}`)}</div>
              <div className="stat-value">{tile.value ?? "—"}</div>
            </div>
          ))}
        </div>

        {error && <p className="error-text u-mb-16">{error}</p>}

        <div className="panel">
          <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <h2>{t("found.table_title")}</h2>
            <select value={filter} onChange={(e) => setFilter(e.target.value as FoundStatus | "")} style={{ width: "auto" }}
              aria-label={t("found.filter")}>
              <option value="new">{t("found.status_new")}</option>
              <option value="registered">{t("found.status_registered")}</option>
              <option value="ignored">{t("found.status_ignored")}</option>
              <option value="">{t("found.filter_all")}</option>
            </select>
          </div>
          <div style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>{t("found.col_agent")}</th>
                  <th>{t("found.col_device")}</th>
                  <th>{t("found.col_risk")}</th>
                  <th>{t("found.col_seen")}</th>
                  <th>{t("found.col_status")}</th>
                  {isAdmin && <th></th>}
                </tr>
              </thead>
              <tbody>
                {items === null && <tr className="empty-row"><td colSpan={6}>{t("common.loading")}</td></tr>}
                {items?.length === 0 && (
                  <tr className="empty-row"><td colSpan={6}>{t(filter === "new" ? "found.empty_new" : "found.empty")}</td></tr>
                )}
                {items?.map((f) => (
                  <tr key={f.id}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{f.name}</div>
                      <div className="hint-text" style={{ fontSize: 11 }}>
                        {[f.vendor, t(`found.category_${f.category}`, f.category)].filter(Boolean).join(" · ")}
                        {f.evidence?.process_name ? ` · ${f.evidence.process_name}` : ""}
                      </div>
                      {f.evidence?.matched_by === "behavior" && <Signals ev={f.evidence} />}
                    </td>
                    <td>
                      <Link href={`/devices?focus=${f.device_id}`} className="mono" style={{ fontSize: 12 }}>{f.device_host}</Link>
                      {f.device_user && <div className="hint-text" style={{ fontSize: 11 }}>{f.device_user}</div>}
                    </td>
                    <td>
                      <span className={`pill ${riskPill(f.risk_score)}`}>
                        {f.risk_score == null ? "—" : f.risk_score.toFixed(1)}
                      </span>
                    </td>
                    <td style={{ fontSize: 12 }}>
                      <div title={new Date(f.last_seen_at).toLocaleString(i18n.language)}>{ago(f.last_seen_at, i18n.language)}</div>
                      <div className="hint-text" style={{ fontSize: 11 }}>
                        {t("found.first_seen", { when: new Date(f.first_seen_at).toLocaleDateString(i18n.language) })}
                        {f.seen_count > 1 ? ` · ×${f.seen_count}` : ""}
                      </div>
                    </td>
                    <td>
                      <span className={`pill ${STATUS_PILL[f.status]}`}>{t(`found.status_${f.status}`)}</span>
                      {f.registered_agent && (
                        <div style={{ fontSize: 11, marginTop: 4 }}>
                          <Link href={`/agents/${f.registered_agent.id}`}>{f.registered_agent.name}</Link>
                        </div>
                      )}
                    </td>
                    {isAdmin && (
                      <td className="u-nowrap">
                        {f.status === "new" && (
                          <>
                            <button className="btn btn-primary btn-sm" disabled={busyId === f.id} onClick={() => register(f)}>
                              {t("found.register")}
                            </button>{" "}
                            <button className="btn btn-sm" disabled={busyId === f.id}
                              onClick={() => act(f.id, () => ignoreFoundAgent(f.id))}>
                              {t("found.ignore")}
                            </button>
                          </>
                        )}
                        {f.status === "ignored" && (
                          <button className="btn btn-sm" disabled={busyId === f.id}
                            onClick={() => act(f.id, () => restoreFoundAgent(f.id))}>
                            {t("found.restore")}
                          </button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
}
