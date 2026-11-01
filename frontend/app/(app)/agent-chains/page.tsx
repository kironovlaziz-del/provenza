"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { LoadError } from "@/components/LoadError";
import { apiErrorMessage } from "@/lib/inventory_api";
import { listChains } from "@/lib/agent_api";
import type { DelegationChainT } from "@/lib/agent_types";

function statusClass(s: string): string {
  switch (s) {
    case "active":
      return "pill-medium";
    case "completed":
      return "pill-low";
    case "violated":
      return "pill-critical";
    case "terminated":
      return "pill-neutral";
    default:
      return "pill-neutral";
  }
}

export default function AgentChainsPage() {
  const { t, i18n } = useTranslation();
  const [chains, setChains] = useState<DelegationChainT[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    listChains()
      .then((v) => { setChains(v); setLoadError(null); })
      .catch((e) => setLoadError(apiErrorMessage(e, t("common.load_failed"))))
      .finally(() => setLoading(false));
  }, []);

  return (
    <>
      <PageHeader title={t("chains.title")} />
      <div className="content">
          <LoadError message={loadError} />
        <p className="hint-text u-mb-16">{t("chains.hint")}</p>
        <div className="panel">
          <div className="panel-header"><h2>{t("chains.table_title")}</h2></div>
          <table>
            <thead>
              <tr>
                <th>{t("chains.col_id")}</th>
                <th>{t("chains.col_task")}</th>
                <th>{t("chains.col_hops")}</th>
                <th>{t("chains.col_depth")}</th>
                <th>{t("chains.col_status")}</th>
                <th>{t("chains.col_started")}</th>
              </tr>
            </thead>
            <tbody>
              {loading && <tr className="empty-row"><td colSpan={6}>{t("common.loading")}</td></tr>}
              {!loading && chains.length === 0 && (
                <tr className="empty-row"><td colSpan={6}>{t("chains.empty")}</td></tr>
              )}
              {chains.map((c) => (
                <tr key={c.id}>
                  <td>
                    <Link href={`/agent-chains/${c.id}`} style={{ fontWeight: 600 }}>#{c.id}</Link>
                  </td>
                  <td>{c.root_task || "—"}</td>
                  <td>{c.total_hops}</td>
                  <td>{c.max_depth_reached}</td>
                  <td><span className={`pill ${statusClass(c.status)}`}>{t(`chains.status_${c.status}`, c.status)}</span></td>
                  <td className="mono" style={{ fontSize: 12 }}>
                    {new Date(c.started_at).toLocaleString(i18n.language)}
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
