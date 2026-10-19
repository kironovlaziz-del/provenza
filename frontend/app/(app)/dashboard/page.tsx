"use client";

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";
import { PageHeader } from "@/components/PageHeader";
import { SetupChecklist } from "@/components/SetupChecklist";
import { fetchDashboardStats, type DashboardStats } from "@/lib/api";

// Palette shared across charts - enough distinct colours for typical
// status/severity distributions without dragging in a full theme.
const PALETTE = [
  "#2451d9", // accent blue
  "#2f9e63", // green
  "#a9760a", // amber
  "#c1541a", // orange
  "#c1352f", // red
  "#676b76", // gray
  "#8b5cf6", // violet
  "#0ea5e9", // sky
];

export default function DashboardPage() {
  const { t } = useTranslation();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [windowDays, setWindowDays] = useState(7);

  useEffect(() => {
    setLoading(true);
    fetchDashboardStats(windowDays)
      .then(setStats)
      .finally(() => setLoading(false));
  }, [windowDays]);

  if (loading || !stats) {
    return (
      <>
        <PageHeader title={t("dashboard.title")} />
        <div className="content">
          <p className="loading-line">{t("dashboard.loading")}</p>
        </div>
      </>
    );
  }

  // Pie/bar data shape: {name, value}
  const callsByStatusData = Object.entries(stats.calls_by_status).map(
    ([name, value]) => ({ name, value }),
  );
  const incidentsBySeverityData = Object.entries(
    stats.incidents_by_severity,
  ).map(([name, value]) => ({ name, value }));

  return (
    <>
      <PageHeader
        title={t("dashboard.title")}
        actions={
          <select
            value={windowDays}
            onChange={(e) => setWindowDays(Number(e.target.value))}
            style={{
              border: "1px solid var(--border-strong)",
              borderRadius: 4,
              padding: "5px 8px",
              background: "var(--bg-panel)",
              fontSize: 12,
            }}
          >
            <option value={7}>7d</option>
            <option value={14}>14d</option>
            <option value={30}>30d</option>
            <option value={90}>90d</option>
          </select>
        }
      />
      <div className="content">
        <SetupChecklist />
        <div className="stat-grid">
          <div className="stat">
            <div className="stat-label">{t("dashboard.stat_calls", "LLM calls (gateway)")}</div>
            <div className="stat-value">{stats.total_calls}</div>
          </div>
          <div className="stat">
            <div className="stat-label">{t("dashboard.stat_pending")}</div>
            <div className="stat-value">{stats.pending_approvals}</div>
          </div>
          <div className="stat">
            <div className="stat-label">{t("dashboard.stat_incidents")}</div>
            <div className="stat-value">{stats.total_incidents}</div>
          </div>
          <div className="stat">
            <div className="stat-label">{t("dashboard.stat_policies")}</div>
            <div className="stat-value">{stats.total_policies}</div>
          </div>
        </div>

        {/* Line chart: LLM calls through the gateway per day */}
        <div className="panel u-mb-20">
          <div className="panel-header">
            <h2>{t("dashboard.calls_trend", "LLM calls per day")}</h2>
            <span className="hint-text">
              {t("dashboard.window", { days: windowDays })}
            </span>
          </div>
          <div className="panel-body">
            <ResponsiveContainer width="100%" height={260}>
              <LineChart data={stats.calls_by_day}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e4e9" />
                <XAxis dataKey="date" fontSize={11} />
                <YAxis fontSize={11} allowDecimals={false} />
                <Tooltip />
                <Legend />
                <Line
                  type="monotone"
                  dataKey="total"
                  stroke="#2451d9"
                  strokeWidth={2}
                  name={t("dashboard.line_total", "Total")}
                />
                <Line
                  type="monotone"
                  dataKey="completed"
                  stroke="#2f9e63"
                  strokeWidth={2}
                  name={t("dashboard.line_completed", "Completed")}
                />
                <Line
                  type="monotone"
                  dataKey="denied"
                  stroke="#c1352f"
                  strokeWidth={2}
                  name={t("dashboard.line_denied", "Denied")}
                />
                <Line
                  type="monotone"
                  dataKey="failed"
                  stroke="#a9760a"
                  strokeWidth={2}
                  name={t("dashboard.line_failed", "Failed")}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Three pie charts side by side */}
        <div className="dashboard-grid-3">
          <div className="panel">
            <div className="panel-header">
              <h2>{t("dashboard.calls_by_status", "LLM calls by outcome")}</h2>
            </div>
            <div className="panel-body">
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie
                    data={callsByStatusData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={40}
                    outerRadius={80}
                    paddingAngle={2}
                  >
                    {callsByStatusData.map((_, i) => (
                      <Cell key={i} fill={PALETTE[i % PALETTE.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <h2>{t("dashboard.incidents_by_severity")}</h2>
            </div>
            <div className="panel-body">
              {incidentsBySeverityData.length === 0 ? (
                <p className="hint-text">{t("dashboard.no_data")}</p>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={incidentsBySeverityData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#e2e4e9" />
                    <XAxis dataKey="name" fontSize={11} />
                    <YAxis fontSize={11} allowDecimals={false} />
                    <Tooltip />
                    <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                      {incidentsBySeverityData.map((_, i) => (
                        <Cell key={i} fill={PALETTE[i % PALETTE.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>
        </div>

      </div>
    </>
  );
}
