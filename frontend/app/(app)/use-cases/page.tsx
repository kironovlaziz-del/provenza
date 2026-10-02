"use client";

import { Form } from "@/components/Form";
import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { RiskPill, StatusPill } from "@/components/Pill";
import { createUseCase, listUseCases } from "@/lib/api";
import type { RiskLevel, UseCase } from "@/lib/types";
import { useAuth } from "@/lib/auth";

export default function UseCasesPage() {
  const router = useRouter();
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [useCases, setUseCases] = useState<UseCase[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [riskLevel, setRiskLevel] = useState<RiskLevel>("low");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  function refresh() {
    setLoading(true);
    listUseCases()
      .then(setUseCases)
      .finally(() => setLoading(false));
  }

  useEffect(refresh, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await createUseCase({ name, risk_level: riskLevel });
      setName("");
      setRiskLevel("low");
      setShowForm(false);
      refresh();
    } catch {
      setError(t("use_cases.failed"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <PageHeader
        title={t("use_cases.title")}
        actions={
          isAdmin ? (
            <button className="btn btn-primary btn-sm" onClick={() => setShowForm((s) => !s)}>
              {showForm ? t("use_cases.cancel") : t("use_cases.new")}
            </button>
          ) : undefined
        }
      />
      <div className="content">
        {isAdmin && showForm && (
          <div className="panel" style={{ marginBottom: 20 }}>
            <div className="panel-header">
              <h2>{t("use_cases.form_title")}</h2>
            </div>
            <div className="panel-body">
              <Form onSubmit={handleCreate}>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="name">{t("use_cases.name")}</label>
                    <input
                      id="name"
                      required
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder={t("use_cases.name_placeholder")}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="risk">{t("use_cases.risk")}</label>
                    <select
                      id="risk"
                      value={riskLevel}
                      onChange={(e) => setRiskLevel(e.target.value as RiskLevel)}
                    >
                      <option value="low">{t("risk.low")}</option>
                      <option value="medium">{t("risk.medium")}</option>
                      <option value="high">{t("risk.high")}</option>
                      <option value="critical">{t("risk.critical")}</option>
                    </select>
                  </div>
                </div>
                {error && <p className="error-text">{error}</p>}
                <button className="btn btn-primary" type="submit" disabled={submitting}>
                  {submitting ? t("use_cases.submitting") : t("use_cases.submit")}
                </button>
              </Form>
            </div>
          </div>
        )}

        <div className="panel">
          <div className="panel-header">
            <h2>{t("use_cases.title")}</h2>
          </div>
          <table>
            <thead>
              <tr>
                <th>{t("use_cases.col_id")}</th>
                <th>{t("use_cases.col_name")}</th>
                <th>{t("use_cases.col_risk")}</th>
                <th>{t("use_cases.col_status")}</th>
                <th>{t("use_cases.col_policy")}</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr className="empty-row">
                  <td colSpan={5}>{t("common.loading")}</td>
                </tr>
              )}
              {!loading && useCases.length === 0 && (
                <tr className="empty-row">
                  <td colSpan={5}>{t("use_cases.empty")}</td>
                </tr>
              )}
              {useCases.map((uc) => (
                <tr
                  key={uc.id}
                  className="clickable"
                  onClick={() => router.push(`/use-cases/${uc.id}`)}
                >
                  <td className="mono">#{uc.id}</td>
                  <td>{uc.name}</td>
                  <td>
                    <RiskPill level={uc.risk_level} />
                  </td>
                  <td>
                    <StatusPill status={uc.status} />
                  </td>
                  <td className="mono">
                    {uc.approved_policy_version_id
                      ? `${t("use_cases.policy_version")} #${uc.approved_policy_version_id}`
                      : t("use_cases.policy_not_linked")}
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