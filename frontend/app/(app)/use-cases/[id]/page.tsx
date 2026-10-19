"use client";

import React, { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { RiskPill, StatusPill } from "@/components/Pill";
import { getUseCase, updateUseCase } from "@/lib/api";
import type { RiskLevel, UseCase } from "@/lib/types";
import { useAuth } from "@/lib/auth";
import { translateApiError } from "@/lib/errors";

export default function UseCaseDetailPage() {
  const params = useParams<{ id: string }>();
  const useCaseId = Number(params.id);
  const { t, i18n } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [actionError, setActionError] = useState<string | null>(null);

  const [useCase, setUseCase] = useState<UseCase | null>(null);
  const [loading, setLoading] = useState(true);
  const [riskLevel, setRiskLevel] = useState<RiskLevel>("low");
  const [status, setStatus] = useState("active");
  const [saving, setSaving] = useState(false);
  const [savedAt, setSavedAt] = useState<number | null>(null);

  function refresh() {
    setLoading(true);
    getUseCase(useCaseId)
      .then((uc) => {
        setUseCase(uc);
        setRiskLevel(uc.risk_level);
        setStatus(uc.status);
      })
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    if (!Number.isNaN(useCaseId)) refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [useCaseId]);

  function showError(err: unknown) {
    const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
    setActionError(translateApiError(detail, t, t("use_cases.save_failed")));
  }

  async function handleSave() {
    setSaving(true);
    setActionError(null);
    try {
      const updated = await updateUseCase(useCaseId, { risk_level: riskLevel, status });
      setUseCase(updated);
      setSavedAt(Date.now());
    } catch (err) {
      showError(err);
    } finally {
      setSaving(false);
    }
  }

  if (loading || !useCase) {
    return (
      <>
        <PageHeader title={t("use_cases.title")} />
        <div className="content">
          <p className="loading-line">{t("use_cases.detail.loading")}</p>
        </div>
      </>
    );
  }

  return (
    <>
      <PageHeader title={useCase.name} />
      <div className="content">
        <div className="breadcrumb">
          <Link href="/use-cases">{t("use_cases.detail.breadcrumb")}</Link> / #{useCase.id}
        </div>

        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-body">
            <dl className="kv-grid">
              <dt>{t("use_cases.detail.current_risk")}</dt>
              <dd>
                <RiskPill level={useCase.risk_level} />
              </dd>
              <dt>{t("use_cases.detail.status")}</dt>
              <dd>
                <StatusPill status={useCase.status} />
              </dd>
              <dt>{t("use_cases.detail.owner")}</dt>
              <dd className="mono">{useCase.owner_user_id ?? "—"}</dd>
              <dt>{t("use_cases.detail.created")}</dt>
              <dd className="mono">
                {new Date(useCase.created_at).toLocaleString(i18n.language)}
              </dd>
            </dl>
          </div>
        </div>

        {actionError && <p className="error-text" style={{ marginBottom: 16 }}>{actionError}</p>}

        {isAdmin && (
        <>
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header">
            <h2>{t("use_cases.detail.edit_title")}</h2>
          </div>
          <div className="panel-body">
            <div className="form-row">
              <div className="field">
                <label htmlFor="risk">{t("use_cases.detail.risk")}</label>
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
              <div className="field">
                <label htmlFor="status">{t("use_cases.detail.status")}</label>
                <select id="status" value={status} onChange={(e) => setStatus(e.target.value)}>
                  <option value="active">{t("status.active")}</option>
                  <option value="inactive">{t("status.inactive")}</option>
                  <option value="suspended">{t("status.suspended")}</option>
                </select>
              </div>
            </div>
            <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
              {saving ? t("use_cases.detail.saving") : t("use_cases.detail.save")}
            </button>
            {savedAt && (
              <span className="hint-text" style={{ marginLeft: 12 }}>
                {t("use_cases.detail.saved")}
              </span>
            )}
          </div>
        </div>

        </>
        )}
      </div>
    </>
  );
}