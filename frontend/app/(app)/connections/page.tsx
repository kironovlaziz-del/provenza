"use client";

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { ProviderPolicyPanel } from "@/components/ProviderPolicyPanel";
import { Form } from "@/components/Form";
import { SealedCredential, sealNew } from "@/components/gateways/SealedCredential";
import { createProvider, listProviders, updateProvider, listProviderModels } from "@/lib/api";
import type { Provider } from "@/lib/types";
import { errorMessage } from "@/lib/errors";

const TYPE_DEFAULTS: Record<string, { base_url: string; default_model: string }> = {
  openai: { base_url: "https://api.openai.com/v1", default_model: "gpt-4o-mini" },
  anthropic: { base_url: "https://api.anthropic.com/v1", default_model: "claude-3-5-haiku-20241022" },
  groq: { base_url: "https://api.groq.com/openai/v1", default_model: "openai/gpt-oss-120b" },
  azure_openai: { base_url: "", default_model: "gpt-4o-mini" },
  custom: { base_url: "", default_model: "" },
};

function ToggleSwitch({
  on,
  onClick,
  disabled,
  labelOn,
  labelOff,
}: {
  on: boolean;
  onClick: () => void;
  disabled?: boolean;
  labelOn: string;
  labelOff: string;
}) {
  return (
    <button className="conn-toggle" onClick={onClick} disabled={disabled} type="button">
      <span className={`conn-toggle-track${on ? " on" : ""}`}>
        <span className="conn-toggle-thumb" />
      </span>
      {on ? labelOn : labelOff}
    </button>
  );
}

function ConnectionCard({
  provider,
  onToggle,
  onSaveCredentials,
  busy,
}: {
  provider: Provider;
  onToggle: () => void;
  onSaveCredentials: (fields: { base_url?: string; default_model?: string }) => Promise<void>;
  busy: boolean;
}) {
  const { t } = useTranslation();
  const [editing, setEditing] = useState(false);
  const [baseUrl, setBaseUrl] = useState(provider.base_url || "");
  const [defaultModel, setDefaultModel] = useState(provider.default_model || "");
  const [saving, setSaving] = useState(false);
  const [models, setModels] = useState<string[]>([]);
  const [loadingModels, setLoadingModels] = useState(false);

  async function handleLoadModels() {
    setLoadingModels(true);
    try {
      const res = await listProviderModels(provider.id);
      setModels(res.models || []);
    } catch {
      setModels([]);
    } finally {
      setLoadingModels(false);
    }
  }

  async function handleSave() {
    setSaving(true);
    try {
      await onSaveCredentials({
        base_url: baseUrl,
        default_model: defaultModel,
      });
      setEditing(false);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="conn-card">
      <div className="conn-card-header">
        <div>
          <div className="conn-card-name">{provider.name}</div>
          <div className="conn-card-type">{provider.type}</div>
        </div>
        <ToggleSwitch
          on={provider.status === "active"}
          onClick={onToggle}
          disabled={busy}
          labelOn={t("connections.toggle_on")}
          labelOff={t("connections.toggle_off")}
        />
      </div>
      <div className="hint-text">{provider.sla || t("connections.no_sla")}</div>
      <div>
        <span className={`pill ${provider.has_credentials ? "pill-low" : "pill-medium"}`}>
          {provider.has_credentials
            ? t("connections.key_configured")
            : t("connections.key_missing")}
        </span>
      </div>

      {!editing ? (
        <button className="btn btn-sm" onClick={() => setEditing(true)}>
          {t("connections.configure_access")}
        </button>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <div className="field" style={{ margin: 0 }}>
            <label>{t("connections.api_key_sealed", "API key")}</label>
            <SealedCredential obj="provider" id={provider.id} />
          </div>
          <div className="field" style={{ margin: 0 }}>
            <label>{t("connections.base_url")}</label>
            <input
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder={TYPE_DEFAULTS[provider.type]?.base_url || "https://..."}
            />
          </div>
          <div className="field" style={{ margin: 0 }}>
            <label>{t("connections.default_model")}</label>
            <div style={{ display: "flex", gap: 8, minWidth: 0 }}>
              {models.length > 0 ? (
                <select value={defaultModel} onChange={(e) => setDefaultModel(e.target.value)} style={{ flex: 1, minWidth: 0 }}>
                  {!models.includes(defaultModel) && defaultModel && <option value={defaultModel}>{defaultModel}</option>}
                  {models.map((m) => <option key={m} value={m}>{m}</option>)}
                </select>
              ) : (
                <input
                  value={defaultModel}
                  onChange={(e) => setDefaultModel(e.target.value)}
                  placeholder={TYPE_DEFAULTS[provider.type]?.default_model || "model-name"}
                  style={{ flex: 1 }}
                />
              )}
              <button type="button" className="btn btn-sm" onClick={handleLoadModels} disabled={loadingModels} style={{ flexShrink: 0, whiteSpace: "nowrap" }}>
                {loadingModels ? t("connections.loading_models") : t("connections.load_models")}
              </button>
            </div>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn btn-primary btn-sm" onClick={handleSave} disabled={saving}>
              {saving ? t("connections.saving") : t("connections.save")}
            </button>
            <button className="btn btn-sm" onClick={() => setEditing(false)} disabled={saving}>
              {t("common.cancel")}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function ConnectionsPage() {
  const { t } = useTranslation();
  const [providers, setProviders] = useState<Provider[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<number | null>(null);

  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [type, setType] = useState("openai");
  const [sla, setSla] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [defaultModel, setDefaultModel] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  function refresh() {
    setLoading(true);
    listProviders()
      .then(setProviders)
      .finally(() => setLoading(false));
  }

  useEffect(refresh, []);

  function handleTypeChange(next: string) {
    setType(next);
    const defaults = TYPE_DEFAULTS[next];
    if (defaults) {
      setBaseUrl(defaults.base_url);
      setDefaultModel(defaults.default_model);
    }
  }

  async function handleToggle(p: Provider) {
    setBusyId(p.id);
    try {
      const next = p.status === "active" ? "suspended" : "active";
      await updateProvider(p.id, { status: next });
      refresh();
    } finally {
      setBusyId(null);
    }
  }

  async function handleSaveCredentials(
    p: Provider,
    fields: { base_url?: string; default_model?: string }
  ) {
    setBusyId(p.id);
    try {
      await updateProvider(p.id, fields);
      refresh();
    } finally {
      setBusyId(null);
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const created = await createProvider({
        name,
        type,
        sla: sla || undefined,
        base_url: baseUrl || undefined,
        default_model: defaultModel || undefined,
      });
      // the key is sealed here to the egress proxies: the server never receives it in clear text
      await sealNew("provider", created.id, apiKey);
      setName("");
      setSla("");
      setApiKey("");
      setBaseUrl("");
      setDefaultModel("");
      setType("openai");
      setShowForm(false);
      refresh();
    } catch (err) {
      setError(errorMessage(err, t, t("connections.failed")));
    } finally {
      setSubmitting(false);
    }
  }

  const activeCount = providers.filter((p) => p.status === "active").length;
  const withKeysCount = providers.filter((p) => p.has_credentials).length;

  return (
    <>
      <PageHeader
        title={t("connections.title")}
        actions={
          <button className="btn btn-primary btn-sm" onClick={() => setShowForm((s) => !s)}>
            {showForm ? t("connections.cancel") : t("connections.connect")}
          </button>
        }
      />
      <div className="content">
        <p className="hint-text" style={{ marginBottom: 16 }}>
          {t("connections.hint")}
        </p>

        <ProviderPolicyPanel refreshKey={providers} />

        <div className="stat-grid" style={{ marginBottom: 4 }}>
          <div className="stat">
            <div className="stat-label">{t("connections.stat_active")}</div>
            <div className="stat-value">{activeCount}</div>
          </div>
          <div className="stat">
            <div className="stat-label">{t("connections.stat_with_keys")}</div>
            <div className="stat-value">{withKeysCount}</div>
          </div>
          <div className="stat">
            <div className="stat-label">{t("connections.stat_total")}</div>
            <div className="stat-value">{providers.length}</div>
          </div>
        </div>

        {showForm && (
          <div className="panel" style={{ margin: "20px 0" }}>
            <div className="panel-header">
              <h2>{t("connections.form_title")}</h2>
            </div>
            <div className="panel-body">
              <Form onSubmit={handleCreate}>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="name">{t("connections.name")}</label>
                    <input
                      id="name"
                      required
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder={t("connections.name_placeholder")}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="type">{t("connections.type")}</label>
                    <select id="type" value={type} onChange={(e) => handleTypeChange(e.target.value)}>
                      <option value="openai">openai</option>
                      <option value="anthropic">anthropic</option>
                      <option value="groq">groq</option>
                      <option value="azure_openai">azure_openai</option>
                      <option value="custom">custom</option>
                    </select>
                  </div>
                </div>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="base_url">{t("connections.base_url")}</label>
                    <input
                      id="base_url"
                      value={baseUrl}
                      onChange={(e) => setBaseUrl(e.target.value)}
                      placeholder={TYPE_DEFAULTS[type]?.base_url || "https://..."}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="default_model">{t("connections.default_model")}</label>
                    <input
                      id="default_model"
                      value={defaultModel}
                      onChange={(e) => setDefaultModel(e.target.value)}
                      placeholder={TYPE_DEFAULTS[type]?.default_model || "model-name"}
                    />
                  </div>
                </div>
                <div className="field">
                  <label htmlFor="api_key">{t("connections.api_key")}</label>
                  <input
                    id="api_key"
                    type="password"
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder={t("sealed.placeholder", "Sealed in this browser; the server never sees it")}
                  />
                </div>
                <div className="field">
                  <label htmlFor="sla">{t("connections.sla")}</label>
                  <input
                    id="sla"
                    value={sla}
                    onChange={(e) => setSla(e.target.value)}
                    placeholder={t("connections.sla_placeholder")}
                  />
                </div>
                {error && <p className="error-text">{error}</p>}
                <button className="btn btn-primary" type="submit" disabled={submitting}>
                  {submitting ? t("connections.submitting") : t("connections.submit")}
                </button>
              </Form>
            </div>
          </div>
        )}

        {loading ? (
          <p className="loading-line">{t("connections.loading")}</p>
        ) : providers.length === 0 ? (
          <p className="hint-text">{t("connections.empty")}</p>
        ) : (
          <div className="conn-grid">
            {providers.map((p) => (
              <ConnectionCard
                key={p.id}
                provider={p}
                busy={busyId === p.id}
                onToggle={() => handleToggle(p)}
                onSaveCredentials={(fields) => handleSaveCredentials(p, fields)}
              />
            ))}
          </div>
        )}
      </div>
    </>
  );
}
