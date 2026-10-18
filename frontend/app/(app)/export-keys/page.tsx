"use client";

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { Form } from "@/components/Form";
import {
  createExportKey,
  listExportKeys,
  revokeExportKey,
  type ExportKey,
} from "@/lib/export_keys_api";

// Read-only keys for a SIEM/SOAR: it pulls the egress sensor feed
// (violations and allowed connections) with X-Export-Key instead of a
// person's session. The key is shown once, right after it is made.
export default function ExportKeysPage() {
  const { t, i18n } = useTranslation();
  const [keys, setKeys] = useState<ExportKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [revealedKey, setRevealedKey] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [origin, setOrigin] = useState("https://provenza.example.com");

  function refresh() {
    setLoading(true);
    listExportKeys()
      .then(setKeys)
      .catch(() => setError(t("export_keys.load_failed", "Could not load the keys.")))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    setOrigin(window.location.origin);
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const created = await createExportKey(name);
      setRevealedKey(created.api_key);
      setCopied(null);
      setName("");
      setShowForm(false);
      refresh();
    } catch {
      setError(t("export_keys.failed", "Could not create the key."));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleRevoke(k: ExportKey) {
    if (!window.confirm(t("export_keys.revoke_confirm", "Revoke this key? Whatever uses it stops getting events at once."))) return;
    setBusyId(k.id);
    try {
      await revokeExportKey(k.id);
      refresh();
    } finally {
      setBusyId(null);
    }
  }

  async function copy(text: string, what: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(what);
    } catch {
      // no clipboard (insecure context): the text stays selectable
    }
  }

  const keyForExample = revealedKey ?? "pvx_…";
  const example = `curl -H "X-Export-Key: ${keyForExample}" \\\n  "${origin}/api/v1/egress-sensor/events?limit=500"`;
  const fmt = (s: string | null) => (s ? new Date(s).toLocaleString(i18n.language) : "—");

  return (
    <>
      <PageHeader
        title={t("export_keys.title", "SIEM export")}
        actions={
          <button className="btn btn-primary btn-sm" onClick={() => setShowForm((s) => !s)}>
            {showForm ? t("common.cancel", "Cancel") : t("export_keys.new", "New key")}
          </button>
        }
      />
      <div className="content">
        <p className="hint-text u-mb-16">
          {t("export_keys.hint", "A SIEM or SOAR reads the egress sensor events - blocked or observed violations and the sample of allowed connections - with a read-only key of this organization. A key reads nothing else and can be revoked at any time.")}
        </p>

        {revealedKey && (
          <div className="panel" style={{ marginBottom: 20, borderColor: "var(--danger, #c0392b)" }}>
            <div className="panel-header">
              <h2>{t("export_keys.reveal_title", "Your new key")}</h2>
            </div>
            <div className="panel-body">
              <p className="error-text" style={{ marginBottom: 12 }}>
                {t("export_keys.reveal_warning", "Copy it now: it is shown only this once. Provenza keeps only its hash.")}
              </p>
              <div className="form-row" style={{ alignItems: "center" }}>
                <code className="mono" style={{ wordBreak: "break-all", flex: 1 }}>{revealedKey}</code>
                <button type="button" className="btn btn-sm" onClick={() => copy(revealedKey, "key")}>
                  {copied === "key" ? t("export_keys.copied", "Copied") : t("export_keys.copy", "Copy")}
                </button>
              </div>
              <button type="button" className="btn btn-sm" style={{ marginTop: 12 }} onClick={() => setRevealedKey(null)}>
                {t("export_keys.dismiss", "I have saved it")}
              </button>
            </div>
          </div>
        )}

        {showForm && (
          <div className="panel" style={{ marginBottom: 20 }}>
            <div className="panel-header">
              <h2>{t("export_keys.form_title", "New export key")}</h2>
            </div>
            <div className="panel-body">
              <Form onSubmit={handleCreate}>
                <div className="field">
                  <label htmlFor="export-key-name">{t("export_keys.name", "Name")}</label>
                  <input
                    id="export-key-name"
                    required
                    maxLength={255}
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder={t("export_keys.name_placeholder", "Splunk production")}
                  />
                </div>
                {error && <p className="error-text">{error}</p>}
                <button className="btn btn-primary" type="submit" disabled={submitting}>
                  {submitting ? t("common.loading", "Loading…") : t("export_keys.create", "Create key")}
                </button>
              </Form>
            </div>
          </div>
        )}

        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header">
            <h2>{t("export_keys.howto_title", "How the SIEM reads events")}</h2>
          </div>
          <div className="panel-body">
            <pre className="mono" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0 }}>{example}</pre>
            <button type="button" className="btn btn-sm" style={{ marginTop: 8 }} onClick={() => copy(example, "example")}>
              {copied === "example" ? t("export_keys.copied", "Copied") : t("export_keys.copy", "Copy")}
            </button>
            <p className="hint-text" style={{ marginTop: 12 }}>
              {t("export_keys.howto", "Newest events come first. When the answer has next_cursor, pass it back as ?cursor=… for the next page; without it you have everything. Narrow with since, until (ISO 8601), event_type=violation|activity and sensor_id.")}
            </p>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <h2>{t("export_keys.table_title", "Keys")}</h2>
          </div>
          <table>
            <thead>
              <tr>
                <th>{t("export_keys.col_name", "Name")}</th>
                <th>{t("export_keys.col_key", "Key")}</th>
                <th>{t("export_keys.col_created", "Created")}</th>
                <th>{t("export_keys.col_last_used", "Last used")}</th>
                <th>{t("export_keys.col_status", "Status")}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr className="empty-row"><td colSpan={6}>{t("common.loading", "Loading…")}</td></tr>
              )}
              {!loading && keys.length === 0 && (
                <tr className="empty-row"><td colSpan={6}>{t("export_keys.empty", "No keys yet.")}</td></tr>
              )}
              {keys.map((k) => (
                <tr key={k.id}>
                  <td>{k.name}</td>
                  <td className="mono">{k.key_prefix}…</td>
                  <td className="mono">{fmt(k.created_at)}</td>
                  <td className="mono">{k.last_used_at ? fmt(k.last_used_at) : t("export_keys.never_used", "never")}</td>
                  <td>
                    <span className={`pill ${k.revoked_at ? "pill-neutral" : "pill-low"}`}>
                      {k.revoked_at
                        ? `${t("export_keys.revoked", "revoked")} ${fmt(k.revoked_at)}`
                        : t("export_keys.active", "active")}
                    </span>
                  </td>
                  <td className="u-nowrap">
                    {!k.revoked_at && (
                      <button className="btn btn-sm btn-danger" disabled={busyId === k.id} onClick={() => handleRevoke(k)}>
                        {t("export_keys.revoke", "Revoke")}
                      </button>
                    )}
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
