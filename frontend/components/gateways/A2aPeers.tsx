"use client";

// A2A gateway: agents talk to remote agents (peers) only through Provenza.
// A peer's agent card is approved for its exact content (digest); a card that
// changes drifts until re-approved. Agents need "a2a.<slug>" in their rights.

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useDialog } from "@/components/Dialog";
import { Form } from "@/components/Form";
import { SealedCredential, sealNew } from "@/components/gateways/SealedCredential";
import { errorMessage } from "@/lib/errors";
import {
  A2aPeer,
  apiUrl,
  approveA2aPeer,
  blockA2aPeer,
  createA2aPeer,
  deleteA2aPeer,
  listA2aPeers,
  syncA2aPeer,
  updateA2aPeer,
} from "@/lib/gateways_api";

const PEER_PILL: Record<string, string> = {
  approved: "pill-low", pending: "pill-medium", drifted: "pill-high", blocked: "pill-critical", unsynced: "pill-neutral",
};
const EMPTY = { slug: "", name: "", card_url: "", auth_header: "Authorization", auth_secret: "", timeout_seconds: 60 };

export function A2aPeers() {
  const { t, i18n } = useTranslation();
  const { dialog, confirm } = useDialog();
  const [peers, setPeers] = useState<A2aPeer[]>([]);
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState(EMPTY);
  const [showForm, setShowForm] = useState(false);
  const [busy, setBusy] = useState<number | "new" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => listA2aPeers().then(setPeers).finally(() => setLoading(false));
  useEffect(() => { refresh(); }, []);

  async function act(id: number | "new", fn: () => Promise<unknown>) {
    setBusy(id);
    setError(null);
    try {
      await fn();
      await refresh();
    } catch (e) {
      setError(errorMessage(e, t, t("gw.failed")));
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      {dialog}
      <p className="hint-text u-mb-16">{t("gw.a2a.hint", { url: apiUrl("/a2a-gateway/<slug>") })}</p>
      <div className="u-btn-row u-mb-16">
        <button className="btn btn-primary btn-sm" onClick={() => setShowForm((v) => !v)}>
          {showForm ? t("common.cancel") : t("gw.a2a.add")}
        </button>
      </div>

      {showForm && (
        <div className="panel u-mb-16">
          <div className="panel-header"><h2>{t("gw.a2a.add")}</h2></div>
          <div className="panel-body">
            <Form onSubmit={(e) => {
              e.preventDefault();
              act("new", async () => {
                const { auth_secret, ...fields } = form;
                const peer = await createA2aPeer(fields);
                await sealNew("a2a_peer", peer.id, auth_secret);   // sealed here, never sent in clear
                setForm(EMPTY);
                setShowForm(false);
              });
            }}>
              <div className="form-row">
                <div className="field">
                  <label htmlFor="a2a-name">{t("gw.name")}</label>
                  <input id="a2a-name" required maxLength={255} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
                </div>
                <div className="field">
                  <label htmlFor="a2a-slug">{t("gw.slug")}</label>
                  <input id="a2a-slug" required pattern="[a-z0-9][a-z0-9-]{0,39}" value={form.slug}
                         placeholder="travel-agent" onChange={(e) => setForm({ ...form, slug: e.target.value })} />
                </div>
              </div>
              <div className="field">
                <label htmlFor="a2a-card">{t("gw.a2a.card_url")}</label>
                <input id="a2a-card" required type="url" maxLength={500} value={form.card_url}
                       placeholder="https://agent.example.com/.well-known/agent-card.json"
                       onChange={(e) => setForm({ ...form, card_url: e.target.value })} />
              </div>
              <div className="form-row">
                <div className="field">
                  <label htmlFor="a2a-header">{t("gw.auth_header")}</label>
                  <input id="a2a-header" maxLength={100} value={form.auth_header} onChange={(e) => setForm({ ...form, auth_header: e.target.value })} />
                </div>
                <div className="field">
                  <label htmlFor="a2a-secret">{t("gw.secret")}</label>
                  <input id="a2a-secret" type="password" autoComplete="new-password" maxLength={4000} value={form.auth_secret}
                         placeholder={t("sealed.placeholder", "Sealed in this browser; the server never sees it")}
                         onChange={(e) => setForm({ ...form, auth_secret: e.target.value })} />
                </div>
                <div className="field" style={{ maxWidth: 140 }}>
                  <label htmlFor="a2a-timeout">{t("gw.timeout")}</label>
                  <input id="a2a-timeout" type="number" min={1} max={300} value={form.timeout_seconds}
                         onChange={(e) => setForm({ ...form, timeout_seconds: Number(e.target.value) })} />
                </div>
              </div>
              <button className="btn btn-primary" type="submit" disabled={busy === "new"}>
                {busy === "new" ? t("common.loading") : t("common.create")}
              </button>
            </Form>
          </div>
        </div>
      )}

      {error && <p className="error-text">{error}</p>}
      <div className="panel">
        <table>
          <thead>
            <tr>
              <th>{t("gw.name")}</th>
              <th>{t("gw.a2a.card")}</th>
              <th>{t("gw.status")}</th>
              <th>{t("gw.last_sync")}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {loading && <tr className="empty-row"><td colSpan={5}>{t("common.loading")}</td></tr>}
            {!loading && peers.length === 0 && <tr className="empty-row"><td colSpan={5}>{t("gw.a2a.none")}</td></tr>}
            {peers.map((p) => {
              const card = (p.card || {}) as { name?: string; description?: string; skills?: unknown[] };
              return (
                <tr key={p.id}>
                  <td>
                    <strong>{p.name}</strong>
                    <div className="hint-text u-mono">{p.tool_name}</div>
                    <SealedCredential obj="a2a_peer" id={p.id} />
                  </td>
                  <td style={{ maxWidth: 320 }}>
                    {card.name ? <div>{card.name}</div> : null}
                    {card.description ? <div className="hint-text">{String(card.description).slice(0, 160)}</div> : null}
                    <div className="hint-text u-mono" style={{ wordBreak: "break-all" }}>{p.card_url}</div>
                    {p.protocol_version && (
                      <div className="hint-text">A2A {p.protocol_version}{Array.isArray(card.skills) ? ` · ${t("gw.a2a.skills", { n: card.skills.length })}` : ""}</div>
                    )}
                  </td>
                  <td>
                    <span className={`pill ${PEER_PILL[p.status] ?? "pill-neutral"}`}>{t(`gw.tool_status.${p.status}`, p.status)}</span>
                    {!p.enabled && <div className="hint-text">{t("gw.disabled")}</div>}
                    {p.served && <div className="hint-text">{t("gw.served")}</div>}
                    {p.last_error && <div className="hint-text" style={{ maxWidth: 240 }}>{p.last_error}</div>}
                  </td>
                  <td className="u-mono u-nowrap">{p.last_synced_at ? new Date(p.last_synced_at).toLocaleString(i18n.language) : t("gw.never")}</td>
                  <td className="u-nowrap">
                    <div className="u-btn-row">
                      {p.credential_source === "none" ? (
                        <button className="btn btn-sm" disabled={busy === p.id} onClick={() => act(p.id, () => syncA2aPeer(p.id))}>
                          {t("gw.sync")}
                        </button>
                      ) : (
                        <span className="hint-text" title={t("gw.synced_by_proxy_a2a_hint", "Its credential is sealed to the egress proxies: they fetch its card every minute and agents reach it through them (/_a2a/<peer>).")}>
                          {t("gw.synced_by_proxy", "synced by the egress proxies")}
                        </span>
                      )}
                      {(p.status === "pending" || p.status === "drifted") && (
                        <button className="btn btn-sm btn-primary" disabled={busy === p.id} onClick={() => act(p.id, () => approveA2aPeer(p.id))}>
                          {p.status === "drifted" ? t("gw.approve_change") : t("gw.approve")}
                        </button>
                      )}
                      {p.status !== "blocked" && p.status !== "unsynced" && (
                        <button className="btn btn-sm btn-danger" disabled={busy === p.id} onClick={() => act(p.id, () => blockA2aPeer(p.id))}>
                          {t("gw.block")}
                        </button>
                      )}
                      <button className="btn btn-sm" disabled={busy === p.id}
                              onClick={() => act(p.id, () => updateA2aPeer(p.id, { enabled: !p.enabled }))}>
                        {p.enabled ? t("gw.disable") : t("gw.enable")}
                      </button>
                      <button className="btn btn-sm btn-danger" disabled={busy === p.id}
                              onClick={async () => {
                                if (await confirm(t("gw.confirm_delete", { name: p.name }), { danger: true })) {
                                  act(p.id, () => deleteA2aPeer(p.id));
                                }
                              }}>
                        {t("common.delete")}
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}
