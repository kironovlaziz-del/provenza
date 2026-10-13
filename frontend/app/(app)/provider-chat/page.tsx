"use client";

import React, { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { listProviders, providerChat, listProviderModels } from "@/lib/api";
import { errorMessage } from "@/lib/errors";

interface Provider {
  id: number; name: string; type: string; default_model?: string | null; status: string;
}
interface Msg { role: "user" | "assistant"; text: string; flags?: string[]; blocked?: boolean; }

export default function ProviderChatPage() {
  const { t } = useTranslation();
  const [providers, setProviders] = useState<Provider[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [models, setModels] = useState<string[]>([]);
  const [model, setModel] = useState<string>("");
  const [modelsLoading, setModelsLoading] = useState(false);
  const [messages, setMessages] = useState<Msg[]>([]);
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    listProviders()
      .then((rows: Provider[]) => {
        const active = rows.filter((p) => p.status === "active");
        setProviders(active);
        if (active.length) setSelectedId(active[0].id);
      })
      .finally(() => setLoading(false));
  }, []);

  // when provider changes: reset chat, load its models
  useEffect(() => {
    setMessages([]);
    setModels([]);
    setModel("");
    if (selectedId == null) return;
    const prov = providers.find((p) => p.id === selectedId);
    setModelsLoading(true);
    listProviderModels(selectedId)
      .then((res) => {
        setModels(res.models || []);
        // default to provider's default_model if present in list, else first
        const def = prov?.default_model && res.models?.includes(prov.default_model)
          ? prov.default_model
          : (res.models?.[0] || "");
        setModel(def);
      })
      .catch(() => setModels([]))
      .finally(() => setModelsLoading(false));
  }, [selectedId, providers]);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  async function handleSend(e: React.FormEvent) {
    e.preventDefault();
    if (!draft.trim() || selectedId == null || sending) return;
    const userMsg: Msg = { role: "user", text: draft };
    setMessages((m) => [...m, userMsg]);
    setDraft("");
    setSending(true);
    setError(null);
    try {
      const res = await providerChat(selectedId, userMsg.text, undefined, model || undefined);
      if (res.blocked) {
        setMessages((m) => [...m, { role: "assistant", text: res.blocked_reason || t("provider_chat.blocked"), blocked: true }]);
      } else {
        setMessages((m) => [...m, { role: "assistant", text: res.answer, flags: res.flags }]);
      }
    } catch (err) {
      setError(errorMessage(err, t, t("provider_chat.failed")));
    } finally {
      setSending(false);
    }
  }

  const selected = providers.find((p) => p.id === selectedId);

  // dark chat palette
  const C = {
    panel: "#121826", panel2: "#0d121e", line: "#273349", text: "#e6ebf5",
    muted: "#8a97b1", user: "#2563eb", bot: "#1b2333", accent: "#22d3ee",
  };

  return (
    <>
      <PageHeader title={t("provider_chat.title")} />
      <div className="content">
        <p className="hint-text u-mb-16">{t("provider_chat.hint")}</p>

        {/* controls row: provider + model selectors */}
        <div style={{ display: "flex", gap: 12, marginBottom: 14, flexWrap: "wrap", alignItems: "center" }}>
          <div>
            <label className="hint-text" style={{ display: "block", fontSize: 11, marginBottom: 3 }}>{t("provider_chat.provider")}</label>
            <select
              value={selectedId ?? ""}
              onChange={(e) => setSelectedId(e.target.value ? Number(e.target.value) : null)}
              disabled={loading || providers.length === 0}
              style={{ minWidth: 180 }}
            >
              {providers.length === 0 && <option>{t("provider_chat.no_providers")}</option>}
              {providers.map((p) => <option key={p.id} value={p.id}>{p.name} ({p.type})</option>)}
            </select>
          </div>
          <div>
            <label className="hint-text" style={{ display: "block", fontSize: 11, marginBottom: 3 }}>{t("provider_chat.model")}</label>
            <select
              value={model}
              onChange={(e) => setModel(e.target.value)}
              disabled={modelsLoading || models.length === 0}
              style={{ minWidth: 240 }}
            >
              {modelsLoading && <option>{t("common.loading")}</option>}
              {!modelsLoading && models.length === 0 && <option>{t("provider_chat.no_models")}</option>}
              {models.map((m) => <option key={m} value={m}>{m}</option>)}
            </select>
          </div>
        </div>

        {/* compact dark chat window */}
        <div style={{
          maxWidth: 720, border: `1px solid ${C.line}`, borderRadius: 12, overflow: "hidden",
          background: C.panel, boxShadow: "0 8px 30px -12px rgba(0,0,0,0.5)",
        }}>
          {/* header */}
          <div style={{ padding: "10px 14px", borderBottom: `1px solid ${C.line}`, background: C.panel2, display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: C.accent, boxShadow: `0 0 8px ${C.accent}` }} />
            <span style={{ color: C.text, fontSize: 13, fontWeight: 600 }}>
              {selected ? selected.name : t("provider_chat.select_provider")}
            </span>
            {model && <span style={{ color: C.muted, fontSize: 11, fontFamily: "monospace" }}>· {model}</span>}
          </div>

          {/* messages — fixed height, scrollable */}
          <div style={{ height: 380, overflowY: "auto", padding: 16, display: "flex", flexDirection: "column", gap: 10, background: C.panel }}>
            {messages.length === 0 && (
              <div style={{ margin: "auto", color: C.muted, fontSize: 13, textAlign: "center" }}>
                {t("provider_chat.empty")}
              </div>
            )}
            {messages.map((m, i) => (
              <div key={i} style={{ alignSelf: m.role === "user" ? "flex-end" : "flex-start", maxWidth: "80%" }}>
                <div style={{
                  padding: "9px 13px", borderRadius: 12, fontSize: 13.5, lineHeight: 1.5,
                  background: m.role === "user" ? C.user : (m.blocked ? "#3b1d1d" : C.bot),
                  color: m.role === "user" ? "#fff" : (m.blocked ? "#fca5a5" : C.text),
                  whiteSpace: "pre-wrap", wordBreak: "break-word",
                  border: m.role === "user" ? "none" : `1px solid ${C.line}`,
                }}>
                  {m.text}
                </div>
                {m.flags && m.flags.length > 0 && (
                  <div style={{ color: C.accent, fontSize: 10.5, marginTop: 3, fontFamily: "monospace" }}>
                    🛡 {t("provider_chat.masked")}: {m.flags.join(", ")}
                  </div>
                )}
              </div>
            ))}
            <div ref={endRef} />
          </div>

          {/* input */}
          {error && <div style={{ color: "#fca5a5", fontSize: 12, padding: "0 14px 6px", background: C.panel }}>{error}</div>}
          <form onSubmit={handleSend} style={{ display: "flex", gap: 8, padding: 12, borderTop: `1px solid ${C.line}`, background: C.panel2 }}>
            <input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder={t("provider_chat.placeholder")}
              disabled={selectedId == null || sending}
              style={{
                flex: 1, background: C.panel, border: `1px solid ${C.line}`, borderRadius: 8,
                color: C.text, padding: "9px 12px", fontSize: 13.5, outline: "none",
              }}
            />
            <button
              type="submit"
              disabled={selectedId == null || sending || !draft.trim()}
              style={{
                background: C.accent, color: "#04141a", border: "none", borderRadius: 8,
                padding: "0 18px", fontSize: 13.5, fontWeight: 600, cursor: "pointer",
                opacity: (selectedId == null || sending || !draft.trim()) ? 0.5 : 1,
              }}
            >
              {sending ? t("provider_chat.sending") : t("provider_chat.send")}
            </button>
          </form>
        </div>
      </div>
    </>
  );
}
