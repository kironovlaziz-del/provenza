"use client";

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { Form } from "@/components/Form";
import { registerAgent } from "@/lib/agent_api";
import { linkFoundAgent } from "@/lib/endpoints_api";
import type { AgentCreated } from "@/lib/agent_types";
import { translateApiError } from "@/lib/errors";

// small helper: comma/space separated string -> string[]
function toList(s: string): string[] {
  return s.split(/[,\n]/).map((x) => x.trim()).filter(Boolean);
}

export default function NewAgentPage() {
  const router = useRouter();
  const { t } = useTranslation();
  const [name, setName] = useState("");
  // Opened from Discovery -> Agents Found: register that finding.
  const [foundId, setFoundId] = useState<number | null>(null);
  const [description, setDescription] = useState("");
  const [linkResult, setLinkResult] = useState<"linked" | "failed" | null>(null);

  useEffect(() => {
    const p = new URLSearchParams(window.location.search);
    const found = Number(p.get("found"));
    if (found > 0) {
      setFoundId(found);
      setName((p.get("name") || "").slice(0, 100));
      setDescription((p.get("description") || "").slice(0, 500));
      const type = p.get("type");
      if (type && ["crewai", "langgraph", "autogen", "custom"].includes(type)) setAgentType(type);
    }
  }, []);
  const [agentType, setAgentType] = useState("custom");
  const [ownerTeam, setOwnerTeam] = useState("");
  const [capabilities, setCapabilities] = useState("");
  const [tools, setTools] = useState("");
  const [models, setModels] = useState("");
  const [depth, setDepth] = useState(3);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<AgentCreated | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedPriv, setCopiedPriv] = useState(false);
  // "agent": the agent keeps its own private key (recommended);
  // "server": quick start, the server generates the pair and shows it once.
  const [keyMode, setKeyMode] = useState<"agent" | "server">("agent");
  const [publicKey, setPublicKey] = useState("");
  // Hybrid = Ed25519 + ML-DSA-65: both signatures are required, so a forgery
  // needs to break both (ML-DSA resists quantum attacks on elliptic curves).
  const [hybrid, setHybrid] = useState(true);
  const [pqPublicKey, setPqPublicKey] = useState("");
  const [copiedPq, setCopiedPq] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const agent = await registerAgent({
        name,
        description: description || undefined,
        agent_type: agentType,
        owner_team: ownerTeam || undefined,
        capabilities: toList(capabilities),
        allowed_tools: toList(tools),
        allowed_models: toList(models),
        max_delegation_depth: depth,
        public_key: keyMode === "agent" ? publicKey.trim() : undefined,
        pq_public_key: keyMode === "agent" && hybrid ? pqPublicKey.replace(/\s+/g, "") : undefined,
        key_scheme: keyMode === "server" ? (hybrid ? "hybrid" : "ed25519") : undefined,
      });
      if (foundId) {
        // the agent exists either way; a failed link is shown, not fatal
        setLinkResult(await linkFoundAgent(foundId, agent.id).then(() => "linked" as const, () => "failed" as const));
      }
      setCreated(agent);
    } catch (err) {
      const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
      const msg = Array.isArray(detail) && detail[0]?.msg ? String(detail[0].msg).replace(/^Value error, /, "") : null;
      setError(msg ?? translateApiError(detail, t, t("agents.register_failed")));
    } finally {
      setSubmitting(false);
    }
  }

  async function copy(text: string, which: "key" | "priv" | "pq") {
    try {
      await navigator.clipboard.writeText(text);
      if (which === "key") setCopiedKey(true);
      else if (which === "pq") setCopiedPq(true);
      else setCopiedPriv(true);
    } catch {
      /* clipboard may be unavailable; value is still visible */
    }
  }

  if (created) {
    return (
      <>
        <PageHeader title={t("agents.registered_title")} />
        <div className="content">
          {linkResult === "linked" && <p className="hint-text u-mb-16">{t("found.linked_note")}</p>}
          {linkResult === "failed" && <p className="error-text u-mb-16">{t("found.link_failed_note")}</p>}
          <div className="panel" style={{ borderColor: "var(--danger, #c0392b)" }}>
            <div className="panel-header"><h2>{t("agents.secrets_title")}</h2></div>
            <div className="panel-body">
              <p className="error-text" style={{ marginBottom: 14 }}>
                {t("agents.secrets_warning")}
              </p>

              <div className="field">
                <label>{t("agents.api_key")}</label>
                <div className="form-row" style={{ alignItems: "center" }}>
                  <code className="mono" style={{ wordBreak: "break-all", flex: 1 }}>{created.api_key}</code>
                  <button type="button" className="btn btn-sm" onClick={() => copy(created.api_key, "key")}>
                    {copiedKey ? t("agents.copied") : t("agents.copy")}
                  </button>
                </div>
              </div>

              {created.private_key ? (
                <div className="field" style={{ marginTop: 12 }}>
                  <label>{t("agents.private_key")}</label>
                  <div className="form-row" style={{ alignItems: "center" }}>
                    <code className="mono" style={{ wordBreak: "break-all", flex: 1 }}>{created.private_key}</code>
                    <button type="button" className="btn btn-sm" onClick={() => copy(created.private_key ?? "", "priv")}>
                      {copiedPriv ? t("agents.copied") : t("agents.copy")}
                    </button>
                  </div>
                  <p className="hint-text" style={{ marginTop: 6 }}>{t("agents.private_key_note")}</p>
                  {created.pq_private_key && (
                    <>
                      <label style={{ marginTop: 12 }}>{t("agents.pq_private_key")}</label>
                      <div className="form-row" style={{ alignItems: "center" }}>
                        <code className="mono" style={{ wordBreak: "break-all", flex: 1 }}>{created.pq_private_key}</code>
                        <button type="button" className="btn btn-sm" onClick={() => copy(created.pq_private_key ?? "", "pq")}>
                          {copiedPq ? t("agents.copied") : t("agents.copy")}
                        </button>
                      </div>
                      <p className="hint-text" style={{ marginTop: 6 }}>{t("agents.pq_private_key_note")}</p>
                    </>
                  )}
                  <p className="hint-text" style={{ marginTop: 6 }}>{t("agents.key_server_note")}</p>
                </div>
              ) : (
                <p className="hint-text" style={{ marginTop: 12 }}>{t("agents.key_agent_note")}</p>
              )}
              {created.key_fingerprint && (
                <div className="field" style={{ marginTop: 12 }}>
                  <label>{t("agents.key_fingerprint")}</label>
                  <code className="mono" style={{ wordBreak: "break-all" }}>{created.key_fingerprint}</code>
                  <p className="hint-text" style={{ marginTop: 6 }}>
                    {t("agents.scheme")}: {created.pq_public_key ? t("agents.scheme_hybrid") : t("agents.scheme_classic")}
                  </p>
                  <p className="hint-text" style={{ marginTop: 6 }}>{t("agents.key_fingerprint_hint")}</p>
                </div>
              )}

              <button className="btn btn-primary" style={{ marginTop: 18 }} onClick={() => router.push("/agents")}>
                {t("agents.done")}
              </button>
            </div>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <PageHeader title={t("agents.register")} />
      <div className="content">
        {foundId && (
          <p className="hint-text u-mb-16">
            {t("found.registering_note")} {description && <strong>{description}</strong>}
          </p>
        )}
        <div className="panel">
          <div className="panel-body">
            <Form onSubmit={handleSubmit}>
              <div className="form-row">
                <div className="field">
                  <label>{t("agents.name")}</label>
                  <input required value={name} onChange={(e) => setName(e.target.value)} placeholder="marketing-assistant" />
                </div>
                <div className="field">
                  <label>{t("agents.type")}</label>
                  <select value={agentType} onChange={(e) => setAgentType(e.target.value)}>
                    <option value="crewai">CrewAI</option>
                    <option value="langgraph">LangGraph</option>
                    <option value="autogen">AutoGen</option>
                    <option value="custom">Custom</option>
                  </select>
                </div>
              </div>
              <div className="field">
                <label>{t("agents.owner_team")}</label>
                <input value={ownerTeam} onChange={(e) => setOwnerTeam(e.target.value)} placeholder="marketing" />
              </div>
              <div className="field">
                <label>{t("agents.capabilities")}</label>
                <input value={capabilities} onChange={(e) => setCapabilities(e.target.value)} placeholder="read_analytics, generate_text" />
                <p className="hint-text">{t("agents.comma_hint")}</p>
              </div>
              <div className="field">
                <label>{t("agents.tools")}</label>
                <input value={tools} onChange={(e) => setTools(e.target.value)} placeholder="openai.chat, google.analytics.read" />
              </div>
              <div className="field">
                <label>{t("agents.models")}</label>
                <input value={models} onChange={(e) => setModels(e.target.value)} placeholder="gpt-4o-mini" />
              </div>
              <div className="field">
                <label>{t("agents.max_depth")}</label>
                <input type="number" min={0} max={10} value={depth} onChange={(e) => setDepth(Number(e.target.value))} />
              </div>
              <div className="field">
                <label>{t("agents.signing_key")}</label>
                <label style={{ display: "flex", gap: 8, alignItems: "center", fontWeight: 400 }}>
                  <input type="radio" name="keymode" checked={keyMode === "agent"} onChange={() => setKeyMode("agent")} style={{ width: "auto" }} />
                  {t("agents.key_mode_agent")}
                </label>
                <label style={{ display: "flex", gap: 8, alignItems: "center", fontWeight: 400 }}>
                  <input type="radio" name="keymode" checked={keyMode === "server"} onChange={() => setKeyMode("server")} style={{ width: "auto" }} />
                  {t("agents.key_mode_server")}
                </label>
                {keyMode === "agent" && (
                  <>
                    <input
                      className="mono"
                      required
                      value={publicKey}
                      onChange={(e) => setPublicKey(e.target.value)}
                      placeholder={t("agents.public_key_placeholder")}
                      style={{ marginTop: 6 }}
                    />
                    <p className="hint-text">{t("agents.public_key_hint")}</p>
                  </>
                )}
                <label style={{ display: "flex", gap: 8, alignItems: "flex-start", fontWeight: 400, marginTop: 8 }}>
                  <input type="checkbox" checked={hybrid} onChange={(e) => setHybrid(e.target.checked)} style={{ width: "auto", marginTop: 3 }} />
                  <span>
                    {t("agents.hybrid")}
                    <span className="hint-text" style={{ display: "block", fontSize: 12 }}>{t("agents.hybrid_hint")}</span>
                  </span>
                </label>
                {keyMode === "agent" && hybrid && (
                  <>
                    <textarea
                      className="mono"
                      required
                      rows={4}
                      value={pqPublicKey}
                      onChange={(e) => setPqPublicKey(e.target.value)}
                      placeholder={t("agents.pq_public_key_placeholder")}
                      style={{ marginTop: 6, fontSize: 11, wordBreak: "break-all" }}
                    />
                    <p className="hint-text">{t("agents.pq_public_key_hint")}</p>
                  </>
                )}
              </div>
              {error && <p className="error-text">{error}</p>}
              <button className="btn btn-primary" type="submit" disabled={submitting}>
                {submitting ? t("agents.registering") : t("agents.register")}
              </button>
            </Form>
          </div>
        </div>
      </div>
    </>
  );
}
