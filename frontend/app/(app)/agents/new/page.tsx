"use client";

import React, { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { Form } from "@/components/Form";
import { registerAgent } from "@/lib/agent_api";
import { linkFoundAgent } from "@/lib/endpoints_api";
import { issueEnrollment, type EnrollmentT } from "@/lib/enrollment_api";
import { attestCommand, podSpecSnippet } from "@/lib/attestation_api";
import { EnrollPanel } from "@/components/EnrollPanel";
import { getIdentityOverview } from "@/lib/agent_identity_api";
import type { AgentCreated } from "@/lib/agent_types";
import { translateApiError } from "@/lib/errors";
import { assignAgent, listRoles, listTeams, teamPath, type RoleT, type TeamT } from "@/lib/teams_api";

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
  // org -> team -> agent; a role template gives the rights (and keeps them in step)
  const [teams, setTeams] = useState<TeamT[]>([]);
  const [roles, setRoles] = useState<RoleT[]>([]);
  const [teamId, setTeamId] = useState("");
  const [roleId, setRoleId] = useState("");
  const [assignFailed, setAssignFailed] = useState<string | null>(null);
  const [capabilities, setCapabilities] = useState("");
  const [tools, setTools] = useState("");
  const [models, setModels] = useState("");
  const [depth, setDepth] = useState(3);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<AgentCreated | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedPriv, setCopiedPriv] = useState(false);
  // "enroll": a one-time token; the agent generates its key and proves it
  //           holds it (the default, and the only way in strict organizations);
  // "agent":  direct registration of a public key, nothing proven;
  // "server": quick start, the server generates the pair and shows it once.
  const [keyMode, setKeyMode] = useState<"enroll" | "agent" | "server">("enroll");
  const [directAllowed, setDirectAllowed] = useState(false);
  const [ttl, setTtl] = useState(24);
  const [issued, setIssued] = useState<EnrollmentT | null>(null);

  useEffect(() => {
    Promise.all([listTeams(), listRoles()]).then(([ts, rs]) => { setTeams(ts); setRoles(rs); }).catch(() => undefined);
  }, []);
  // roles an agent of the chosen team can have: the team's own and org-wide ones
  // no team chosen: every role (a team's role then sets its team); a team chosen: its roles and org-wide ones
  const roleChoices = teamId ? roles.filter((r) => r.team_id === null || String(r.team_id) === teamId) : roles;
  const role = roleChoices.find((r) => String(r.id) === roleId) ?? null;
  useEffect(() => {
    if (roleId && !roleChoices.some((r) => String(r.id) === roleId)) setRoleId("");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [teamId, roles]);
  // a role that requires a hybrid key forces the box on; leaving it restores the choice
  const hybridBeforeRole = useRef<boolean | null>(null);
  useEffect(() => {
    if (role?.require_hybrid) {
      if (hybridBeforeRole.current === null) hybridBeforeRole.current = hybrid;
      setHybrid(true);
    } else if (hybridBeforeRole.current !== null) {
      setHybrid(hybridBeforeRole.current);
      hybridBeforeRole.current = null;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [role]);
  // with a role the rights are the role's: nothing typed in the hidden fields is sent
  const rights = role
    ? { capabilities: [], allowed_tools: [], allowed_models: [], max_delegation_depth: role.max_delegation_depth }
    : { capabilities: toList(capabilities), allowed_tools: toList(tools), allowed_models: toList(models), max_delegation_depth: depth };

  useEffect(() => {
    getIdentityOverview().then((o) => setDirectAllowed(!!o.settings.allow_direct_registration)).catch(() => setDirectAllowed(false));
  }, []);
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
      if (keyMode === "enroll") {
        setIssued(await issueEnrollment({
          name: name || undefined,
          description: description || undefined,
          agent_type: agentType,
          owner_team: teamId ? undefined : ownerTeam || undefined,
          team_id: teamId ? Number(teamId) : undefined,
          role_id: role ? role.id : undefined,
          ...rights,
          require_hybrid: hybrid,
          ttl_hours: ttl,
          discovered_agent_id: foundId ?? undefined,
        }));
        return;
      }
      const agent = await registerAgent({
        name,
        description: description || undefined,
        agent_type: agentType,
        owner_team: ownerTeam || undefined,
        ...rights,
        public_key: keyMode === "agent" ? publicKey.trim() : undefined,
        pq_public_key: keyMode === "agent" && hybrid ? pqPublicKey.replace(/\s+/g, "") : undefined,
        key_scheme: keyMode === "server" ? (hybrid ? "hybrid" : "ed25519") : undefined,
      });
      if (teamId || role) {
        // registered directly: put it in the team / give it the role afterwards
        await assignAgent(agent.id, teamId ? Number(teamId) : null, role ? role.id : null).catch((err) => {
          const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
          setAssignFailed(translateApiError(detail, t, t("teams.failed")));
        });
      }
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

  if (issued?.token) {
    return (
      <>
        <PageHeader title={t("enroll.issued_title")} />
        <div className="content">
          <div className="panel">
            <div className="panel-body" style={{ display: "grid", gap: 12 }}>
              <p>{t("enroll.issued_intro", { name: issued.name || "—", time: new Date(issued.expires_at).toLocaleString() })}</p>
              <div className="field">
                <label>{t("enroll.token")}</label>
                <code className="mono" style={{ wordBreak: "break-all" }}>{issued.token}</code>
                <p className="hint-text">{t("enroll.token_once")}</p>
              </div>
              <EnrollPanel token={issued.token} hybrid={issued.require_hybrid} />
              {issued.attestation?.required && (
                <div className="field">
                  <label>{t("attest.enroll_title")}</label>
                  <p className="hint-text">{t("attest.enroll_hint", { policy: issued.attestation.policy ?? "—", audience: issued.attestation.audience ?? "—" })}</p>
                  {issued.attestation.audience && (
                    <pre className="mono" style={{ fontSize: 11, whiteSpace: "pre", overflowX: "auto" }}>{podSpecSnippet(issued.attestation.audience)}</pre>
                  )}
                  <code className="mono" style={{ fontSize: 12 }}>{attestCommand(issued.attestation.validity_minutes ?? 60)}</code>
                </div>
              )}
              <div>
                <button type="button" className="btn btn-primary" onClick={() => router.push("/agent-identity")}>
                  {t("enroll.done")}
                </button>
              </div>
            </div>
          </div>
        </div>
      </>
    );
  }

  if (created) {
    return (
      <>
        <PageHeader title={t("agents.registered_title")} />
        <div className="content">
          {linkResult === "linked" && <p className="hint-text u-mb-16">{t("found.linked_note")}</p>}
          {linkResult === "failed" && <p className="error-text u-mb-16">{t("found.link_failed_note")}</p>}
          {assignFailed && <p className="error-text u-mb-16">{t("teams.assign_failed_note")}: {assignFailed}</p>}
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
                  <input required={keyMode !== "enroll"} value={name} onChange={(e) => setName(e.target.value)} placeholder="marketing-assistant" />
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
              <div className="form-row">
                <div className="field">
                  <label htmlFor="agent-team">{t("teams.team")}</label>
                  {teams.length > 0 ? (
                    <select id="agent-team" value={teamId} onChange={(e) => setTeamId(e.target.value)}>
                      <option value="">{t("teams.no_team")}</option>
                      {teams.map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}
                    </select>
                  ) : (
                    <input id="agent-team" value={ownerTeam} onChange={(e) => setOwnerTeam(e.target.value)} placeholder="marketing" />
                  )}
                </div>
                <div className="field">
                  <label htmlFor="agent-role">{t("teams.role")}</label>
                  <select id="agent-role" value={roleId} disabled={roleChoices.length === 0} onChange={(e) => {
                    const picked = roles.find((r) => String(r.id) === e.target.value);
                    if (picked?.team_id) setTeamId(String(picked.team_id));
                    setRoleId(e.target.value);
                  }}>
                    <option value="">{t("teams.no_role")}</option>
                    {roleChoices.map((r) => (
                      <option key={r.id} value={r.id}>{r.name} ({r.team_id === null ? t("teams.org_wide") : teamPath(teams, r.team_id)})</option>
                    ))}
                  </select>
                </div>
              </div>
              {teams.length === 0 && <p className="hint-text" style={{ marginTop: -8 }}>{t("teams.create_teams_hint")}</p>}
              {teams.length > 0 && roles.length === 0 && (
                <p className="hint-text" style={{ marginTop: -8 }}>{t("teams.create_roles_hint")}</p>
              )}
              {role ? (
                <div className="field">
                  <label>{t("teams.rights_from_role")}</label>
                  <div className="mono hint-text" style={{ fontSize: 12 }}>
                    <div>{t("agents.capabilities")}: {role.capabilities.join(", ") || "—"}</div>
                    <div>{t("agents.tools")}: {role.allowed_tools.join(", ") || "—"}</div>
                    <div>{t("agents.models")}: {role.allowed_models.join(", ") || "—"}</div>
                    <div>{t("agents.max_depth")}: {role.max_delegation_depth}</div>
                  </div>
                  <p className="hint-text">{t("teams.rights_from_role_hint")}</p>
                </div>
              ) : (
                <>
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
                </>
              )}
              <div className="field">
                <label>{t("agents.signing_key")}</label>
                <label style={{ display: "flex", gap: 8, alignItems: "center", fontWeight: 400 }}>
                  <input type="radio" name="keymode" checked={keyMode === "enroll"} onChange={() => setKeyMode("enroll")} style={{ width: "auto" }} />
                  {t("enroll.mode")}
                </label>
                {directAllowed && (
                  <>
                    <label style={{ display: "flex", gap: 8, alignItems: "center", fontWeight: 400 }}>
                      <input type="radio" name="keymode" checked={keyMode === "agent"} onChange={() => setKeyMode("agent")} style={{ width: "auto" }} />
                      {t("agents.key_mode_agent")} — {t("enroll.unproven")}
                    </label>
                    <label style={{ display: "flex", gap: 8, alignItems: "center", fontWeight: 400 }}>
                      <input type="radio" name="keymode" checked={keyMode === "server"} onChange={() => setKeyMode("server")} style={{ width: "auto" }} />
                      {t("agents.key_mode_server")}
                    </label>
                  </>
                )}
                {keyMode === "enroll" && (
                  <div style={{ marginTop: 6 }}>
                    <p className="hint-text">{t("enroll.mode_hint")}</p>
                    <label htmlFor="enr-ttl">{t("enroll.ttl")}</label>
                    <select id="enr-ttl" value={ttl} onChange={(e) => setTtl(Number(e.target.value))} style={{ width: "auto" }}>
                      {[1, 24, 72, 168].map((h) => <option key={h} value={h}>{t("enroll.ttl_hours", { count: h })}</option>)}
                    </select>
                  </div>
                )}
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
                  <input type="checkbox" checked={hybrid} disabled={!!role?.require_hybrid} onChange={(e) => setHybrid(e.target.checked)} style={{ width: "auto", marginTop: 3 }} />
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
                {submitting ? t("agents.registering") : keyMode === "enroll" ? t("enroll.issue") : t("agents.register")}
              </button>
            </Form>
          </div>
        </div>
      </div>
    </>
  );
}
