"use client";

// Teams (org -> team -> sub-team -> agent) and role templates: named sets of
// rights. An agent with a role has exactly the role's rights; editing the role
// changes every agent that has it.

import React, { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { Form } from "@/components/Form";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import { translateApiError } from "@/lib/errors";
import { listPolicies, type AttestationPolicyT } from "@/lib/attestation_api";
import {
  createRole, createTeam, deleteRole, deleteTeam, listRoles, listTeams, splitList, teamPath, updateRole, updateTeam,
  type RoleT, type TeamT,
} from "@/lib/teams_api";

type TeamForm = { id: number | null; name: string; description: string; parent_id: string };
type RoleForm = {
  id: number | null; name: string; team_id: string; description: string; capabilities: string; allowed_tools: string;
  allowed_models: string; max_delegation_depth: number; require_hybrid: boolean; require_attestation: boolean;
  attestation_policy_id: string;
};

const EMPTY_TEAM: TeamForm = { id: null, name: "", description: "", parent_id: "" };
const EMPTY_ROLE: RoleForm = {
  id: null, name: "", team_id: "", description: "", capabilities: "", allowed_tools: "", allowed_models: "",
  max_delegation_depth: 3, require_hybrid: false, require_attestation: false, attestation_policy_id: "",
};

function apiError(err: unknown, t: ReturnType<typeof useTranslation>["t"], fallback: string) {
  let detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  const d = detail as { code?: string; context?: { parts?: string[]; agent_names?: string } } | undefined;
  if (d?.code === "team.not_empty" && Array.isArray(d.context?.parts)) {
    // what still uses the team, in the reader's language, naming the agents
    const used = d.context.parts
      .map((p) => (p === "agents" && d.context?.agent_names ? `${t("teams.part_agents")} (${d.context.agent_names})` : t(`teams.part_${p}`, p)))
      .join(", ");
    const msg = t("errors.team.not_empty", { used });
    return d.context.parts.includes("agents") ? `${msg}. ${t("teams.not_empty_agents_hint")}` : msg;
  }
  const msg = Array.isArray(detail) && detail[0]?.msg ? String(detail[0].msg).replace(/^Value error, /, "") : null;
  return msg ?? translateApiError(detail, t, fallback);
}

export default function TeamsPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [teams, setTeams] = useState<TeamT[]>([]);
  const [roles, setRoles] = useState<RoleT[]>([]);
  const [policies, setPolicies] = useState<AttestationPolicyT[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [teamForm, setTeamForm] = useState<TeamForm | null>(null);
  const [roleForm, setRoleForm] = useState<RoleForm | null>(null);

  const load = useCallback(() => {
    Promise.all([listTeams(), listRoles()])
      .then(([ts, rs]) => { setTeams(ts); setRoles(rs); })
      .catch((err) => setError(apiError(err, t, t("teams.load_failed"))));
    listPolicies().then(setPolicies).catch(() => setPolicies([]));
  }, [t]);
  useEffect(load, [load]);

  // teams in tree order: each followed by its sub-teams
  const ordered: { team: TeamT; level: number }[] = useMemo(() => {
    const out: { team: TeamT; level: number }[] = [];
    const kids = (pid: number | null) => teams.filter((x) => x.parent_id === pid).sort((a, b) => a.name.localeCompare(b.name));
    const ids = new Set(teams.map((x) => x.id));
    const walk = (pid: number | null, level: number) => {
      for (const k of kids(pid)) { out.push({ team: k, level }); walk(k.id, level + 1); }
    };
    walk(null, 0);
    // a parent outside the list (should not happen) - still show the team
    for (const x of teams) if (x.parent_id !== null && !ids.has(x.parent_id)) out.push({ team: x, level: 0 });
    return out;
  }, [teams]);

  async function run(action: () => Promise<unknown>, ok: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await action();
      setNotice(ok);
      load();
    } catch (err) {
      setError(apiError(err, t, t("teams.failed")));
    } finally {
      setBusy(false);
    }
  }

  function saveTeam(e: React.FormEvent) {
    e.preventDefault();
    if (!teamForm) return;
    const body = {
      name: teamForm.name.trim(),
      description: teamForm.description.trim(),
      parent_id: teamForm.parent_id ? Number(teamForm.parent_id) : null,
    };
    run(async () => {
      if (teamForm.id) await updateTeam(teamForm.id, body);
      else await createTeam(body);
      setTeamForm(null);
    }, t("teams.saved"));
  }

  function saveRole(e: React.FormEvent) {
    e.preventDefault();
    if (!roleForm) return;
    const body = {
      name: roleForm.name.trim(),
      team_id: roleForm.team_id ? Number(roleForm.team_id) : null,
      description: roleForm.description.trim() || null,
      capabilities: splitList(roleForm.capabilities),
      allowed_tools: splitList(roleForm.allowed_tools),
      allowed_models: splitList(roleForm.allowed_models),
      max_delegation_depth: roleForm.max_delegation_depth,
      require_hybrid: roleForm.require_hybrid,
      require_attestation: roleForm.require_attestation,
      attestation_policy_id: roleForm.attestation_policy_id ? Number(roleForm.attestation_policy_id) : null,
    };
    if (roleForm.require_attestation && !roleForm.attestation_policy_id) {
      setError(t("errors.role.attestation_policy_required"));
      return;
    }
    if (roleForm.id) {
      const current = roles.find((r) => r.id === roleForm.id);
      if (current && current.agents > 0 && !window.confirm(t("teams.confirm_role_update", { count: current.agents }))) return;
      if (current && current.agents > 0 && roleForm.require_attestation && !current.require_attestation
          && !window.confirm(t("teams.confirm_attestation_on", { count: current.agents }))) return;
    }
    let updated = 0;
    const id = roleForm.id;
    setBusy(true);
    setError(null);
    setNotice(null);
    (async () => {
      try {
        if (id) updated = (await updateRole(id, body)).agents_updated ?? 0;
        else await createRole(body);
        setRoleForm(null);
        setNotice(id ? t("teams.role_saved_agents", { count: updated }) : t("teams.saved"));
        load();
      } catch (err) {
        setError(apiError(err, t, t("teams.failed")));
      } finally {
        setBusy(false);
      }
    })();
  }

  const teamOptions = ordered.map(({ team, level }) => (
    <option key={team.id} value={team.id}>{"  ".repeat(level)}{team.name}</option>
  ));

  return (
    <>
      <PageHeader title={t("teams.title")} />
      <div className="content">
        <p className="hint-text u-mb-16">{t("teams.intro")}</p>
        {error && <p className="error-text u-mb-16">{error}</p>}
        {notice && <p className="hint-text u-mb-16">{notice}</p>}

        {/* ---------------- teams ---------------- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h2>{t("teams.teams")}</h2>
            {isAdmin && !teamForm && (
              <button className="btn btn-sm btn-primary" onClick={() => setTeamForm(EMPTY_TEAM)}>{t("teams.new_team")}</button>
            )}
          </div>
          {teamForm && (
            <div className="panel-body">
              <Form onSubmit={saveTeam}>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="team-name">{t("teams.name")}</label>
                    <input id="team-name" required maxLength={100} value={teamForm.name}
                      onChange={(e) => setTeamForm({ ...teamForm, name: e.target.value })} />
                  </div>
                  <div className="field">
                    <label htmlFor="team-parent">{t("teams.parent")}</label>
                    <select id="team-parent" value={teamForm.parent_id}
                      onChange={(e) => setTeamForm({ ...teamForm, parent_id: e.target.value })}>
                      <option value="">{t("teams.no_parent")}</option>
                      {ordered.filter(({ team }) => team.id !== teamForm.id).map(({ team, level }) => (
                        <option key={team.id} value={team.id}>{"  ".repeat(level)}{team.name}</option>
                      ))}
                    </select>
                  </div>
                </div>
                <div className="field">
                  <label htmlFor="team-desc">{t("teams.description")}</label>
                  <input id="team-desc" maxLength={2000} value={teamForm.description}
                    onChange={(e) => setTeamForm({ ...teamForm, description: e.target.value })} />
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <button className="btn btn-primary" type="submit" disabled={busy}>{t("teams.save")}</button>
                  <button className="btn" type="button" onClick={() => setTeamForm(null)}>{t("teams.cancel")}</button>
                </div>
              </Form>
            </div>
          )}
          <div className="panel-body" style={{ overflowX: "auto", paddingTop: teamForm ? 0 : undefined }}>
            {ordered.length === 0 ? (
              <p className="hint-text">{t("teams.no_teams")}</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>{t("teams.name")}</th>
                    <th>{t("teams.agents")}</th>
                    <th>{t("teams.roles")}</th>
                    {isAdmin && <th />}
                  </tr>
                </thead>
                <tbody>
                  {ordered.map(({ team, level }) => (
                    <tr key={team.id}>
                      <td>
                        <div style={{ paddingLeft: level * 18 }}>
                          {level > 0 && <span className="hint-text">└ </span>}
                          <strong>{team.name}</strong>
                          {team.description && <div className="hint-text" style={{ fontSize: 12 }}>{team.description}</div>}
                        </div>
                      </td>
                      <td>{team.agents}</td>
                      <td>{team.roles}</td>
                      {isAdmin && (
                        <td style={{ whiteSpace: "nowrap", textAlign: "right" }}>
                          <button className="btn btn-sm" disabled={busy} onClick={() => setTeamForm({
                            id: team.id, name: team.name, description: team.description ?? "",
                            parent_id: team.parent_id ? String(team.parent_id) : "",
                          })}>{t("teams.edit")}</button>{" "}
                          <button className="btn btn-sm btn-danger" disabled={busy} onClick={() => {
                            if (window.confirm(t("teams.confirm_delete_team", { name: team.name }))) {
                              run(() => deleteTeam(team.id), t("teams.deleted"));
                            }
                          }}>{t("teams.delete")}</button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* ---------------- roles ---------------- */}
        <div className="panel">
          <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h2>{t("teams.role_templates")}</h2>
            {isAdmin && !roleForm && (
              <button className="btn btn-sm btn-primary" onClick={() => setRoleForm(EMPTY_ROLE)}>{t("teams.new_role")}</button>
            )}
          </div>
          <div className="panel-body" style={{ paddingBottom: 0 }}>
            <p className="hint-text">{t("teams.roles_hint")}</p>
          </div>
          {roleForm && (
            <div className="panel-body">
              <Form onSubmit={saveRole}>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="role-name">{t("teams.name")}</label>
                    <input id="role-name" required maxLength={100} value={roleForm.name}
                      onChange={(e) => setRoleForm({ ...roleForm, name: e.target.value })} placeholder="support-reader" />
                  </div>
                  <div className="field">
                    <label htmlFor="role-team">{t("teams.role_team")}</label>
                    <select id="role-team" value={roleForm.team_id}
                      onChange={(e) => setRoleForm({ ...roleForm, team_id: e.target.value })}>
                      <option value="">{t("teams.org_wide")}</option>
                      {teamOptions}
                    </select>
                  </div>
                </div>
                <div className="field">
                  <label htmlFor="role-desc">{t("teams.description")}</label>
                  <input id="role-desc" maxLength={2000} value={roleForm.description}
                    onChange={(e) => setRoleForm({ ...roleForm, description: e.target.value })} />
                </div>
                <div className="field">
                  <label htmlFor="role-caps">{t("agents.capabilities")}</label>
                  <input id="role-caps" className="mono" value={roleForm.capabilities}
                    onChange={(e) => setRoleForm({ ...roleForm, capabilities: e.target.value })} placeholder="read_analytics, generate_text" />
                  <p className="hint-text">{t("agents.comma_hint")}</p>
                </div>
                <div className="field">
                  <label htmlFor="role-tools">{t("agents.tools")}</label>
                  <input id="role-tools" className="mono" value={roleForm.allowed_tools}
                    onChange={(e) => setRoleForm({ ...roleForm, allowed_tools: e.target.value })} placeholder="kb.search, openai.chat" />
                </div>
                <div className="field">
                  <label htmlFor="role-models">{t("agents.models")}</label>
                  <input id="role-models" className="mono" value={roleForm.allowed_models}
                    onChange={(e) => setRoleForm({ ...roleForm, allowed_models: e.target.value })} placeholder="gpt-4o-mini" />
                </div>
                <div className="field">
                  <label htmlFor="role-depth">{t("agents.max_depth")}</label>
                  <input id="role-depth" type="number" min={0} max={10} value={roleForm.max_delegation_depth}
                    onChange={(e) => setRoleForm({ ...roleForm, max_delegation_depth: Number(e.target.value) })} />
                </div>
                <label style={{ display: "flex", gap: 8, alignItems: "flex-start", fontWeight: 400 }}>
                  <input type="checkbox" style={{ width: "auto", marginTop: 3 }} checked={roleForm.require_hybrid}
                    onChange={(e) => setRoleForm({ ...roleForm, require_hybrid: e.target.checked })} />
                  <span>{t("teams.require_hybrid")}<span className="hint-text" style={{ display: "block", fontSize: 12 }}>{t("teams.require_hybrid_hint")}</span></span>
                </label>
                <label style={{ display: "flex", gap: 8, alignItems: "flex-start", fontWeight: 400, marginTop: 8 }}>
                  <input type="checkbox" style={{ width: "auto", marginTop: 3 }} checked={roleForm.require_attestation}
                    onChange={(e) => setRoleForm({ ...roleForm, require_attestation: e.target.checked })} />
                  <span>{t("teams.require_attestation")}<span className="hint-text" style={{ display: "block", fontSize: 12 }}>{t("teams.require_attestation_hint")}</span></span>
                </label>
                {roleForm.require_attestation && (
                  <div className="field" style={{ marginTop: 8, marginLeft: 26 }}>
                    <label htmlFor="role-attest-policy">{t("teams.attestation_policy")}</label>
                    {policies.length > 0 ? (
                      <select id="role-attest-policy" required value={roleForm.attestation_policy_id}
                        onChange={(e) => setRoleForm({ ...roleForm, attestation_policy_id: e.target.value })}>
                        <option value="">—</option>
                        {policies.map((p) => <option key={p.id} value={p.id}>{p.name} (aud {p.audience})</option>)}
                      </select>
                    ) : (
                      <p className="hint-text">{t("teams.no_attestation_policies")} <Link href="/attestation">{t("attest.title")}</Link></p>
                    )}
                  </div>
                )}
                <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
                  <button className="btn btn-primary" type="submit" disabled={busy}>{t("teams.save")}</button>
                  <button className="btn" type="button" onClick={() => setRoleForm(null)}>{t("teams.cancel")}</button>
                </div>
              </Form>
            </div>
          )}
          <div className="panel-body" style={{ overflowX: "auto" }}>
            {roles.length === 0 ? (
              <p className="hint-text">{t("teams.no_roles")}</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>{t("teams.role")}</th>
                    <th>{t("teams.rights")}</th>
                    <th>{t("teams.agents")}</th>
                    {isAdmin && <th />}
                  </tr>
                </thead>
                <tbody>
                  {roles.map((r) => (
                    <tr key={r.id}>
                      <td>
                        <strong>{r.name}</strong>
                        <div className="hint-text" style={{ fontSize: 12 }}>
                          {r.team_id ? teamPath(teams, r.team_id) : t("teams.org_wide")}
                        </div>
                        <div style={{ display: "flex", gap: 4, marginTop: 4, flexWrap: "wrap" }}>
                          {r.require_hybrid && <span className="pill pill-accent">{t("teams.hybrid_pill")}</span>}
                          {r.require_attestation && (
                            <span className={`pill ${r.attestation_policy_id ? "pill-medium" : "pill-critical"}`}
                              title={r.attestation_policy_id ? "" : t("errors.agent.attestation_policy_missing")}>
                              {t("teams.attestation_pill")}
                              {r.attestation_policy_id ? `: ${policies.find((p) => p.id === r.attestation_policy_id)?.name ?? "#" + r.attestation_policy_id}` : " !"}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="mono" style={{ fontSize: 12 }}>
                        <div>{t("agents.capabilities")}: {r.capabilities.join(", ") || "—"}</div>
                        <div>{t("agents.tools")}: {r.allowed_tools.join(", ") || "—"}</div>
                        <div>{t("agents.models")}: {r.allowed_models.join(", ") || "—"}</div>
                        <div>{t("agents.max_depth")}: {r.max_delegation_depth}</div>
                      </td>
                      <td>{r.agents}</td>
                      {isAdmin && (
                        <td style={{ whiteSpace: "nowrap", textAlign: "right" }}>
                          <button className="btn btn-sm" disabled={busy} onClick={() => setRoleForm({
                            id: r.id, name: r.name, team_id: r.team_id ? String(r.team_id) : "",
                            description: r.description ?? "", capabilities: r.capabilities.join(", "),
                            allowed_tools: r.allowed_tools.join(", "), allowed_models: r.allowed_models.join(", "),
                            max_delegation_depth: r.max_delegation_depth, require_hybrid: r.require_hybrid,
                            require_attestation: r.require_attestation,
                            attestation_policy_id: r.attestation_policy_id ? String(r.attestation_policy_id) : "",
                          })}>{t("teams.edit")}</button>{" "}
                          <button className="btn btn-sm btn-danger" disabled={busy} onClick={() => {
                            if (window.confirm(t("teams.confirm_delete_role", { name: r.name }))) {
                              run(() => deleteRole(r.id), t("teams.deleted"));
                            }
                          }}>{t("teams.delete")}</button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
