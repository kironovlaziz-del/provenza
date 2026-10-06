"use client";

// The agent's team and role template. With a role, its rights are the role's
// (and change with it); without one they are set per agent.

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import type { Agent } from "@/lib/agent_types";
import { translateApiError } from "@/lib/errors";
import { assignAgent, listRoles, listTeams, teamPath, type RoleT, type TeamT } from "@/lib/teams_api";

export function AgentAssignment({ agent, isAdmin, onChanged }: { agent: Agent; isAdmin: boolean; onChanged: () => void }) {
  const { t } = useTranslation();
  const [teams, setTeams] = useState<TeamT[]>([]);
  const [roles, setRoles] = useState<RoleT[]>([]);
  const [editing, setEditing] = useState(false);
  const [teamId, setTeamId] = useState(agent.team_id ? String(agent.team_id) : "");
  const [roleId, setRoleId] = useState(agent.role_id ? String(agent.role_id) : "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([listTeams(), listRoles()]).then(([ts, rs]) => { setTeams(ts); setRoles(rs); }).catch(() => undefined);
  }, [agent.team_id, agent.role_id]);

  const role = roles.find((r) => r.id === agent.role_id) ?? null;
  const choices = teamId ? roles.filter((r) => r.team_id === null || String(r.team_id) === teamId) : roles;

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const chosen = choices.find((r) => String(r.id) === roleId) ?? null;
      await assignAgent(agent.id, teamId ? Number(teamId) : null, chosen ? chosen.id : null);
      setEditing(false);
      onChanged();
    } catch (err) {
      const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
      setError(translateApiError(detail, t, t("teams.failed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="ag-label">{t("teams.team_and_role")}</div>
      {!editing ? (
        <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
          <span>
            {agent.team_id
              ? <strong>{teamPath(teams, agent.team_id) || agent.owner_team}</strong>
              : agent.owner_team
                ? <span title={t("teams.free_text_team")}>{agent.owner_team} <span className="hint-text">({t("teams.not_linked")})</span></span>
                : <span className="hint-text">{t("teams.no_team")}</span>}
            {" · "}
            {agent.role_id ? <strong>{role?.name ?? `#${agent.role_id}`}</strong> : <span className="hint-text">{t("teams.no_role")}</span>}
          </span>
          {isAdmin && (
            <button className="btn btn-sm" onClick={() => {
              setTeamId(agent.team_id ? String(agent.team_id) : "");
              setRoleId(agent.role_id ? String(agent.role_id) : "");
              setEditing(true);
            }}>{t("teams.change")}</button>
          )}
          {agent.role_id ? <span className="hint-text" style={{ fontSize: 12, flexBasis: "100%" }}>{t("teams.agent_rights_from_role")}</span> : null}
        </div>
      ) : (
        <div style={{ display: "grid", gap: 8, maxWidth: 520 }}>
          {teams.length === 0 && (
            <p className="hint-text">{t("teams.create_teams_hint")} <Link href="/teams">{t("teams.title")}</Link></p>
          )}
          <div className="form-row">
            <select aria-label={t("teams.team")} value={teamId} onChange={(e) => { setTeamId(e.target.value); setRoleId(""); }}>
              <option value="">{t("teams.no_team")}</option>
              {teams.map((x) => <option key={x.id} value={x.id}>{teamPath(teams, x.id)}</option>)}
            </select>
            <select aria-label={t("teams.role")} value={roleId} onChange={(e) => {
              const picked = roles.find((r) => String(r.id) === e.target.value);
              if (picked?.team_id) setTeamId(String(picked.team_id));
              setRoleId(e.target.value);
            }}>
              <option value="">{t("teams.no_role")}</option>
              {choices.map((r) => (
                <option key={r.id} value={r.id}>{r.name} ({r.team_id === null ? t("teams.org_wide") : teamPath(teams, r.team_id)})</option>
              ))}
            </select>
          </div>
          {roleId && <p className="hint-text" style={{ fontSize: 12 }}>{t("teams.assign_role_hint")}</p>}
          {!roleId && agent.role_id ? <p className="hint-text" style={{ fontSize: 12 }}>{t("teams.unassign_role_hint")}</p> : null}
          {error && <p className="error-text">{error}</p>}
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn btn-sm btn-primary" disabled={busy} onClick={save}>{t("teams.save")}</button>
            <button className="btn btn-sm" onClick={() => setEditing(false)}>{t("teams.cancel")}</button>
          </div>
        </div>
      )}
    </div>
  );
}
