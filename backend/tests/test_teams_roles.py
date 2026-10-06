# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Teams (org -> team -> sub-team -> agent) and role templates: an agent with a
role has exactly the role's rights and follows its changes; a team's role is
only for that team's agents.
"""

from sqlalchemy import select

from app.core.agent_signing import pq_available
from app.models.agent import Agent
from app.models.audit_log import AIAuditLog
from tests.conftest import auth_headers
from tests.enrollment_helpers import enroll, enroll_with, issue, new_keys

T = "/api/v1/teams"
A = "/api/v1/agents"


def _code(r):
    d = r.json().get("detail")
    return d["code"] if isinstance(d, dict) else d


async def team(client, token, name, **kw):
    r = await client.post(f"{T}/", json={"name": name, **kw}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def role(client, token, name, **kw):
    r = await client.post(f"{T}/roles", json={"name": name, **kw}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def test_team_crud_and_hierarchy(client, admin_token, approver_token):
    h = auth_headers(admin_token)
    eng = await team(client, admin_token, "  Engineering ", description="all of it")
    assert eng["name"] == "Engineering"
    ml = await team(client, admin_token, "ML", parent_id=eng["id"])
    assert ml["parent_id"] == eng["id"]

    r = await client.post(f"{T}/", json={"name": "Engineering"}, headers=h)
    assert r.status_code == 409 and _code(r) == "team.name_taken"
    # a team cannot sit under itself or its own descendant
    r = await client.patch(f"{T}/{eng['id']}", json={"parent_id": ml["id"]}, headers=h)
    assert r.status_code == 422 and _code(r) == "team.parent_cycle"
    r = await client.patch(f"{T}/{eng['id']}", json={"parent_id": eng["id"]}, headers=h)
    assert r.status_code == 422 and _code(r) == "team.parent_cycle"
    r = await client.post(f"{T}/", json={"name": "x", "parent_id": 999999}, headers=h)
    assert r.status_code == 404 and _code(r) == "team.not_found"

    # only admins change teams; everyone reads
    r = await client.post(f"{T}/", json={"name": "nope"}, headers=auth_headers(approver_token))
    assert r.status_code == 403
    listed = (await client.get(f"{T}/", headers=auth_headers(approver_token))).json()
    assert {t["name"] for t in listed} == {"Engineering", "ML"}

    # a team with sub-teams is not deleted
    r = await client.delete(f"{T}/{eng['id']}", headers=h)
    assert r.status_code == 409 and _code(r) == "team.not_empty"
    assert (await client.delete(f"{T}/{ml['id']}", headers=h)).status_code == 200
    assert (await client.delete(f"{T}/{eng['id']}", headers=h)).status_code == 200
    assert (await client.get(f"{T}/", headers=h)).json() == []


async def test_an_agent_enrolled_with_a_role_has_its_rights_and_team(client, db_session, admin_token):
    ops = await team(client, admin_token, "ops")
    r_ = await role(client, admin_token, "runner", team_id=ops["id"], capabilities=["deploy"],
                    allowed_tools=["k8s.apply"], max_delegation_depth=1)
    # rights asked for in the token are ignored: the role decides; the role's team is used
    a = await enroll(client, admin_token, "bot", capabilities=["everything"], allowed_tools=["*"], role_id=r_["id"])
    agent = (await db_session.execute(select(Agent).where(Agent.id == a["id"]))).scalar_one()
    assert agent.role_id == r_["id"] and agent.team_id == ops["id"] and agent.owner_team == "ops"
    assert agent.capabilities == ["deploy"] and agent.allowed_tools == ["k8s.apply"]
    assert agent.max_delegation_depth == 1

    counts = {t["name"]: t for t in (await client.get(f"{T}/", headers=auth_headers(admin_token))).json()}
    assert counts["ops"]["agents"] == 1 and counts["ops"]["roles"] == 1


async def test_a_teams_role_is_only_for_that_team(client, admin_token):
    ops = await team(client, admin_token, "ops")
    sec = await team(client, admin_token, "sec")
    r_ = await role(client, admin_token, "runner", team_id=ops["id"])
    r = await client.post("/api/v1/agent-enrollment/tokens", headers=auth_headers(admin_token),
                          json={"name": "x", "team_id": sec["id"], "role_id": r_["id"]})
    assert r.status_code == 422 and _code(r) == "role.other_team"
    # an org-wide role fits any team
    wide = await role(client, admin_token, "reader", capabilities=["read"])
    tok = await issue(client, admin_token, name="y", team_id=sec["id"], role_id=wide["id"])
    assert tok["team_id"] == sec["id"] and tok["role_id"] == wide["id"]


async def test_changing_a_role_changes_its_agents(client, db_session, admin_token):
    h = auth_headers(admin_token)
    r_ = await role(client, admin_token, "reader", capabilities=["read"], allowed_tools=["kb.search"])
    a1 = await enroll(client, admin_token, "one", role_id=r_["id"])
    a2 = await enroll(client, admin_token, "two", role_id=r_["id"])
    other = await enroll(client, admin_token, "free", capabilities=["read"], allowed_tools=["kb.search"])

    r = await client.patch(f"{T}/roles/{r_['id']}", headers=h,
                           json={"allowed_tools": ["kb.search", "web.fetch"], "max_delegation_depth": 0})
    assert r.status_code == 200, r.text
    assert r.json()["agents_updated"] == 2
    for a in (a1, a2):
        got = (await client.get(f"{A}/{a['id']}", headers=h)).json()
        assert got["allowed_tools"] == ["kb.search", "web.fetch"] and got["max_delegation_depth"] == 0
    got = (await client.get(f"{A}/{other['id']}", headers=h)).json()
    assert got["allowed_tools"] == ["kb.search"]

    # the agent's own rights are not edited while it has a role
    r = await client.put(f"{A}/{a1['id']}", headers=h, json={"capabilities": ["admin"]})
    assert r.status_code == 409 and _code(r) == "agent.rights_from_role"
    # other fields are
    r = await client.put(f"{A}/{a1['id']}", headers=h, json={"description": "reads things"})
    assert r.status_code == 200, r.text

    # null does not wipe a role's name or rights
    r = await client.patch(f"{T}/roles/{r_['id']}", headers=h, json={"name": None, "capabilities": None})
    assert r.status_code == 200 and r.json()["name"] == "reader" and r.json()["capabilities"] == ["read"]

    entry = (await db_session.execute(select(AIAuditLog).where(
        AIAuditLog.entity_type == "role_template", AIAuditLog.action == "updated"))).scalars().first()
    assert entry is not None and entry.metadata_json["agents_updated"] == 2


async def test_a_role_in_use_is_not_deleted(client, admin_token):
    h = auth_headers(admin_token)
    r_ = await role(client, admin_token, "reader")
    await issue(client, admin_token, name="pending", role_id=r_["id"])
    r = await client.delete(f"{T}/roles/{r_['id']}", headers=h)
    assert r.status_code == 409 and _code(r) == "role.in_use"

    unused = await role(client, admin_token, "spare")
    assert (await client.delete(f"{T}/roles/{unused['id']}", headers=h)).status_code == 200


async def test_closed_tokens_do_not_block_deleting(client, admin_token):
    h = auth_headers(admin_token)
    t = await team(client, admin_token, "temp")
    r_ = await role(client, admin_token, "temp-role", team_id=t["id"])
    tok = await issue(client, admin_token, name="x", role_id=r_["id"])
    assert (await client.post(f"/api/v1/agent-enrollment/tokens/{tok['id']}/revoke", headers=h)).status_code == 200
    assert (await client.delete(f"{T}/roles/{r_['id']}", headers=h)).status_code == 200, "revoked token blocked it"
    assert (await client.delete(f"{T}/{t['id']}", headers=h)).status_code == 200


async def test_moving_a_role_must_not_strand_agents(client, admin_token):
    h = auth_headers(admin_token)
    ops = await team(client, admin_token, "ops")
    sec = await team(client, admin_token, "sec")
    wide = await role(client, admin_token, "reader")
    await enroll(client, admin_token, "a", team_id=ops["id"], role_id=wide["id"])
    r = await client.patch(f"{T}/roles/{wide['id']}", headers=h, json={"team_id": sec["id"]})
    assert r.status_code == 409 and _code(r) == "role.agents_in_other_teams"
    r = await client.patch(f"{T}/roles/{wide['id']}", headers=h, json={"team_id": ops["id"]})
    assert r.status_code == 200 and r.json()["team_id"] == ops["id"]


async def test_assignment(client, db_session, admin_token, approver_token):
    h = auth_headers(admin_token)
    ops = await team(client, admin_token, "ops")
    sec = await team(client, admin_token, "sec")
    r_ = await role(client, admin_token, "runner", team_id=ops["id"], capabilities=["deploy"])
    a = await enroll(client, admin_token, "bot", capabilities=["read"])

    r = await client.put(f"{A}/{a['id']}/assignment", headers=auth_headers(approver_token),
                         json={"team_id": ops["id"], "role_id": None})
    assert r.status_code == 403
    r = await client.put(f"{A}/{a['id']}/assignment", headers=h, json={"team_id": sec["id"], "role_id": r_["id"]})
    assert r.status_code == 422 and _code(r) == "role.other_team"

    r = await client.put(f"{A}/{a['id']}/assignment", headers=h, json={"team_id": ops["id"], "role_id": r_["id"]})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["team_id"] == ops["id"] and d["role_id"] == r_["id"] and d["owner_team"] == "ops"
    assert d["capabilities"] == ["deploy"]

    # the owner_team text follows the team; it is not edited directly
    r = await client.put(f"{A}/{a['id']}", headers=h, json={"owner_team": "elsewhere"})
    assert r.status_code == 409 and _code(r) == "agent.team_assigned"
    assert (await client.patch(f"{T}/{ops['id']}", headers=h, json={"name": "platform"})).status_code == 200
    assert (await client.get(f"{A}/{a['id']}", headers=h)).json()["owner_team"] == "platform"

    # a team with agents is not deleted
    r = await client.delete(f"{T}/{ops['id']}", headers=h)
    assert r.status_code == 409 and _code(r) == "team.not_empty"

    # off the role: the rights stay, and are the agent's own again
    r = await client.put(f"{A}/{a['id']}/assignment", headers=h, json={"team_id": ops["id"], "role_id": None})
    assert r.status_code == 200 and r.json()["role_id"] is None and r.json()["capabilities"] == ["deploy"]
    r = await client.put(f"{A}/{a['id']}", headers=h, json={"capabilities": ["read"]})
    assert r.status_code == 200, r.text

    entry = (await db_session.execute(select(AIAuditLog).where(
        AIAuditLog.entity_type == "agent", AIAuditLog.entity_id == a["id"],
        AIAuditLog.action == "assignment_changed"))).scalars().first()
    assert entry is not None


async def test_a_hybrid_role_needs_hybrid_keys(client, admin_token):
    h = auth_headers(admin_token)
    r_ = await role(client, admin_token, "prod", require_hybrid=True)
    tok = await issue(client, admin_token, name="classic", role_id=r_["id"])
    assert tok["require_hybrid"] is True
    r = await enroll_with(client, tok["token"], new_keys(hybrid=False))
    assert r.status_code in (400, 422), r.text

    plain = await enroll(client, admin_token, "plain")
    r = await client.put(f"{A}/{plain['id']}/assignment", headers=h, json={"team_id": None, "role_id": r_["id"]})
    assert r.status_code == 409 and _code(r) == "role.requires_hybrid"

    loose = await role(client, admin_token, "loose")
    r = await client.put(f"{A}/{plain['id']}/assignment", headers=h, json={"team_id": None, "role_id": loose["id"]})
    assert r.status_code == 200, r.text
    r = await client.patch(f"{T}/roles/{loose['id']}", headers=h, json={"require_hybrid": True})
    assert r.status_code == 409 and _code(r) == "role.agents_not_hybrid"

    if pq_available():
        hy = await enroll(client, admin_token, "hy", hybrid=True, role_id=r_["id"])
        assert hy["pq_public_key"]
        # no path back to a classic key while the role requires a hybrid one
        r = await client.post(f"{A}/{hy['id']}/signing-key", headers=h,
                              json={"public_key": new_keys()["public_key"]})
        assert r.status_code == 422 and _code(r) == "role.requires_hybrid", r.text


async def test_free_text_team_without_a_team_still_works(client, db_session, admin_token):
    a = await enroll(client, admin_token, "legacy", owner_team="finance")
    agent = (await db_session.execute(select(Agent).where(Agent.id == a["id"]))).scalar_one()
    assert agent.owner_team == "finance" and agent.team_id is None and agent.role_id is None


async def test_retired_agents_do_not_keep_a_team_or_role(client, db_session, admin_token):
    h = auth_headers(admin_token)
    t = await team(client, admin_token, "sunset")
    r_ = await role(client, admin_token, "sunset-role", team_id=t["id"], capabilities=["read"])
    a = await enroll(client, admin_token, "old-bot", role_id=r_["id"])

    # suspended (killed) can be switched back on: it still holds the team and role
    assert (await client.put(f"{A}/{a['id']}", headers=h, json={"status": "suspended"})).status_code == 200
    r = await client.delete(f"{T}/{t['id']}", headers=h)
    assert r.status_code == 409 and _code(r) == "team.not_empty"
    assert "old-bot" in r.json()["detail"]["context"]["agent_names"]

    # retired does not
    assert (await client.put(f"{A}/{a['id']}", headers=h, json={"status": "retired"})).status_code == 200
    listed = {x["name"]: x for x in (await client.get(f"{T}/", headers=h)).json()}
    assert listed["sunset"]["agents"] == 0
    assert (await client.delete(f"{T}/roles/{r_['id']}", headers=h)).status_code == 200
    assert (await client.delete(f"{T}/{t['id']}", headers=h)).status_code == 200
    agent = (await db_session.execute(select(Agent).where(Agent.id == a["id"]))).scalar_one()
    await db_session.refresh(agent)
    assert agent.team_id is None and agent.role_id is None
    assert agent.owner_team == "sunset" and agent.capabilities == ["read"]  # history and rights kept

    # retired is final: neither a kill nor a status change brings it back
    r = await client.post(f"{A}/{a['id']}/kill", headers=h, json={"reason": "again", "cascade": True})
    assert r.status_code == 409 and _code(r) == "agent.retired_final"
    r = await client.put(f"{A}/{a['id']}", headers=h, json={"status": "active"})
    assert r.status_code == 409 and _code(r) == "agent.retired_final"
    assert (await client.get(f"{A}/{a['id']}", headers=h)).json()["status"] == "retired"
