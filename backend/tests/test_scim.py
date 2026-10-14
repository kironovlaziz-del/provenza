# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
SCIM 2.0 provisioning (app/api/scim.py) and offboarding
(app/services/offboarding.py): the identity provider creates and switches
off users; a user switched off takes their agents' keys with them.
"""

import secrets

import pytest
from sqlalchemy import select, update

from app.models.agent import Agent
from app.models.audit_log import AIAuditLog
from app.models.enrollment import AgentEnrollment
from app.models.user import User
from tests.conftest import _create_org_with_admin_and_approver, _login, auth_headers

S = "/api/v1/scim/v2"
ADMIN = "/api/v1/scim"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"


async def _token(client, admin_token):
    r = await client.post(f"{ADMIN}/token", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _h(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/scim+json"}


async def _create(client, token, email, **extra):
    r = await client.post(f"{S}/Users", json={"schemas": [USER_SCHEMA], "userName": email,
                                              "name": {"givenName": "Ann", "familyName": "Lee"},
                                              "emails": [{"value": email, "primary": True}], "active": True, **extra},
                          headers=_h(token))
    assert r.status_code == 201, r.text
    assert r.headers["content-type"].startswith("application/scim+json")
    return r.json()


async def _owned_agent(client, admin_token, db_session, owner_id):
    r = await client.post("/api/v1/agents/register", json={
        "name": "own-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": [], "allowed_tools": [],
        "allowed_models": [], "max_delegation_depth": 1}, headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    await db_session.execute(update(Agent).where(Agent.id == r.json()["id"]).values(owner_user_id=owner_id))
    await db_session.commit()
    return r.json()


async def _agent_works(client, agent):
    r = await client.get("/api/v1/agent-identity/me", headers={"X-Agent-Key": agent["api_key"]})
    return r.status_code == 200


@pytest.mark.asyncio
async def test_settings_are_admin_only_and_the_token_is_shown_once(client, admin_token, approver_token):
    assert (await client.post(f"{ADMIN}/token", headers=auth_headers(approver_token))).status_code == 403
    token = await _token(client, admin_token)
    assert token.startswith("pvz_scim_")
    st = (await client.get(f"{ADMIN}/settings", headers=auth_headers(admin_token))).json()
    assert st["enabled"] and st["token_prefix"] == token[:14] and "token" not in st
    assert st["base_url"].endswith("/api/v1/scim/v2")
    r = await client.put(f"{ADMIN}/settings", json={"default_role": "admin"}, headers=auth_headers(admin_token))
    assert r.status_code == 422                    # the IdP never makes admins
    # a new token replaces the old one
    newer = await _token(client, admin_token)
    assert (await client.get(f"{S}/ServiceProviderConfig", headers=_h(token))).status_code == 401
    assert (await client.get(f"{S}/ServiceProviderConfig", headers=_h(newer))).json()["patch"]["supported"]


@pytest.mark.asyncio
async def test_without_a_valid_token_nothing(client, admin_token):
    for hdr in ({}, _h("pvz_scim_nope"), _h("Bearer-less")):
        r = await client.get(f"{S}/Users", headers=hdr)
        assert r.status_code == 401 and r.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    token = await _token(client, admin_token)
    await client.delete(f"{ADMIN}/token", headers=auth_headers(admin_token))
    assert (await client.get(f"{S}/Users", headers=_h(token))).status_code == 401


@pytest.mark.asyncio
async def test_okta_style_lifecycle_offboards_the_agents(client, admin_token, db_session):
    token = await _token(client, admin_token)
    u = await _create(client, token, "ann.lee@acme.example")
    assert u["active"] and u["displayName"] == "Ann Lee" and u["userName"] == "ann.lee@acme.example"
    row = await db_session.get(User, int(u["id"]))
    assert row.role == "user" and row.scim_managed

    found = (await client.get(f"{S}/Users", params={"filter": 'userName eq "ANN.LEE@acme.example"'},
                              headers=_h(token))).json()
    assert found["totalResults"] == 1 and found["Resources"][0]["id"] == u["id"]
    assert (await client.get(f"{S}/Users", params={"filter": 'title co "x"'}, headers=_h(token))).status_code == 400

    agent = await _owned_agent(client, admin_token, db_session, int(u["id"]))
    db_session.add(AgentEnrollment(org_id=row.org_id, created_by=row.id, token_hash=secrets.token_hex(32),
                                   token_prefix="pvz_enr_x", expires_at=row.created_at.replace(year=2099)))
    await db_session.commit()
    assert await _agent_works(client, agent)

    # Okta: PATCH replace active false
    r = await client.patch(f"{S}/Users/{u['id']}", json={"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                                                          "Operations": [{"op": "replace", "value": {"active": False}}]},
                           headers=_h(token))
    assert r.status_code == 200 and r.json()["active"] is False
    assert not await _agent_works(client, agent)                       # its key no longer authenticates
    a = await db_session.get(Agent, agent["id"])
    await db_session.refresh(a)
    assert a.status == "suspended" and a.api_key_revoked_at is not None
    await db_session.refresh(row)
    assert row.status == "disabled" and row.sessions_valid_after is not None
    e = (await db_session.execute(select(AgentEnrollment).where(AgentEnrollment.created_by == row.id))).scalar_one()
    assert e.revoked_at is not None
    actions = (await db_session.execute(select(AIAuditLog.action).where(
        AIAuditLog.org_id == row.org_id, AIAuditLog.action.in_(["offboarded", "suspended_with_owner"])))).scalars().all()
    assert set(actions) == {"offboarded", "suspended_with_owner"}

    # back on: the user, not the agents
    r = await client.patch(f"{S}/Users/{u['id']}", json={"Operations": [{"op": "replace", "path": "active",
                                                                          "value": "True"}]}, headers=_h(token))
    assert r.json()["active"] is True
    await db_session.refresh(a)
    assert a.status == "suspended"


@pytest.mark.asyncio
async def test_entra_style_patch_and_delete(client, admin_token, db_session):
    token = await _token(client, admin_token)
    u = await _create(client, token, "bo@acme.example", externalId="entra-oid-1")
    r = await client.patch(f"{S}/Users/{u['id']}", json={"Operations": [
        {"op": "Replace", "path": "displayName", "value": "Bo Chen"},
        {"op": "Add", "path": "title", "value": "Engineer"},              # not kept, not an error
        {"op": "Replace", "path": "active", "value": "False"}]}, headers=_h(token))
    assert r.status_code == 200 and r.json()["displayName"] == "Bo Chen" and r.json()["active"] is False
    found = (await client.get(f"{S}/Users", params={"filter": 'externalId eq "entra-oid-1"'}, headers=_h(token))).json()
    assert found["totalResults"] == 1
    assert (await client.delete(f"{S}/Users/{u['id']}", headers=_h(token))).status_code == 204
    row = await db_session.get(User, int(u["id"]))
    await db_session.refresh(row)
    assert row.status == "disabled" and row.scim_external_id is None


@pytest.mark.asyncio
async def test_adoption_uniqueness_and_the_last_admin(client, admin_token, db_session):
    token = await _token(client, admin_token)
    admin = (await db_session.execute(select(User).where(User.role == "admin"))).scalars().first()
    # the admin's own account is adopted, not duplicated
    adopted = await _create(client, token, admin.email.upper())
    assert adopted["id"] == str(admin.id)
    # the organization's last active admin cannot be switched off from the IdP
    r = await client.patch(f"{S}/Users/{admin.id}", json={"Operations": [{"op": "replace", "path": "active",
                                                                           "value": False}]}, headers=_h(token))
    assert r.status_code == 409 and r.json()["scimType"] == "mutability"
    other = await _create(client, token, "cy@acme.example")
    r = await client.put(f"{S}/Users/{other['id']}", json={"userName": admin.email, "active": True}, headers=_h(token))
    assert r.status_code == 409 and r.json()["scimType"] == "uniqueness"
    assert (await client.get(f"{S}/Users/999999", headers=_h(token))).status_code == 404


@pytest.mark.asyncio
async def test_one_organizations_token_sees_only_its_users(client, admin_token, db_session):
    token = await _token(client, admin_token)
    await _create(client, token, "mine@acme.example")
    await _create_org_with_admin_and_approver(db_session, org_slug="scim-other", admin_email="a@other.example",
                                              approver_email="b@other.example")
    await db_session.commit()
    other_admin = await _login(client, "scim-other", "a@other.example", "TestPass123!")
    other_token = await _token(client, other_admin)
    listed = (await client.get(f"{S}/Users", headers=_h(other_token))).json()
    assert [u for u in listed["Resources"] if u["userName"] == "mine@acme.example"] == []
    mine_id = (await client.get(f"{S}/Users", params={"filter": 'userName eq "mine@acme.example"'},
                                headers=_h(token))).json()["Resources"][0]["id"]
    assert (await client.get(f"{S}/Users/{mine_id}", headers=_h(other_token))).status_code == 404


@pytest.mark.asyncio
async def test_an_admin_disabling_a_user_offboards_their_agents_too(client, admin_token, approver_token, db_session):
    approver = (await db_session.execute(select(User).where(User.role == "approver"))).scalars().first()
    agent = await _owned_agent(client, admin_token, db_session, approver.id)
    assert await _agent_works(client, agent)
    r = await client.put(f"/api/v1/users/{approver.id}/status", json={"status": "disabled"},
                         headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["status"] == "disabled"
    assert not await _agent_works(client, agent)
    assert (await client.get("/api/v1/agent-identity/", headers=auth_headers(approver_token))).status_code == 401
