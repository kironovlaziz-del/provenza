"""
Rule packs (app/services/rule_packs.py, api/policy_packs.py): a profile
replaces a level and its undo puts the level back; a guard only adds
restrictions and its undo takes out exactly what it added. Both write the
level as the editor does (revision, audit log).
"""

import pytest
from sqlalchemy import select

from app.models.audit_log import AIAuditLog
from app.models.team import Team
from app.services import rule_packs
from app.services.rule_packs_builtin import BUILTIN
from tests.conftest import auth_headers

P = "/api/v1/policy-packs"


def _code(r):
    d = r.json().get("detail")
    return d["code"] if isinstance(d, dict) else d
L = "/api/v1/policy-layers"


async def _layer(client, token, scope="org", target_id=None):
    q = f"?scope={scope}" + (f"&target_id={target_id}" if target_id else "")
    r = await client.get(L + q, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _put(client, token, yaml, scope="org", target_id=None):
    cur = await _layer(client, token, scope, target_id)
    r = await client.put(L, json={"scope": scope, "target_id": target_id, "yaml": yaml, "revision": cur["revision"]},
                         headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _apply(client, token, pack, scope="org", target_id=None, revision=None):
    r = await client.post(f"{P}/apply", json={"pack": pack, "scope": scope, "target_id": target_id,
                                              "revision": revision}, headers=auth_headers(token))
    return r


def test_the_built_in_packs():
    assert len(BUILTIN) == 18
    kinds = [p["kind"] for p in BUILTIN]
    assert kinds.count("profile") == 8 and kinds.count("guard") == 10
    for p in BUILTIN:
        doc = rule_packs.validate(p["kind"], p["yaml"])
        if p["kind"] == "guard":
            assert "allow" not in doc.get("tools", {}), p["slug"]       # a guard never allows a tool


@pytest.mark.asyncio
async def test_packs_are_listed_and_only_admins_change_them(client, admin_token, approver_token):
    r = await client.get(P, headers=auth_headers(approver_token))
    assert r.status_code == 200 and len(r.json()["builtin"]) == 18 and r.json()["own"] == []
    body = {"name": "No exports", "kind": "guard", "yaml": "tools:\n  deny: ['*.export*']\n"}
    assert (await client.post(P, json=body, headers=auth_headers(approver_token))).status_code == 403
    r = await client.post(P, json=body, headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    own = r.json()
    assert own["ref"] == f"own:{own['id']}" and own["document"] == {"tools": {"deny": ["*.export*"]}}
    assert _code(await client.post(P, json=body, headers=auth_headers(admin_token))) == "pack.name_taken"
    # a guard may not allow tools; a pack must say something; YAML is checked like a level
    for yaml, code in (("tools:\n  allow: ['x']\n", "pack.guard_allows_tools"), ("version: 1\n", "pack.empty"),
                       ("tools:\n  deny: x\n", "policy.expected_list")):
        r = await client.post(P, json={**body, "name": "bad", "yaml": yaml}, headers=auth_headers(admin_token))
        assert r.status_code == 422 and _code(r) == code, r.text
    r = await client.put(f"{P}/{own['id']}", json={**body, "yaml": "tools:\n  deny: ['*.dump*']\n"},
                         headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["document"]["tools"]["deny"] == ["*.dump*"]
    assert (await client.delete(f"{P}/{own['id']}", headers=auth_headers(admin_token))).status_code == 200
    assert (await client.get(P, headers=auth_headers(admin_token))).json()["own"] == []


@pytest.mark.asyncio
async def test_a_guard_adds_and_its_undo_takes_out_only_what_it_added(client, db_session, admin_token):
    await _put(client, admin_token, "limits:\n  requests_per_minute: 50\ntools:\n  deny: ['shell.*']\n"
                                    "  require_approval: ['email.send']\n")
    r = await client.post(f"{P}/preview", json={"pack": "builtin:guard-mass-messaging", "scope": "org"},
                          headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    pv = r.json()
    changed = {c["field"]: c for c in pv["changes"]}
    assert changed["limits.requests_per_minute"] == {"field": "limits.requests_per_minute", "before": 50, "after": 20}
    assert "email.send*" in changed["tools.require_approval"]["added"]
    assert changed["tools.require_approval"]["removed"] == []

    r = await _apply(client, admin_token, "builtin:guard-mass-messaging", revision=pv["revision"])
    assert r.status_code == 200, r.text
    app = r.json()["application"]
    doc = (await _layer(client, admin_token))["document"]
    assert doc["limits"]["requests_per_minute"] == 20
    assert doc["tools"]["deny"][0] == "shell.*" and "*.broadcast*" in doc["tools"]["deny"]
    # what was there before is not counted as the pack's
    assert "email.send" not in app["delta"].get("tools.require_approval", [])
    # the audit log names the pack
    meta = (await db_session.execute(select(AIAuditLog.metadata_json).where(
        AIAuditLog.entity_type == "policy_layer_org").order_by(AIAuditLog.id.desc()).limit(1))).scalar_one()
    assert meta["pack_ref"] == "builtin:guard-mass-messaging" and meta["pack_application"] == app["id"]

    # applying it again adds nothing
    r = await _apply(client, admin_token, "builtin:guard-mass-messaging")
    assert r.status_code == 409 and _code(r) == "pack.nothing_to_add"

    # an admin adds one of the pack's own entries by hand meanwhile? It is the pack's: it goes on undo.
    # One of their own (sms.send) stays.
    cur = await _layer(client, admin_token)
    await _put(client, admin_token, cur["yaml"].replace("- email.send\n", "- email.send\n  - crm.sync\n"))
    r = await client.post(f"{P}/applications/{app['id']}/preview-undo", headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["edited_since"] is True
    r = await client.post(f"{P}/applications/{app['id']}/undo", json={}, headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    doc = (await _layer(client, admin_token))["document"]
    assert doc == {"limits": {"requests_per_minute": 50},
                   "tools": {"deny": ["shell.*"], "require_approval": ["email.send", "crm.sync"]}}
    r = await client.post(f"{P}/applications/{app['id']}/undo", json={}, headers=auth_headers(admin_token))
    assert r.status_code == 409 and _code(r) == "pack.already_undone"
    apps = (await client.get(f"{P}/applications", headers=auth_headers(admin_token))).json()
    assert apps[0]["undone_at"] is not None


@pytest.mark.asyncio
async def test_a_stricter_level_and_an_own_allow_list_are_left_alone(client, admin_token):
    await _put(client, admin_token, "limits:\n  requests_per_minute: 5\nmodels:\n  allow: ['llama-*']\n")
    r = await _apply(client, admin_token, "builtin:guard-mass-messaging")
    assert r.status_code == 200 and r.json()["skipped"] == ["limits.requests_per_minute"]
    r = await _apply(client, admin_token, "builtin:guard-models")
    # the level keeps its own model list; the providers list is new
    assert r.status_code == 200 and r.json()["skipped"] == ["models.allow"], r.text
    doc = (await _layer(client, admin_token))["document"]
    assert doc["models"]["allow"] == ["llama-*"] and doc["providers"]["allow"] == ["openai", "anthropic", "google"]
    assert doc["limits"]["requests_per_minute"] == 5


@pytest.mark.asyncio
async def test_a_profile_replaces_a_level_and_its_undo_puts_it_back(client, db_session, org_and_users, admin_token):
    team = Team(org_id=org_and_users["org"].id, name="Support")
    db_session.add(team)
    await db_session.flush()
    await _put(client, admin_token, "# ours\ntools:\n  allow: ['kb.*']\n", scope="team", target_id=team.id)
    r = await _apply(client, admin_token, "builtin:team-support", scope="team", target_id=team.id)
    assert r.status_code == 200, r.text
    app = r.json()["application"]
    layer = await _layer(client, admin_token, "team", team.id)
    assert layer["document"]["description"] == "Customer support agents"
    assert layer["yaml"].startswith("# Team level - CUSTOMER SUPPORT")          # the pack's text, comments included

    # edited since: the undo says so first
    await _put(client, admin_token, layer["yaml"] + '    - "tickets.escalate"\n', scope="team", target_id=team.id)
    r = await client.post(f"{P}/applications/{app['id']}/undo", json={}, headers=auth_headers(admin_token))
    assert r.status_code == 409 and _code(r) == "pack.edited_since"
    r = await client.post(f"{P}/applications/{app['id']}/undo", json={"confirm_edited": True},
                          headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    assert (await _layer(client, admin_token, "team", team.id))["document"] == {"tools": {"allow": ["kb.*"]}}


@pytest.mark.asyncio
async def test_the_lockdown_profile_allows_nothing_until_undone(client, admin_token):
    r = await _apply(client, admin_token, "builtin:lockdown-allow-nothing")
    assert r.status_code == 200, r.text
    assert (await _layer(client, admin_token))["document"]["tools"] == {"allow": []}
    app = r.json()["application"]
    assert (await client.post(f"{P}/applications/{app['id']}/undo", json={},
                              headers=auth_headers(admin_token))).status_code == 200
    assert (await _layer(client, admin_token))["document"] == {}


@pytest.mark.asyncio
async def test_a_stale_revision_and_another_org_are_refused(client, admin_token, approver_token):
    await _put(client, admin_token, "tools:\n  deny: ['a.*']\n")
    r = await _apply(client, admin_token, "builtin:guard-secrets", revision=0)
    assert r.status_code == 409 and _code(r) == "policy.stale"
    r = await _apply(client, approver_token, "builtin:guard-secrets")
    assert r.status_code == 403
    r = await _apply(client, admin_token, "own:999999")
    assert r.status_code == 404 and _code(r) == "pack.not_found"
    r = await _apply(client, admin_token, "builtin:guard-secrets", scope="team", target_id=999999)
    assert r.status_code == 404


def test_merge_and_undo_are_inverse_on_what_the_guard_added():
    level = {"tools": {"deny": ["x.*"]}, "limits": {"max_tokens": 9000}}
    pack = {"tools": {"deny": ["x.*", "y.*"], "require_approval": ["z.*"]}, "limits": {"max_tokens": 100}}
    new, delta, skipped = rule_packs.merge_guard(level, pack)
    assert new == {"tools": {"deny": ["x.*", "y.*"], "require_approval": ["z.*"]}, "limits": {"max_tokens": 100}}
    assert delta == {"tools.deny": ["y.*"], "tools.require_approval": ["z.*"],
                     "limits.max_tokens": {"before": 9000, "set": 100}} and skipped == []
    assert rule_packs.undo_guard(new, delta) == level
    # a limit changed by hand since stays as it is
    new["limits"]["max_tokens"] = 50
    assert rule_packs.undo_guard(new, delta)["limits"] == {"max_tokens": 50}


def test_a_guard_adds_argument_rules_and_its_undo_takes_them_out():
    mine = {"tool": "kb.search", "arg": "q", "op": "max_length", "value": 200, "effect": "deny"}
    theirs = {"tool": "payments.*", "arg": "amount", "op": "max", "value": 100, "effect": "require_approval"}
    level = {"tools": {"arguments": [mine]}}
    new, delta, _ = rule_packs.merge_guard(level, {"tools": {"arguments": [mine, theirs]}})
    assert new["tools"]["arguments"] == [mine, theirs] and delta == {"tools.arguments": [theirs]}
    assert rule_packs.diff(level, new)[0]["added"] == [theirs]
    assert rule_packs.undo_guard(new, delta) == level
