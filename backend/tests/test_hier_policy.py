# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Hierarchical policies: organization -> team -> agent, lower levels can only
tighten, applied in the gateway, to agent actions and to user requests.
"""

import pytest
from sqlalchemy import select

from app.core import policy_doc
from app.models.audit_log import AIAuditLog
from tests.conftest import auth_headers
from tests.enrollment_helpers import enroll
from tests.test_gateway import FakeProvider, _chat, _setup, msgs  # noqa: F401
from app.services import gateway_adapters

L = "/api/v1/policy-layers"
A = "/api/v1/agents"
T = "/api/v1/teams"


@pytest.fixture
def fake(monkeypatch):
    f = FakeProvider()
    monkeypatch.setattr(gateway_adapters, "chat", f)
    return f


def _code(r):
    d = r.json().get("detail")
    return d["code"] if isinstance(d, dict) else d


async def put(client, token, scope, yaml_text, target_id=None, revision=None):
    body = {"scope": scope, "target_id": target_id, "yaml": yaml_text}
    if revision is not None:
        body["revision"] = revision
    return await client.put(L, json=body, headers=auth_headers(token))


async def team_with(client, token, agent_id, name="ml"):
    t = (await client.post(f"{T}/", json={"name": name}, headers=auth_headers(token))).json()
    r = await client.put(f"{A}/{agent_id}/assignment", json={"team_id": t["id"], "role_id": None},
                         headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return t


def test_levels_only_tighten():
    g = policy_doc.from_yaml("limits: {max_tokens: 4000}\nmodels: {allow: ['gpt-*']}\ncontent: {scan_output: true}")
    t = policy_doc.validate({"limits": {"max_tokens": 9000}, "models": {"allow": ["gpt-4o-mini", "llama-3"]},
                             "content": {"scan_output": False}})
    r = policy_doc.resolve([("organization", g), ("team ml", t)])
    e = policy_doc.Effective(r)
    assert e.limit("limits.max_tokens") == 4000 and e.source("limits.max_tokens") == "organization"
    assert e.switch("content.scan_output")
    assert e.refusing("models.allow", "gpt-4o-mini") is None
    assert e.refusing("models.allow", "gpt-4o") == "team ml"
    assert e.refusing("models.allow", "llama-3") == "organization"
    ignored = {(i["field"], i["value"]) for i in r["ignored"]}
    assert {("limits.max_tokens", 9000), ("content.scan_output", False), ("models.allow", "llama-3")} <= ignored


async def test_write_read_and_concurrent_edits(client, admin_token, approver_token, db_session):
    # blocked terms have their own page now
    r = await put(client, admin_token, "org", "content:\n  blocked_terms: [Project Titan]\n", revision=0)
    assert r.status_code == 422 and _code(r) == "policy.blocked_terms_moved"
    yaml_text = "# company-wide\nlimits:\n  max_tokens: 2000\ncontent:\n  scan_output: true\n"
    r = await put(client, admin_token, "org", yaml_text, revision=0)
    assert r.status_code == 200, r.text
    assert r.json()["revision"] == 1 and r.json()["document"]["content"]["scan_output"] is True
    got = (await client.get(f"{L}?scope=org", headers=auth_headers(admin_token))).json()
    assert got["yaml"] == yaml_text  # what the admin wrote, comments included

    # someone else saved in between
    r = await put(client, admin_token, "org", "limits: {max_tokens: 1000}", revision=0)
    assert r.status_code == 409 and _code(r) == "policy.stale"
    r = await put(client, admin_token, "org", "limits: {max_tokens: 1000}", revision=1)
    assert r.status_code == 200 and r.json()["revision"] == 2

    r = await put(client, admin_token, "org", "limits: {max_token: 5}")
    assert r.status_code == 422 and _code(r) == "policy.unknown_key"
    assert r.json()["detail"]["context"]["path"] == "limits.max_token"
    r = await put(client, admin_token, "org", "a: &x [1]\nb: *x")
    assert r.status_code == 422 and _code(r) == "policy.yaml_alias"
    r = await put(client, approver_token, "org", "limits: {max_tokens: 1}")
    assert r.status_code == 403
    r = await put(client, admin_token, "team", "limits: {max_tokens: 1}")
    assert r.status_code == 422 and _code(r) == "policy.target_required"
    r = await put(client, admin_token, "team", "limits: {max_tokens: 1}", target_id=999999)
    assert r.status_code == 404

    entry = (await db_session.execute(select(AIAuditLog).where(
        AIAuditLog.entity_type == "policy_layer_org").order_by(AIAuditLog.seq.desc()))).scalars().first()
    assert entry.metadata_json["before"]["limits"]["max_tokens"] == 2000
    assert entry.metadata_json["after"]["limits"]["max_tokens"] == 1000


async def test_preview_shows_sources_and_what_has_no_effect(client, admin_token, db_session):
    agent = await enroll(client, admin_token, "prev-bot", capabilities=["read"], allowed_tools=["kb.search"])
    t = await team_with(client, admin_token, agent["id"])
    await put(client, admin_token, "org", "limits: {max_tokens: 2000}\nmodels: {allow: ['gpt-*']}")
    r = await client.post(f"{L}/preview", headers=auth_headers(admin_token), json={
        "scope": "team", "target_id": t["id"],
        "yaml": "limits: {max_tokens: 8000, requests_per_minute: 10}\nmodels: {allow: [llama-3]}"})
    body = r.json()
    assert body["ok"] is True
    f = body["effective"]["fields"]
    assert f["limits.max_tokens"] == {"value": 2000, "source": "organization"}
    assert f["limits.requests_per_minute"] == {"value": 10, "source": "team ml"}
    assert {(i["field"], i["value"]) for i in body["effective"]["ignored"]} >= {("limits.max_tokens", 8000),
                                                                              ("models.allow", "llama-3")}
    assert [lv["source"] for lv in body["levels"]] == ["gateway settings", "organization", "team ml"]
    # nothing was saved
    assert (await client.get(f"{L}?scope=team&target_id={t['id']}", headers=auth_headers(admin_token))).json()[
        "revision"] == 0
    r = await client.post(f"{L}/preview", headers=auth_headers(admin_token),
                          json={"scope": "team", "target_id": t["id"], "yaml": "limits: [1"})
    assert r.json()["ok"] is False and r.json()["error"]["code"] == "policy.yaml_syntax"

    eff = (await client.get(f"{L}/effective?agent_id={agent['id']}", headers=auth_headers(admin_token))).json()
    assert [lv["source"] for lv in eff["levels"]] == ["gateway settings", "organization", "team ml", "agent prev-bot"]


async def test_gateway_follows_the_hierarchy(client, admin_token, db_session, fake):
    a, pid, rid = await _setup(client, admin_token, db_session, models=("gpt-4o-mini",))
    t = await team_with(client, admin_token, a["id"], name="gw-team")

    # a team that only allows claude models: the agent's gpt model is refused, naming the team
    await put(client, admin_token, "team", "models: {allow: ['claude-*']}", target_id=t["id"])
    r = await _chat(client, a, msgs(("user", "hi")))
    assert r.status_code == 403 and "team gw-team" in r.json()["error"]["message"]
    await put(client, admin_token, "team", "", target_id=t["id"])  # cleared

    # organization: a smaller token cap, the provider type allowed; a blocked term (its own page)
    await put(client, admin_token, "org", "limits: {max_tokens: 100}\nproviders: {allow: [openai]}")
    r = await client.post("/api/v1/blocked-terms", json={"term": "titan"}, headers=auth_headers(admin_token))
    assert r.status_code == 201, r.text
    r = await _chat(client, a, msgs(("user", "hello")), max_tokens=5000)
    assert r.status_code == 200, r.text
    assert fake.calls[-1]["params"]["max_tokens"] == 100
    r = await _chat(client, a, msgs(("user", "about TITAN")))
    assert r.status_code == 403 and r.json()["error"]["code"] == "blocked_by_firewall"

    # an agent level cannot raise the cap or allow another provider type
    await put(client, admin_token, "agent", "limits: {max_tokens: 9000}\nproviders: {allow: [anthropic]}",
              target_id=a["id"])
    r = await _chat(client, a, msgs(("user", "hello")))
    assert r.status_code == 403 and r.json()["error"]["code"] == "provider_not_allowed"
    await put(client, admin_token, "agent", "limits: {max_tokens: 9000}", target_id=a["id"])
    r = await _chat(client, a, msgs(("user", "hello")), max_tokens=5000)
    assert r.status_code == 200 and fake.calls[-1]["params"]["max_tokens"] == 100

    # rate limit from a team level
    await put(client, admin_token, "team", "limits: {requests_per_minute: 1}", target_id=t["id"])
    r = await _chat(client, a, msgs(("user", "hello")))
    assert r.status_code == 429


async def test_agent_actions_follow_the_hierarchy(client, admin_token):
    agent = await enroll(client, admin_token, "act-bot", capabilities=["read"],
                         allowed_tools=["kb.search", "kb.delete", "email.send", "web.fetch"])
    t = await team_with(client, admin_token, agent["id"], name="support")
    await put(client, admin_token, "org", "tools: {deny: ['kb.delete']}")
    await put(client, admin_token, "team", "tools: {require_approval: ['email.*']}", target_id=t["id"])
    await put(client, admin_token, "agent", "tools: {allow: ['kb.*', 'email.*']}", target_id=agent["id"])

    async def check(tool):
        r = await client.post(f"{A}/actions/check", headers={"X-Agent-Key": agent["api_key"]},
                              json={"agent_id": agent["id"], "tool_name": tool, "input": {}})
        assert r.status_code == 200, r.text
        return r.json()

    assert (await check("kb.search"))["decision"] == "allowed"
    d = await check("kb.delete")
    assert d["decision"] == "denied" and "organization policy" in d["reason"]
    d = await check("email.send")
    assert d["decision"] == "pending_approval" and "team support policy" in d["reason"]
    d = await check("web.fetch")  # the agent itself holds it, its policy level does not allow it
    assert d["decision"] == "denied" and "agent act-bot policy" in d["reason"]

    await put(client, admin_token, "org", "tools: {deny: ['kb.delete']}\nlimits: {max_delegation_depth: 0}")
    eff = (await client.get(f"{L}/effective?agent_id={agent['id']}", headers=auth_headers(admin_token))).json()
    assert eff["effective"]["fields"]["limits.max_delegation_depth"] == {"value": 0, "source": "organization"}


async def test_user_requests_follow_the_organization_level(client, admin_token):
    provider = (await client.post("/api/v1/providers/", json={"name": "Test", "type": "openai"},
                                  headers=auth_headers(admin_token))).json()["id"]
    uc = (await client.post("/api/v1/use-cases/", json={"name": "UC", "risk_level": "low"},
                            headers=auth_headers(admin_token))).json()["id"]

    async def ask(text):
        return await client.post("/api/v1/requests/", headers=auth_headers(admin_token), json={
            "use_case_id": uc, "provider_id": provider, "input_text": text, "purpose": "test"})

    await put(client, admin_token, "org", "requests: {require_approval: true}")
    r = await client.post("/api/v1/blocked-terms", json={"term": "titan"}, headers=auth_headers(admin_token))
    assert r.status_code == 201, r.text
    r = await ask("about Titan")
    assert r.status_code == 200 and r.json()["status"] == "blocked"
    r = await ask("about the weather")
    assert r.status_code == 200 and r.json()["status"] == "pending_approval"

    await put(client, admin_token, "org", "providers: {allow: [anthropic]}")
    r = await ask("hello")
    assert r.status_code == 403 and _code(r) == "policy.provider_not_allowed"


async def test_overview_lists_levels_with_rules(client, admin_token):
    agent = await enroll(client, admin_token, "ov-bot", capabilities=["read"], allowed_tools=["kb.search"])
    t = await team_with(client, admin_token, agent["id"], name="ov-team")
    await put(client, admin_token, "org", "limits: {max_tokens: 100}")
    await put(client, admin_token, "team", "tools: {deny: [x], require_approval: [y]}", target_id=t["id"])
    await put(client, admin_token, "agent", "limits: {max_tokens: 50}", target_id=agent["id"])
    ov = (await client.get(f"{L}/overview", headers=auth_headers(admin_token))).json()
    assert ov["org"]["rules"] == 1
    assert next(x for x in ov["teams"] if x["id"] == t["id"])["rules"] == 2
    assert ov["agents"] == [{"id": agent["id"], "name": "ov-bot", "rules": 1}]


async def test_rules_that_only_fit_one_place(client, admin_token, approver_token):
    agent = await enroll(client, admin_token, "fit-bot", capabilities=["read"], allowed_tools=["kb.search"])
    t = await team_with(client, admin_token, agent["id"], name="fit")
    # user requests are governed by the organization level only
    r = await put(client, admin_token, "team", "requests: {require_approval: true}", target_id=t["id"])
    assert r.status_code == 422 and _code(r) == "policy.org_only"
    r = await client.post(f"{L}/preview", headers=auth_headers(admin_token),
                          json={"scope": "agent", "target_id": agent["id"], "yaml": "requests: {require_approval: true}"})
    assert r.json()["ok"] is False and r.json()["error"]["code"] == "policy.org_only"
    # deeply nested brackets are refused, not a crash
    r = await put(client, admin_token, "org", "limits: " + "[" * 3000 + "]" * 3000)
    assert r.status_code == 422 and _code(r) == "policy.too_deep"
    # approvers read, they do not write
    assert (await client.get(f"{L}?scope=org", headers=auth_headers(approver_token))).status_code == 200
    assert (await put(client, approver_token, "org", "limits: {max_tokens: 5}")).status_code == 403


async def test_a_team_with_a_policy_level(client, admin_token):
    t = (await client.post(f"{T}/", json={"name": "short-lived"}, headers=auth_headers(admin_token))).json()
    await put(client, admin_token, "team", "tools: {deny: ['shell.*']}", target_id=t["id"])
    r = await client.delete(f"{T}/{t['id']}", headers=auth_headers(admin_token))
    assert r.status_code == 409 and "policy" in r.json()["detail"]["context"]["parts"]
    await put(client, admin_token, "team", "", target_id=t["id"])  # cleared - kept in the audit log
    r = await client.delete(f"{T}/{t['id']}", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
