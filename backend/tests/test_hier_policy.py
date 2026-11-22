# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Hierarchical policies: organization -> team -> agent, lower levels can only
tighten, applied in the gateway and to agent actions.
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
    g = policy_doc.from_yaml("limits: {max_tokens: 4000}\nmodels: {allow: ['gpt-*']}")
    t = policy_doc.validate({"limits": {"max_tokens": 9000}, "models": {"allow": ["gpt-4o-mini", "llama-3"]}})
    r = policy_doc.resolve([("organization", g), ("team ml", t)])
    e = policy_doc.Effective(r)
    assert e.limit("limits.max_tokens") == 4000 and e.source("limits.max_tokens") == "organization"
    assert e.refusing("models.allow", "gpt-4o-mini") is None
    assert e.refusing("models.allow", "gpt-4o") == "team ml"
    assert e.refusing("models.allow", "llama-3") == "organization"
    ignored = {(i["field"], i["value"]) for i in r["ignored"]}
    assert {("limits.max_tokens", 9000), ("models.allow", "llama-3")} <= ignored


def test_removed_sections_are_unknown():
    """content (output scanning, blocked terms) and requests (the removed
    user request pipeline) are no longer part of a policy."""
    for text in ("content: {scan_output: true}", "requests: {require_approval: true}"):
        with pytest.raises(policy_doc.PolicyDocError) as e:
            policy_doc.from_yaml(text)
        assert e.value.code == "policy.unknown_key"


async def test_write_read_and_concurrent_edits(client, admin_token, approver_token, db_session):
    r = await put(client, admin_token, "org", "content:\n  scan_output: true\n", revision=0)
    assert r.status_code == 422 and _code(r) == "policy.unknown_key"
    yaml_text = "# company-wide\nlimits:\n  max_tokens: 2000\n"
    r = await put(client, admin_token, "org", yaml_text, revision=0)
    assert r.status_code == 200, r.text
    assert r.json()["revision"] == 1 and r.json()["document"] == {"limits": {"max_tokens": 2000}}
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

    # organization: a smaller token cap, the provider type allowed
    await put(client, admin_token, "org", "limits: {max_tokens: 100}\nproviders: {allow: [openai]}")
    r = await _chat(client, a, msgs(("user", "hello")), max_tokens=5000)
    assert r.status_code == 200, r.text
    assert fake.calls[-1]["params"]["max_tokens"] == 100

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
    # a removed section is refused in the preview too
    r = await client.post(f"{L}/preview", headers=auth_headers(admin_token),
                          json={"scope": "agent", "target_id": agent["id"], "yaml": "requests: {require_approval: true}"})
    assert r.json()["ok"] is False and r.json()["error"]["code"] == "policy.unknown_key"
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


# ----------------------------------------------------------------------------- argument rules (tools.arguments)

ARGS = """
tools:
  arguments:
    - {tool: "payments.*", arg: amount, op: max, value: 100, effect: require_approval}
    - {tool: email.send, arg: to, op: domain_in, value: [provenza.dev]}
"""


def test_argument_rules_in_a_level():
    doc = policy_doc.from_yaml(ARGS + "    - {tool: email.send, arg: to, op: domain_in, value: [provenza.dev]}\n")
    rules = doc["tools"]["arguments"]
    assert len(rules) == 2                                                # the same rule twice: once
    assert rules[1] == {"tool": "email.send", "arg": "to", "op": "domain_in", "value": ["provenza.dev"],
                        "effect": "deny"}                                 # the effect written out
    assert policy_doc.from_yaml(policy_doc.to_yaml(doc)) == doc
    for text, code, path in (
        ("tools: {arguments: [{tool: x, arg: y, op: max, value: 1, efect: deny}]}", "policy.unknown_key",
         "tools.arguments[0].efect"),
        ("tools: {arguments: [{tool: x, arg: y, op: max, value: 1}, {tool: x, arg: y, op: nope, value: 1}]}",
         "policy.bad_argument_rule", "tools.arguments[1]"),
        ("tools: {arguments: [{tool: x, arg: y, op: matches, value: '(a+)+'}]}", "policy.bad_argument_rule",
         "tools.arguments[0]"),
        ("tools: {arguments: [{tool: x, arg: y, op: max, value: 1, effect: allow}]}", "policy.bad_argument_rule",
         "tools.arguments[0]"),
        ("tools: {arguments: {tool: x}}", "policy.expected_list", "tools.arguments"),
    ):
        with pytest.raises(policy_doc.PolicyDocError) as err:
            policy_doc.from_yaml(text)
        assert (err.value.code, err.value.path) == (code, path), text
    # every level's rules apply, each with the level it comes from
    team = policy_doc.from_yaml("tools: {arguments: [{tool: kb.search, arg: q, op: max_length, value: 200}]}")
    eff = policy_doc.Effective(policy_doc.resolve([("organization", doc), ("team ml", team)]))
    assert [(i["value"]["tool"], i["source"]) for i in eff.fields["tools.arguments"]["items"]] == \
        [("payments.*", "organization"), ("email.send", "organization"), ("kb.search", "team ml")]


async def test_agent_actions_follow_argument_rules_of_every_level(client, admin_token):
    from tests.test_behavior_monitor import containment
    await containment(client, admin_token, containment_enabled=False)    # refused on purpose, again and again
    agent = await enroll(client, admin_token, "arg-bot", capabilities=["read"],
                         allowed_tools=["payments.refund", "email.send", "kb.search"])
    t = await team_with(client, admin_token, agent["id"], name="arg-team")
    assert (await put(client, admin_token, "org", ARGS)).status_code == 200
    r = await put(client, admin_token, "team", "tools: {arguments: [{tool: kb.search, arg: q, op: max_length, "
                                                "value: 10}]}", target_id=t["id"])
    assert r.status_code == 200, r.text

    async def check(tool, inp):
        r = await client.post(f"{A}/actions/check", headers={"X-Agent-Key": agent["api_key"]},
                              json={"agent_id": agent["id"], "tool_name": tool, "input": inp})
        assert r.status_code == 200, r.text
        return r.json()

    assert (await check("payments.refund", {"amount": 40}))["decision"] == "allowed"
    d = await check("payments.refund", {"amount": 240})
    assert d["decision"] == "pending_approval" and "organization policy" in d["reason"] and "amount" in d["reason"]
    d = await check("payments.refund", {"amount": "40; also 900"})        # not a number: fails closed
    assert d["decision"] == "pending_approval"
    assert (await check("email.send", {"to": "ann@provenza.dev"}))["decision"] == "allowed"
    d = await check("email.send", {"to": ["ann@provenza.dev", "eve@evil.example"]})   # every one of them
    assert d["decision"] == "denied" and "organization policy" in d["reason"]
    d = await check("email.send", {"subject": "no recipient"})            # a missing argument violates
    assert d["decision"] == "denied" and "missing" in d["reason"]
    d = await check("kb.search", {"q": "a question longer than ten"})
    assert d["decision"] == "denied" and "team arg-team policy" in d["reason"]

    # an agent level adds its own; it cannot take one away from above
    await put(client, admin_token, "agent", "tools: {arguments: [{tool: payments.refund, arg: currency, op: in, "
                                            "value: [EUR]}]}", target_id=agent["id"])
    d = await check("payments.refund", {"amount": 40, "currency": "USD"})
    assert d["decision"] == "denied" and "agent arg-bot policy" in d["reason"]
    assert (await check("payments.refund", {"amount": 40, "currency": "EUR"}))["decision"] == "allowed"

    eff = (await client.get(f"{L}/effective?agent_id={agent['id']}", headers=auth_headers(admin_token))).json()
    items = eff["effective"]["fields"]["tools.arguments"]["items"]
    assert [i["source"] for i in items] == ["organization", "organization", "team arg-team", "agent arg-bot"]

    # a bad rule is named in the preview, with where it is
    r = await client.post(f"{L}/preview", headers=auth_headers(admin_token), json={
        "scope": "org", "target_id": None, "yaml": "tools: {arguments: [{tool: x, arg: y, op: maximum, value: 1}]}"})
    assert r.json()["ok"] is False
    assert r.json()["error"]["code"] == "policy.bad_argument_rule" and r.json()["error"]["path"] == "tools.arguments[0]"
    assert "unknown op" in r.json()["error"]["detail"]


async def test_argument_rules_of_the_hierarchy_count_for_compliance(client, admin_token, db_session):
    from app.services import compliance_engine

    org_id = (await client.get("/api/v1/users/me", headers=auth_headers(admin_token))).json()["org_id"]
    before = (await compliance_engine.collect_facts(db_session, org_id))["argument_rules"]
    assert (await put(client, admin_token, "org", ARGS)).status_code == 200
    assert (await compliance_engine.collect_facts(db_session, org_id))["argument_rules"] == before + 2
