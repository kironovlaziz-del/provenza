# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
PII rules: built-in types switched off or set to block, custom patterns
(checked against slow regular expressions), the sample tester, and the
rules applied by the gateway and user requests.
"""

import pytest
import regex
from sqlalchemy import select

from app.core import pii_patterns as pp
from app.models.audit_log import AIAuditLog
from app.models.pii import PiiRule
from app.services import prompt_firewall as pf
from tests.conftest import auth_headers
from tests.test_kill_switch import fake  # noqa: F401 - fixture
from tests.test_gateway import _chat, _cleanup_route, _setup, msgs

pytestmark = pytest.mark.asyncio

P = "/api/v1/pii"
PINFL = r"\b[3-6]\d{13}\b"


def _code(r):
    d = r.json().get("detail")
    return d["code"] if isinstance(d, dict) else d


async def _rule(client, token, **kw):
    body = {"name": "PINFL", "label": "PINFL", "pattern": PINFL, "action": "mask", **kw}
    return await client.post(f"{P}/rules", json=body, headers=auth_headers(token))


# ------------------------------------------------------------------ patterns

@pytest.mark.parametrize("pattern,code", [
    (r"(a+)+$", "pii.nested_quantifier"),
    (r"(\w+\s?)*$", "pii.nested_quantifier"),
    (r"(.*a){20}", "pii.nested_quantifier"),
    (r"(a|aa)+$", "pii.alternation_in_repeat"),
    (r"(.)\1", "pii.backreference"),
    (r"\d*", "pii.matches_empty"),
    (r"x{1,5000}", "pii.repeat_too_large"),
    (r"(", "pii.pattern_invalid"),
    ("a" * 600, "pii.pattern_too_long"),
    (r"(?:(?:a{1000}){1000}){1000}b", "pii.repeat_too_large"),   # compiling it would exhaust memory
    (r"(?:[a-z]{1,30}){1,30}@", "pii.nested_quantifier"),
    (r"(a?){30}a{30}", "pii.nested_quantifier"),
    (r"(?:\w+\s\w+@){e<=3}", "pii.braces"),                     # fuzzy matching in the run-time engine
    (r".*.*.*!", "pii.broad_repeat"),
    (r"\D*?password", "pii.broad_repeat"),                       # prose is one long run of \D
    (r"[a-z ]*\d", "pii.broad_repeat"),
])
async def test_dangerous_patterns_are_refused(pattern, code):
    with pytest.raises(pp.PiiPatternError) as e:
        pp.validate(pattern)
    assert e.value.code == code


async def test_useful_patterns_pass():
    for p in (PINFL, r"\b\d{9}\b", r"\bДОГ-\d{4}/\d{2,6}\b", r"\+998[\s-]?\d{2}[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}",
              r"\b(?:\d{3}-){2}\d{4}\b"):
        pp.validate(p)


async def test_a_slow_rule_refuses_the_prompt_instead_of_letting_it_through():
    cfg = pf.PiiConfig(actions={}, custom=[pf.CustomRule(7, "SLOW", regex.compile(r"(a|aa)+$"), "mask")])
    r = pf.scan("a" * 40 + "!", pii=cfg)
    assert r.blocked and r.timed_out == [7] and "pii_timeout:slow" in r.flags


async def test_more_values_than_the_cap_mask_the_whole_text():
    cfg = pf.PiiConfig(actions={}, custom=[pf.CustomRule(3, "DIGIT", pp.compile_rule(r"\d", False), "mask")])
    r = pf.scan("1" * 50000, pii=cfg)
    assert r.masked_text == "[MASKED:DIGIT]" and not r.blocked and not r.timed_out


async def test_unchecked_text_is_withheld_from_masked_views():
    cfg = pf.PiiConfig(actions={}, custom=[pf.CustomRule(7, "SLOW", regex.compile(r"(a|aa)+$"), "mask")])
    shown = pf.scan("a" * 40 + "!", pii=cfg, mask_only=True)
    assert shown.masked_text == pf.WITHHELD_TEXT and not shown.blocked


async def test_the_request_budget_counts_only_time_in_the_rules():
    cfg = pf.PiiConfig(actions={}, custom=[pf.CustomRule(1, "PINFL", pp.compile_rule(PINFL, False), "mask")],
                       budget=1.0)
    for _ in range(20):
        assert not pf.scan("ПИНФЛ 31234567890123 " * 50, pii=cfg).timed_out
    assert 0.9 < cfg.budget <= 1.0


async def test_a_mask_rule_only_spares_a_blocked_type_it_fully_covers():
    cfg = pf.PiiConfig(actions={"CREDIT_CARD": "block"},
                       custom=[pf.CustomRule(1, "FOUR", pp.compile_rule(r"\b\d{4}\b", False), "mask")])
    assert pf.scan("card 4111 1111 1111 1111", pii=cfg).blocked


async def test_custom_rule_wins_over_builtin_and_block_refuses():
    cfg = pf.PiiConfig(actions={"EMAIL": "block", "CREDIT_CARD": "mask"},
                       custom=[pf.CustomRule(1, "PINFL", pp.compile_rule(PINFL, False), "mask")])
    r = pf.scan("ПИНФЛ 31234567890123, ip 10.1.2.3", pii=cfg)
    assert r.masked_text == "ПИНФЛ [MASKED:PINFL], ip 10.1.2.3"  # IP_ADDRESS is off
    r = pf.scan("write to john@example.com", pii=cfg)
    assert r.blocked and r.flags == ["blocked_pii:email"] and "john" not in (r.blocked_reason or "")
    assert pf.scan("write to john@example.com", pii=cfg, mask_only=True).masked_text == "write to [MASKED:EMAIL]"


# ------------------------------------------------------------------ API

async def test_builtin_settings(client, admin_token, approver_token):
    ov = (await client.get(P, headers=auth_headers(approver_token))).json()
    assert {b["type"]: (b["enabled"], b["action"]) for b in ov["builtin"]}["EMAIL"] == (True, "mask")
    assert ov["revision"] == 0

    body = {"types": {"EMAIL": {"action": "block"}, "IP_ADDRESS": {"enabled": False}}, "revision": 0}
    assert (await client.put(f"{P}/builtin", json=body, headers=auth_headers(approver_token))).status_code == 403
    r = await client.put(f"{P}/builtin", json=body, headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    state = {b["type"]: (b["enabled"], b["action"]) for b in r.json()["builtin"]}
    assert state["EMAIL"] == (True, "block") and state["IP_ADDRESS"][0] is False and r.json()["revision"] == 1

    r = await client.put(f"{P}/builtin", json=body, headers=auth_headers(admin_token))  # revision 0 is stale now
    assert r.status_code == 409 and _code(r) == "pii.stale"
    r = await client.put(f"{P}/builtin", json={"types": {"NOPE": {"enabled": False}}}, headers=auth_headers(admin_token))
    assert r.status_code == 422 and _code(r) == "pii.unknown_type"

    t = (await client.post(f"{P}/test", json={"sample": "mail a@b.co from 10.0.0.1"},
                           headers=auth_headers(approver_token))).json()
    assert t["firewall"]["blocked"] and t["firewall"]["flags"] == ["blocked_pii:email"]


async def test_custom_rule_lifecycle(client, admin_token, db_session):
    h = auth_headers(admin_token)
    r = await _rule(client, admin_token, pattern=r"(a+)+$")
    assert r.status_code == 422 and _code(r) == "pii.nested_quantifier"
    r = await _rule(client, admin_token, label="EMAIL")
    assert r.status_code == 422 and _code(r) == "pii.label_builtin"
    r = await _rule(client, admin_token, label="pinfl")
    assert r.status_code == 201, r.text
    rule = r.json()
    assert rule["label"] == "PINFL" and rule["revision"] == 1
    r = await _rule(client, admin_token)
    assert r.status_code == 409 and _code(r) == "pii.label_taken"

    # the tester: a draft replacing the saved rule
    t = (await client.post(f"{P}/test", headers=h, json={
        "sample": "ПИНФЛ 31234567890123", "rule_id": rule["id"],
        "rule": {"label": "PINFL", "pattern": PINFL, "action": "block"}})).json()
    assert t["rule"]["ok"] and t["rule"]["matches"][0]["text"] == "31234567890123"
    assert t["firewall"]["blocked"] and t["firewall"]["flags"] == ["blocked_pii:pinfl"]
    t = (await client.post(f"{P}/test", headers=h, json={"sample": "x", "rule": {"pattern": "(a|aa)+"}})).json()
    assert not t["rule"]["ok"] and t["rule"]["error"] == "pii.alternation_in_repeat"

    r = await client.patch(f"{P}/rules/{rule['id']}", headers=h, json={"action": "block", "revision": 1})
    assert r.status_code == 200 and r.json()["action"] == "block" and r.json()["revision"] == 2
    r = await client.patch(f"{P}/rules/{rule['id']}", headers=h, json={"enabled": False, "revision": 1})
    assert r.status_code == 409 and _code(r) == "pii.stale"
    r = await client.patch(f"{P}/rules/{rule['id']}", headers=h, json={"enabled": None})
    assert r.status_code == 422 and _code(r) == "pii.value_required"

    assert (await client.delete(f"{P}/rules/{rule['id']}", headers=h)).status_code == 200
    assert (await client.get(P, headers=h)).json()["rules"] == []
    kept = (await db_session.execute(select(PiiRule).where(PiiRule.id == rule["id"]))).scalar_one()
    assert kept.deleted_at is not None  # never hard-deleted
    assert (await _rule(client, admin_token)).status_code == 201  # the label is free again

    actions = [a for (a,) in (await db_session.execute(
        select(AIAuditLog.action).where(AIAuditLog.entity_type == "pii_rule", AIAuditLog.entity_id == rule["id"])
        .order_by(AIAuditLog.seq)))]
    assert actions == ["created", "updated", "deleted"]


async def test_rules_apply_to_gateway_and_requests(client, admin_token, db_session, fake):  # noqa: F811
    h = auth_headers(admin_token)
    assert (await _rule(client, admin_token)).status_code == 201
    a, pid, rid = await _setup(client, admin_token, db_session)
    try:
        r = await _chat(client, a, msgs(("user", "ПИНФЛ 31234567890123")))
        assert r.status_code == 200, r.text
        assert "31234567890123" not in fake.calls[-1]["messages"][0]["content"]
        assert "[MASKED:PINFL]" in fake.calls[-1]["messages"][0]["content"]

        await client.put(f"{P}/builtin", json={"types": {"EMAIL": {"action": "block"}}}, headers=h)
        r = await _chat(client, a, msgs(("user", "send to john@example.com")))
        assert r.status_code == 403 and r.json()["error"]["code"] == "blocked_by_firewall"
    finally:
        await _cleanup_route(client, admin_token, rid)

    uc = (await client.post("/api/v1/use-cases/", json={"name": "UC", "risk_level": "low"}, headers=h)).json()["id"]
    r = await client.post("/api/v1/requests/", headers=h, json={
        "use_case_id": uc, "provider_id": pid, "input_text": "ПИНФЛ 31234567890123", "purpose": "test"})
    assert r.status_code == 200, r.text
    assert "[MASKED:PINFL]" in r.json()["masked_input_text"]
