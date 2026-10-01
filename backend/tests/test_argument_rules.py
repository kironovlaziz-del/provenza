"""
ASI02 - argument-level tool constraints. Unit tests for the pure rule
module plus API tests through the agent policy engine.
"""

import secrets

import pytest

from app.services.argument_rules import RuleError, evaluate_argument_rules, validate_argument_rules
from tests.conftest import auth_headers

READ_ONLY_SQL = {"tool": "db.query", "arg": "sql", "op": "not_matches",
                 "value": r"(?i)\b(drop|delete|truncate|alter|update|insert)\b", "effect": "deny"}
CORP_EMAIL = {"tool": "email.send", "arg": "to", "op": "domain_in", "value": ["corp.example"], "effect": "deny"}
SANDBOX = {"tool": "file.*", "arg": "path", "op": "starts_with", "value": ["/sandbox/"], "effect": "deny"}
PAY_LIMIT = {"tool": "payments.*", "arg": "amount", "op": "max", "value": 100, "effect": "require_approval"}


def verdict(rules, tool, data):
    return evaluate_argument_rules(rules, tool, data)[0]


class TestOperators:
    def test_read_only_sql(self):
        assert verdict([READ_ONLY_SQL], "db.query", {"sql": "select * from users"}) == "ok"
        assert verdict([READ_ONLY_SQL], "db.query", {"sql": "DROP TABLE users"}) == "deny"
        assert verdict([READ_ONLY_SQL], "db.query", {"sql": "select 1; delete from x"}) == "deny"

    def test_email_domain_and_subdomain(self):
        assert verdict([CORP_EMAIL], "email.send", {"to": "a@corp.example"}) == "ok"
        assert verdict([CORP_EMAIL], "email.send", {"to": "a@eu.corp.example"}) == "ok"
        assert verdict([CORP_EMAIL], "email.send", {"to": "Bob <b@CORP.example>"}) == "ok"
        assert verdict([CORP_EMAIL], "email.send", {"to": "a@evil.com"}) == "deny"
        assert verdict([CORP_EMAIL], "email.send", {"to": "a@corp.example.evil.com"}) == "deny"
        assert verdict([CORP_EMAIL], "email.send", {"to": "a@notcorp.example"}) == "deny"

    def test_every_list_element_must_comply(self):
        assert verdict([CORP_EMAIL], "email.send", {"to": ["a@corp.example", "b@corp.example"]}) == "ok"
        assert verdict([CORP_EMAIL], "email.send", {"to": ["a@corp.example", "x@evil.com"]}) == "deny"

    def test_path_traversal_is_normalised(self):
        assert verdict([SANDBOX], "file.delete", {"path": "/sandbox/tmp/a.txt"}) == "ok"
        assert verdict([SANDBOX], "file.delete", {"path": "/sandbox/../etc/passwd"}) == "deny"
        assert verdict([SANDBOX], "file.delete", {"path": "/sandboxevil/x"}) == "deny"
        assert verdict([SANDBOX], "file.write", {"path": "/etc/hosts"}) == "deny"

    def test_numeric_limits_and_approval_effect(self):
        assert verdict([PAY_LIMIT], "payments.charge", {"amount": 50}) == "ok"
        assert verdict([PAY_LIMIT], "payments.charge", {"amount": "99.5"}) == "ok"
        assert verdict([PAY_LIMIT], "payments.charge", {"amount": 5000}) == "approval"
        assert verdict([PAY_LIMIT], "payments.charge", {"amount": "lots"}) == "approval"

    def test_other_ops(self):
        r = lambda op, value: [{"tool": "t", "arg": "x", "op": op, "value": value}]
        assert verdict(r("equals", "a"), "t", {"x": "a"}) == "ok"
        assert verdict(r("in", ["a", "b"]), "t", {"x": "c"}) == "deny"
        assert verdict(r("not_in", ["root"]), "t", {"x": "root"}) == "deny"
        assert verdict(r("min", 1), "t", {"x": 0}) == "deny"
        assert verdict(r("max_length", 3), "t", {"x": "abcd"}) == "deny"
        assert verdict(r("matches", r"^[a-z]+$"), "t", {"x": "abc"}) == "ok"
        assert verdict(r("matches", r"^[a-z]+$"), "t", {"x": "ab1"}) == "deny"

    def test_nested_argument_path(self):
        rule = [{"tool": "email.send", "arg": "options.cc", "op": "domain_in", "value": "corp.example"}]
        assert verdict(rule, "email.send", {"options": {"cc": "a@corp.example"}}) == "ok"
        assert verdict(rule, "email.send", {"options": {"cc": "a@evil.com"}}) == "deny"


class TestFailClosed:
    def test_missing_argument_violates(self):
        v, why = evaluate_argument_rules([CORP_EMAIL], "email.send", {"subject": "hi"})
        assert v == "deny" and "missing" in why

    def test_other_tools_are_not_affected(self):
        assert verdict([CORP_EMAIL], "db.query", {"sql": "x"}) == "ok"

    def test_oversized_regex_subject_violates(self):
        padding = "select 1 " * 2000  # > 10k chars, DROP hidden at the end
        assert verdict([READ_ONLY_SQL], "db.query", {"sql": padding + "drop table x"}) == "deny"

    def test_broken_stored_rule_denies(self):
        broken = [{"tool": "t", "arg": "x", "op": "nonsense", "value": 1}]
        assert verdict(broken, "t", {"x": 1}) == "deny"

    def test_deny_wins_over_approval(self):
        rules = [PAY_LIMIT, {"tool": "payments.*", "arg": "currency", "op": "in", "value": ["USD"]}]
        v, why = evaluate_argument_rules(rules, "payments.charge", {"amount": 5000, "currency": "BTC"})
        assert v == "deny" and "currency" in why


class TestValidation:
    @pytest.mark.parametrize("rule, fragment", [
        ({"tool": "t", "arg": "x", "op": "bogus", "value": 1}, "unknown op"),
        ({"tool": "t", "arg": "x", "op": "matches", "value": "(a+)+$"}, "nested quantifiers"),
        ({"tool": "t", "arg": "x", "op": "matches", "value": "("}, "invalid regular expression"),
        ({"tool": "t", "arg": "x", "op": "matches", "value": "a" * 301}, "longer than"),
        ({"tool": "t", "arg": "x", "op": "max", "value": "ten"}, "needs a number"),
        ({"tool": "t", "arg": "x", "op": "in", "value": []}, "non-empty"),
        ({"tool": "t", "arg": "a..b", "op": "equals", "value": 1}, "dotted path"),
        ({"tool": "", "arg": "x", "op": "equals", "value": 1}, "tool"),
        ({"tool": "t", "arg": "x", "op": "equals", "value": 1, "effect": "maybe"}, "effect"),
        ({"tool": "t", "op": "equals", "value": 1}, "'arg' is required"),
    ])
    def test_invalid_rules_are_rejected(self, rule, fragment):
        with pytest.raises(RuleError) as exc:
            validate_argument_rules([rule])
        assert fragment in str(exc.value)

    def test_valid_rules_pass(self):
        validate_argument_rules([READ_ONLY_SQL, CORP_EMAIL, SANDBOX, PAY_LIMIT])


# ---------------------------------------------------------------------- through the API
async def _agent(client, token, tools):
    r = await client.post(
        "/api/v1/agents/register",
        json={"name": "arg-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["read"],
              "allowed_tools": tools, "allowed_models": [], "max_delegation_depth": 1},
        headers=auth_headers(token),
    )
    assert r.status_code == 200, r.text
    return r.json()


async def _policy(client, token, agent_id, rules):
    return await client.post("/api/v1/agents/policies/",
                             json={"name": "args-" + secrets.token_hex(2), "agent_id": agent_id,
                                   "rules": {"argument_rules": rules}, "priority": 100},
                             headers=auth_headers(token))


async def _check(client, token, agent, tool, inp):
    r = await client.post("/api/v1/agents/actions/check",
                          json={"agent_id": agent["id"], "tool_name": tool, "input": inp},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


class TestThroughPolicyEngine:
    @pytest.mark.asyncio
    async def test_invalid_rule_is_rejected_when_saving(self, client, admin_token):
        a = await _agent(client, admin_token, ["db.query"])
        r = await _policy(client, admin_token, a["id"], [{"tool": "db.query", "arg": "sql", "op": "matches", "value": "(a+)+"}])
        assert r.status_code == 422, r.text
        assert "nested quantifiers" in r.text

    @pytest.mark.asyncio
    async def test_harmful_arguments_are_denied_with_a_reason(self, client, admin_token):
        a = await _agent(client, admin_token, ["db.query"])
        assert (await _policy(client, admin_token, a["id"], [READ_ONLY_SQL])).status_code == 200
        ok = await _check(client, admin_token, a, "db.query", {"sql": "select * from orders"})
        assert ok["decision"] == "allowed"
        bad = await _check(client, admin_token, a, "db.query", {"sql": "drop table orders"})
        assert bad["decision"] == "denied"
        assert "argument 'sql'" in bad["reason"]

    @pytest.mark.asyncio
    async def test_payment_over_limit_goes_to_approval(self, client, admin_token):
        a = await _agent(client, admin_token, ["payments.charge"])
        assert (await _policy(client, admin_token, a["id"], [PAY_LIMIT])).status_code == 200
        assert (await _check(client, admin_token, a, "payments.charge", {"amount": 20}))["decision"] == "allowed"
        big = await _check(client, admin_token, a, "payments.charge", {"amount": 2500})
        assert big["decision"] == "pending_approval"
        assert "amount" in big["reason"]

    @pytest.mark.asyncio
    async def test_omitting_the_argument_does_not_bypass(self, client, admin_token):
        a = await _agent(client, admin_token, ["email.send"])
        assert (await _policy(client, admin_token, a["id"], [CORP_EMAIL])).status_code == 200
        r = await _check(client, admin_token, a, "email.send", {"subject": "hello"})
        assert r["decision"] == "denied" and "missing" in r["reason"]
