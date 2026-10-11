# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
PVP Input Guard (app/pvp/guard.py).

  - body size: refused with 413 before the application reads it, whether
    the length is declared or the body streams;
  - structure: deep nesting / NUL characters are a 422, not a 500 - before
    the guard, a 5000-deep input crashed the check endpoint with a
    RecursionError, and U+0000 cannot be stored in JSONB;
  - identifiers: a tool name with a Cyrillic letter, an invisible character
    or a full-width form is not the name a policy compares against;
  - rate limit per authenticated principal, not per IP or a claimed id;
  - refusals are logged without content and visible to admins only, per
    organization.
"""

import secrets

import pytest

from app.core.config import settings
from app.pvp import guard
from tests.conftest import _create_org_with_admin_and_approver, _login, auth_headers

CHECK = "/api/v1/agents/actions/check"
RECORD = "/api/v1/agents/actions/record"
LOG = "/api/v1/pvp/guard-log"


async def _agent(client, token):
    r = await client.post("/api/v1/agents/register", json={
        "name": "grd-" + secrets.token_hex(3), "agent_type": "custom",
        "capabilities": ["read"], "allowed_tools": ["db.read"], "allowed_models": ["gpt-4o-mini"],
        "max_delegation_depth": 3,
    }, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


def _nested(depth: int) -> str:
    return "[" * depth + "]" * depth


def _json_post(client, url, token, content):
    return client.post(url, content=content, headers={**auth_headers(token), "Content-Type": "application/json"})


# ---------------------------------------------------------------------------
# Pure checks
# ---------------------------------------------------------------------------

class TestStructure:
    def test_clean_value_has_no_findings(self):
        assert guard.structure_findings({"q": "select 1", "rows": [1, 2, {"a": None}]}) == []

    def test_depth_is_bounded(self):
        value = current = {}
        for _ in range(guard.MAX_DEPTH + 5):
            current["a"] = {}
            current = current["a"]
        assert [f.code for f in guard.structure_findings(value)] == ["input.too_deep"]

    def test_depth_within_the_limit_passes(self):
        value = current = {}
        for _ in range(guard.MAX_DEPTH - 1):
            current["a"] = {}
            current = current["a"]
        assert guard.structure_findings(value) == []

    def test_node_count_is_bounded(self):
        assert [f.code for f in guard.structure_findings(list(range(guard.MAX_NODES + 1)))] == ["input.too_many_nodes"]

    def test_nul_in_value_and_key(self):
        codes = {f.code for f in guard.structure_findings({"a": "x\x00y"})}
        assert codes == {"input.nul_character"}
        assert guard.structure_findings({"k\x00": 1})[0].code == "input.nul_character"

    def test_long_string_and_key(self):
        assert guard.structure_findings("x" * (guard.MAX_STRING + 1))[0].code == "input.string_too_long"
        assert guard.structure_findings({"k" * (guard.MAX_KEY + 1): 1})[0].code == "input.key_too_long"

    def test_paths_do_not_carry_content(self):
        # a key that is not a plain name may itself be the secret
        f = guard.structure_findings({"user": {"ivan@example.com": "a\x00"}})[0]
        assert f.path == "$.user.*"
        assert "ivan" not in f.path


class TestIdentifiers:
    @pytest.mark.parametrize("name", ["db.read", "openai.chat", "gpt-4o-mini", "stripe_charge", "ответ.читать"])
    def test_ordinary_names_pass(self, name):
        assert guard.identifier_findings(name, "$.tool_name") == []

    @pytest.mark.parametrize("name,code", [
        ("stripe.chаrge", "identifier.mixed_script"),          # Cyrillic "a"
        ("stripe.​charge", "identifier.invisible_character"),  # zero-width space
        ("stripe.charge‮", "identifier.invisible_character"),  # bidi override
        ("ｓtripe.charge", "identifier.not_normalized"),        # full-width "s"
        (" stripe.charge", "identifier.surrounding_space"),
    ])
    def test_deceptive_names_are_refused(self, name, code):
        assert [f.code for f in guard.identifier_findings(name, "$.tool_name")] == [code]

    def test_lists_point_at_the_item(self):
        f = guard.inspect({"delegated_tools": ["db.read", "db.wrіte"]}, {})
        assert [(x.code, x.path) for x in f] == [("identifier.mixed_script", "$.delegated_tools[1]")]


def test_body_limits_cover_only_pvp_routes():
    assert guard.body_limit("/api/v1/agents/actions/check") == 1 * guard.MiB
    assert guard.body_limit("/api/v1/agents/actions/record") == 8 * guard.MiB
    assert guard.body_limit("/api/v1/agents/12/delegate") == 64 * guard.KiB
    assert guard.body_limit("/api/v1/agents/register") is None
    assert guard.body_limit("/api/v1/gateway/v1/chat/completions") is None


# ---------------------------------------------------------------------------
# Through the API
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_oversized_body_is_refused_before_parsing(client, admin_token):
    body = '{"agent_id": 1, "tool_name": "db.read", "input": {"x": "%s"}}' % ("a" * guard.MiB)
    r = await _json_post(client, CHECK, admin_token, body)
    assert r.status_code == 413
    assert r.json()["detail"]["code"] == "pvp.body_too_large"


@pytest.mark.asyncio
async def test_oversized_streamed_body_is_refused(client, admin_token):
    async def chunks():
        yield b'{"agent_id": 1, "tool_name": "db.read", "input": {"x": "'
        for _ in range(80):
            yield b"a" * 16 * guard.KiB   # 1.25 MiB in total, no Content-Length
        yield b'"}}'

    r = await client.post(CHECK, content=chunks(),
                          headers={**auth_headers(admin_token), "Content-Type": "application/json"})
    assert r.status_code == 413


@pytest.mark.asyncio
async def test_body_under_the_limit_still_works(client, admin_token):
    a = await _agent(client, admin_token)
    r = await client.post(CHECK, json={"agent_id": a["id"], "tool_name": "db.read", "input": {"x": "a" * 500_000}},
                          headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_deep_nesting_is_a_422_not_a_500(client, admin_token):
    a = await _agent(client, admin_token)
    body = '{"agent_id": %d, "tool_name": "db.read", "input": {"x": %s}}' % (a["id"], _nested(5000))
    r = await _json_post(client, CHECK, admin_token, body)
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert detail["code"] == "pvp.input_rejected" and detail["context"]["reason"] == "input.too_deep"


@pytest.mark.asyncio
async def test_nul_in_recorded_output_is_refused(client, admin_token):
    a = await _agent(client, admin_token)
    r = await client.post(RECORD, json={"agent_id": a["id"], "tool_name": "db.read", "check_id": "x" * 43,
                                        "output": {"text": "a\u0000b"}, "signature": "AAAA"},
                          headers=auth_headers(admin_token))
    assert r.status_code == 422
    assert r.json()["detail"]["context"]["reason"] == "input.nul_character"


@pytest.mark.asyncio
async def test_homoglyph_tool_name_is_refused_and_logged_without_content(client, admin_token):
    a = await _agent(client, admin_token)
    marker = "secret-" + secrets.token_hex(6)
    r = await client.post(CHECK, json={"agent_id": a["id"], "tool_name": "stripe.chаrge",
                                       "input": {"note": marker}}, headers=auth_headers(admin_token))
    assert r.status_code == 422
    assert r.json()["detail"]["context"]["reason"] == "identifier.mixed_script"
    assert marker not in r.text

    log = await client.get(LOG, headers=auth_headers(admin_token))
    assert log.status_code == 200, log.text
    row = log.json()["items"][0]
    assert row["reason"] == "identifier.mixed_script" and row["route"] == "action.request"
    assert row["findings"] == [{"code": "identifier.mixed_script", "path": "$.tool_name"}]
    assert len(row["body_sha256"]) == 64 and row["size_bytes"] > 0
    assert marker not in log.text and "stripe" not in log.text


@pytest.mark.asyncio
async def test_delegation_identifiers_are_checked(client, admin_token):
    from tests.delegation_helpers import delegation_body

    a = await _agent(client, admin_token)
    b = await _agent(client, admin_token)
    body = delegation_body(a, b["id"], "t", ["reаd"])
    r = await client.post(f"/api/v1/agents/{a['id']}/delegate", json=body, headers=auth_headers(admin_token))
    assert r.status_code == 422
    assert r.json()["detail"]["context"]["findings"][0]["path"] == "$.delegated_capabilities[0]"


@pytest.mark.asyncio
async def test_rate_limit_is_per_principal(client, admin_token, approver_token, monkeypatch):
    monkeypatch.setattr(settings, "PVP_RATE_LIMIT_PER_MINUTE", 3)
    a = await _agent(client, admin_token)
    body = {"agent_id": a["id"], "tool_name": "db.read"}
    for _ in range(3):
        assert (await client.post(CHECK, json=body, headers=auth_headers(admin_token))).status_code == 200
    over = await client.post(CHECK, json=body, headers=auth_headers(admin_token))
    assert over.status_code == 429
    assert over.json()["detail"]["code"] == "pvp.rate_limited" and over.headers["Retry-After"] == "60"
    # same IP, another principal: its own budget
    assert (await client.post(CHECK, json=body, headers=auth_headers(approver_token))).status_code == 200


@pytest.mark.asyncio
async def test_guard_log_is_admin_only_and_per_organization(client, db_session, admin_token, approver_token):
    a = await _agent(client, admin_token)
    await client.post(CHECK, json={"agent_id": a["id"], "tool_name": "db.rеad"}, headers=auth_headers(admin_token))

    assert (await client.get(LOG, headers=auth_headers(approver_token))).status_code == 403

    other = await _create_org_with_admin_and_approver(
        db_session, org_slug="guard-other", admin_email="a@guard-other.example.com",
        approver_email="b@guard-other.example.com")
    await db_session.commit()
    other_token = await _login(client, "guard-other", "a@guard-other.example.com", other["password"])
    theirs = await client.get(LOG, headers=auth_headers(other_token))
    assert theirs.status_code == 200 and theirs.json()["total"] == 0

    ours = await client.get(LOG, params={"reason": "identifier.mixed_script"}, headers=auth_headers(admin_token))
    assert ours.json()["total"] == 1
    # agent_id names the agent KEY that sent it; a session acting for an agent leaves it empty
    # (an id from the body is a claim, not an identity)
    assert ours.json()["items"][0]["agent_id"] is None
