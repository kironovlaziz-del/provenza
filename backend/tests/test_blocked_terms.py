# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Blocked terms in one place: matching through disguises, scopes (org,
agents, team, agent, policy), block or monitor, categories, hit counts,
CSV export / import, the tester, audit.
"""

import pytest
from sqlalchemy import select

from app.core import term_match as tm
from app.models.audit_log import AIAuditLog
from app.models.blocked_term import BlockedTerm
from tests.conftest import auth_headers
from tests.test_gateway import FakeProvider, _chat, _cleanup_route, _setup, msgs

pytestmark = pytest.mark.asyncio

B = "/api/v1/blocked-terms"
A = "/api/v1/agents"
T = "/api/v1/teams"


@pytest.fixture
def fake(monkeypatch):
    from app.services import gateway_adapters

    f = FakeProvider()
    monkeypatch.setattr(gateway_adapters, "chat", f)
    return f


def _code(r):
    d = r.json().get("detail")
    return d["code"] if isinstance(d, dict) else d


async def _term(client, token, term, **kw):
    r = await client.post(B, json={"term": term, **kw}, headers=auth_headers(token))
    assert r.status_code == 201, r.text
    return r.json()


# ------------------------------------------------------------------ matching

@pytest.mark.parametrize("text", [
    "our Project Titan plan", "Project_Titan", "PROJECT-TITAN", "ProjectTitan", "P r o j e c t  T i t a n",
    "Prоject Titan",            # Cyrillic о
    "Pr0ject T1tan",            # digits for letters
    "Pro\u200bject Titan",      # zero-width space
    "Ｐｒｏｊｅｃｔ Ｔｉｔａｎ",  # full width
    "Prōject Tītan",            # accents
])
async def test_word_mode_sees_through_disguises(text):
    assert tm.find(text, [tm.Term(1, "Project Titan")])


@pytest.mark.parametrize("term,text", [
    ("therapist", "the rapist"), ("island", "is land"), ("init", "in it"),   # words are not glued across spaces
    ("iOS", "room 105"), ("test", "PIN 7357"), ("io", "version 1.0"),          # numbers stay numbers
    ("man", "man\u0303ana"),                                                   # a separate accent is part of the word
    ("Ali", "all of them"), ("Li", "World War II"),                             # l and i stay different letters
    ("BA", "Plan B a lot"),                                                     # two one-letter words are not glued
])
async def test_ordinary_text_does_not_match(term, text):
    assert not tm.find(text, [tm.Term(1, term)])


async def test_substring_mode_does_not_cross_spaces_and_emails_split():
    assert not tm.find("send it", [tm.Term(1, "dit", match="substring")])
    assert not tm.find("he has some", [tm.Term(1, "ass", match="substring")])
    assert tm.find("bob@titan.com", [tm.Term(1, "titan")]) and tm.find("@titan", [tm.Term(1, "titan")])
    assert tm.find("he11o c1ient", [tm.Term(1, "hello client")])


async def test_word_mode_needs_whole_words_substring_does_not():
    assert not tm.find("this class is fine", [tm.Term(1, "ass")])
    assert not tm.find("titanium", [tm.Term(1, "titan")])
    assert tm.find("titanium", [tm.Term(1, "titan", match="substring")])
    assert tm.find("Документ СЕКРЕТНО!", [tm.Term(1, "секретно")])  # Cyrillic terms find themselves


# ------------------------------------------------------------------ API

async def test_crud_categories_and_audit(client, admin_token, approver_token, db_session):
    h = auth_headers(admin_token)
    r = await client.post(B, json={"term": "x"}, headers=auth_headers(approver_token))
    assert r.status_code == 403
    r = await client.post(B, json={"term": "!!"}, headers=h)
    assert r.status_code == 422 and _code(r) == "terms.too_short"
    r = await client.post(B, json={"term": "titan", "scope": "team"}, headers=h)
    assert r.status_code == 422 and _code(r) == "terms.target_required"

    cat = (await client.post(f"{B}/categories", json={"name": "Projects"}, headers=h)).json()
    t = await _term(client, admin_token, "Project Titan", category_id=cat["id"])
    r = await client.post(B, json={"term": "project-titan"}, headers=h)  # the same letters
    assert r.status_code == 409 and _code(r) == "terms.duplicate"

    r = await client.patch(f"{B}/{t['id']}", json={"action": "monitor"}, headers=h)
    assert r.status_code == 200 and r.json()["action"] == "monitor"
    r = await client.patch(f"{B}/{t['id']}", json={"enabled": None}, headers=h)
    assert r.status_code == 422 and _code(r) == "terms.value_required"

    ov = (await client.get(B, headers=auth_headers(approver_token))).json()
    assert ov["terms"][0]["category"] == "Projects" and ov["categories"][0]["terms"] == 1

    assert (await client.delete(f"{B}/{t['id']}", headers=h)).status_code == 200
    assert (await client.get(B, headers=h)).json()["terms"] == []
    kept = (await db_session.execute(select(BlockedTerm).where(BlockedTerm.id == t["id"]))).scalar_one()
    assert kept.deleted_at is not None
    actions = [a for (a,) in (await db_session.execute(
        select(AIAuditLog.action).where(AIAuditLog.entity_type == "blocked_term", AIAuditLog.entity_id == t["id"])
        .order_by(AIAuditLog.seq)))]
    assert actions == ["created", "updated", "deleted"]


async def test_scopes_monitor_categories_and_hits_in_the_gateway(client, admin_token, db_session, fake):
    h = auth_headers(admin_token)
    a, pid, rid = await _setup(client, admin_token, db_session)
    other, _, _ = await _setup(client, admin_token, db_session, route="gpt-4o-mini-other")
    team = (await client.post(f"{T}/", json={"name": "bt-team"}, headers=h)).json()
    sub = (await client.post(f"{T}/", json={"name": "bt-sub", "parent_id": team["id"]}, headers=h)).json()
    r = await client.put(f"{A}/{a['id']}/assignment", json={"team_id": sub["id"], "role_id": None}, headers=h)
    assert r.status_code == 200, r.text
    try:
        await _term(client, admin_token, "zeus", scope="team", target_id=team["id"])   # a team above the agent's
        await _term(client, admin_token, "hermes", scope="agent", target_id=a["id"])
        cat = (await client.post(f"{B}/categories", json={"name": "Watch"}, headers=h)).json()
        watched = await _term(client, admin_token, "apollo", action="monitor", category_id=cat["id"])

        r = await _chat(client, a, msgs(("user", "about Zeus")))
        assert r.status_code == 403 and r.json()["error"]["code"] == "blocked_by_firewall"
        r = await _chat(client, a, msgs(("user", "about h-e-r-m-e-s")))
        assert r.status_code == 403
        assert (await _chat(client, other, msgs(("user", "about zeus and hermes")))).status_code == 200  # not its scope

        # monitor: let through and counted - and not shown to the agent being watched
        r = await _chat(client, a, msgs(("user", "about Apollo")))
        assert r.status_code == 200 and not any("apollo" in f for f in r.json()["provenza"]["flags"])
        hits = {t["term"]: t["hits"] for t in (await client.get(B, headers=h)).json()["terms"]}
        assert hits["apollo"] == 1 and hits["zeus"] == 1 and hits["hermes"] == 1

        # a switched-off category switches its terms off
        await client.patch(f"{B}/categories/{cat['id']}", json={"enabled": False}, headers=h)
        assert (await _chat(client, a, msgs(("user", "about Apollo")))).status_code == 200
        hits = {t["term"]: t["hits"] for t in (await client.get(B, headers=h)).json()["terms"]}
        assert hits["apollo"] == 1
        # a team with terms scoped to it is not deleted from under them
        r = await client.put(f"{A}/{a['id']}/assignment", json={"team_id": None, "role_id": None}, headers=h)
        assert (await client.delete(f"{T}/{sub['id']}", headers=h)).status_code == 200
        r = await client.delete(f"{T}/{team['id']}", headers=h)
        assert r.status_code == 409 and "blocked_terms" in r.json()["detail"]["context"]["parts"]
        assert watched["id"]
    finally:
        await _cleanup_route(client, admin_token, rid)


async def test_requests_use_org_and_their_policy(client, admin_token):
    h = auth_headers(admin_token)
    provider = (await client.post("/api/v1/providers/", json={"name": "P", "type": "openai"}, headers=h)).json()["id"]
    pol = (await client.post("/api/v1/policies/", json={"name": "Contracts"}, headers=h)).json()["id"]
    ver = (await client.post(f"/api/v1/policies/{pol}/versions", json={"rules_json": {}}, headers=h)).json()["id"]
    await client.post(f"/api/v1/policies/{pol}/versions/{ver}/approve", headers=h)
    uc_with = (await client.post("/api/v1/use-cases/", json={"name": "with", "risk_level": "low"}, headers=h)).json()
    await client.put(f"/api/v1/use-cases/{uc_with['id']}", json={"approved_policy_version_id": ver}, headers=h)
    uc_plain = (await client.post("/api/v1/use-cases/", json={"name": "plain", "risk_level": "low"}, headers=h)).json()
    await _term(client, admin_token, "titan")
    await _term(client, admin_token, "zeus", scope="policy", target_id=pol)
    await _term(client, admin_token, "hermes", scope="agents")   # agents only: not user requests

    async def ask(uc, text):
        r = await client.post("/api/v1/requests/", headers=h, json={
            "use_case_id": uc["id"], "provider_id": provider, "input_text": text, "purpose": "t"})
        assert r.status_code == 200, r.text
        return r.json()["status"]

    assert await ask(uc_plain, "about Titan") == "blocked"
    assert await ask(uc_plain, "about Zeus") != "blocked"
    assert await ask(uc_with, "about Zeus") == "blocked"
    assert await ask(uc_with, "about Hermes") != "blocked"


async def test_tester_and_csv(client, admin_token, approver_token):
    h = auth_headers(admin_token)
    await _term(client, admin_token, "Project Titan", note="=HYPERLINK(\"x\")")
    t = (await client.post(f"{B}/test", headers=auth_headers(approver_token), json={
        "sample": "see Pr0ject_Titan and zeus", "term": {"term": "zeus", "action": "monitor"}})).json()
    found = {x["term"]: x for x in t["hits"]}
    assert found["Project Titan"]["spans"][0]["text"] == "Pr0ject_Titan" and found["zeus"]["scope"] == "draft"

    csv_text = (await client.get(f"{B}/export.csv", headers=h)).text
    assert csv_text.lstrip("\ufeff").startswith("term,match,action,scope,target,category,enabled,note")
    assert "'=HYPERLINK" in csv_text  # a formula is not run by a spreadsheet

    data = "term,action,category\nhermes,monitor,Gods\nproject titan,block,\n,block,\n"
    r = await client.post(f"{B}/import", json={"csv": data, "dry_run": True}, headers=h)
    out = r.json()
    assert out["added"] == 1 and len(out["skipped"]) == 1 and len(out["errors"]) == 1
    assert (await client.get(B, headers=h)).json()["terms"].__len__() == 1  # nothing stored on a dry run
    r = await client.post(f"{B}/import", json={"csv": data, "dry_run": False}, headers=h)
    ov = (await client.get(B, headers=h)).json()
    hermes = next(x for x in ov["terms"] if x["term"] == "hermes")
    assert hermes["action"] == "monitor" and hermes["category"] == "Gods"
    r = await client.post(f"{B}/import", json={"csv": data, "dry_run": False}, headers=auth_headers(approver_token))
    assert r.status_code == 403
