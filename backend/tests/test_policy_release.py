"""
Signed policy releases (docs/pvp/edge.md, section 3; app/pvp/signed_policy.py,
app/services/policy_release.py): the bundle and the key manifest, frozen,
signed by a quorum of administrators with their passkeys. Once one is in
force an action needs the working copy AND the signed release: tightening
applies at once, loosening only when signed; agents, keys and the rows
that carry a call must be the signed ones; who may sign comes from the
release before.
"""

import secrets
import time

import pytest
from sqlalchemy import select, update

from app.core.agent_signing import content_hash
from app.models.ai_incident import AIIncident
from app.models.policy_release import PolicyRelease
from app.pvp import signed_policy
from tests import signer
from tests.conftest import _login, auth_headers
from tests.delegation_helpers import action_record_body
from tests.test_gateway import G, FakeProvider, _chat, _setup, msgs

R = "/api/v1/policy-releases"
A = "/api/v1/agents"


@pytest.fixture
def fake(monkeypatch):
    from app.services import gateway_adapters

    f = FakeProvider()
    monkeypatch.setattr(gateway_adapters, "chat", f)
    return f


@pytest.fixture(autouse=True)
def _fresh_cache():
    signed_policy.forget()
    yield
    signed_policy.forget()


async def _agent(client, token, tools=("db.read",)):
    r = await client.post(f"{A}/register", json={
        "name": "rel-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["read"],
        "allowed_tools": list(tools), "allowed_models": [], "max_delegation_depth": 2}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _check(client, token, agent, tool="db.read", inp=None):
    r = await client.post(f"{A}/actions/check", json={"agent_id": agent["id"], "tool_name": tool,
                                                      "input": inp or {"q": 1}}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _prepare(client, token):
    r = await client.post(f"{R}/prepare", headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()["draft"]


async def _sign(client, token, release_id):
    s = await signer.signer(client, token)
    ch = await client.post(f"{R}/{release_id}/challenge", headers=auth_headers(token))
    assert ch.status_code == 200, ch.text
    ch = ch.json()
    return await client.post(f"{R}/{release_id}/sign",
                             json={"statement": ch["statement"], "assertion": s.device.get(ch["challenge"])},
                             headers=auth_headers(token))


async def _release(client, token):
    """Prepare and sign (quorum 1): the working copy comes into force."""
    await signer.signer(client, token)
    draft = await _prepare(client, token)
    r = await _sign(client, token, draft["id"])
    assert r.status_code == 200, r.text
    assert r.json()["in_force"]["number"] == draft["number"]
    return r.json()


async def _second_admin(client, db_session, org_and_users, email="admin2@test.example.com"):
    from app.core.security import get_password_hash
    from app.models.user import User

    db_session.add(User(org_id=org_and_users["org"].id, email=email, name="Admin 2",
                        hashed_password=get_password_hash(org_and_users["password"]), role="admin", status="active"))
    await db_session.commit()
    return await _login(client, org_and_users["org"].slug, email, org_and_users["password"])


class TestReleases:
    @pytest.mark.asyncio
    async def test_without_a_release_nothing_changes(self, client, admin_token, approver_token):
        st = (await client.get(f"{R}/state", headers=auth_headers(admin_token))).json()
        assert st["in_force"] is None and st["draft"] is None and st["unsigned_changes"] is None
        assert st["settings"] == {"quorum": 1, "validity_days": 90, "offline_seconds": 900, "proxy_binaries": [],
                                  "proxy_configs": [], "enforcement": "observe"}
        # no administrator has a passkey: nobody could sign
        r = await client.post(f"{R}/prepare", headers=auth_headers(admin_token))
        assert r.status_code == 409 and r.json()["detail"] == "policy_release.no_signers"
        # only administrators prepare and sign
        assert (await client.post(f"{R}/prepare", headers=auth_headers(approver_token))).status_code == 403
        a = await _agent(client, admin_token)
        assert (await _check(client, admin_token, a))["decision"] == "allowed"

    @pytest.mark.asyncio
    async def test_the_first_release_comes_into_force_when_signed(self, client, admin_token, org_and_users):
        a = await _agent(client, admin_token)
        await signer.signer(client, admin_token)
        draft = await _prepare(client, admin_token)
        assert draft["number"] == 1 and draft["quorum"] == 1 and draft["can_sign"]
        changed = {(c["section"], c["key"]) for c in draft["changes"]}
        assert ("agents", str(a["id"])) in changed
        assert ("manifest.signers", str(org_and_users["admin"].id)) in changed
        st = await _release(client, admin_token)
        assert st["draft"] is None and st["unsigned_count"] == 0
        assert [s["user_id"] for s in st["in_force"]["signers"]] == [org_and_users["admin"].id]
        doc = (await client.get(f"{R}/{st['in_force']['id']}", headers=auth_headers(admin_token))).json()
        assert doc["bundle"]["agents"][str(a["id"])]["allowed_tools"] == ["db.read"]
        assert doc["manifest"]["agents"][str(a["id"])] is not None
        assert doc["signatures"][0]["statement"]["type"] == "provenza.policy.release"
        # a release in force is not signed again
        r = await client.post(f"{R}/{st['in_force']['id']}/challenge", headers=auth_headers(admin_token))
        assert r.status_code == 409 and r.json()["detail"] == "policy_release.not_draft"

    @pytest.mark.asyncio
    async def test_a_statement_must_be_exactly_this_release(self, client, admin_token):
        s = await signer.signer(client, admin_token)
        draft = await _prepare(client, admin_token)
        ch = (await client.post(f"{R}/{draft['id']}/challenge", headers=auth_headers(admin_token))).json()
        other = dict(ch["statement"], not_after=ch["statement"]["not_after"] + 86400)
        from app.core import webauthn
        from tests.webauthn_helpers import b64url

        r = await client.post(f"{R}/{draft['id']}/sign", json={
            "statement": other, "assertion": s.device.get(b64url(webauthn.statement_challenge(other)))},
            headers=auth_headers(admin_token))
        assert r.status_code == 422 and r.json()["detail"] == "passkey.statement_mismatch"
        assert (await client.get(f"{R}/state", headers=auth_headers(admin_token))).json()["in_force"] is None


class TestEnforcement:
    @pytest.mark.asyncio
    async def test_loosening_waits_for_signatures_tightening_applies_at_once(self, client, admin_token):
        a = await _agent(client, admin_token, tools=("db.read", "db.list"))
        await _release(client, admin_token)
        r = await client.put(f"{A}/{a['id']}", json={"allowed_tools": ["db.list", "db.write"]},
                             headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        # taken away: at once
        assert (await _check(client, admin_token, a, "db.read"))["decision"] == "denied"
        # added: not before it is signed
        held = await _check(client, admin_token, a, "db.write")
        assert held["decision"] == "denied" and "signed policy (release #1)" in held["reason"]
        assert (await _check(client, admin_token, a, "db.list"))["decision"] == "allowed"
        st = (await client.get(f"{R}/state", headers=auth_headers(admin_token))).json()
        assert any(c["section"] == "agents" and c["key"] == str(a["id"]) for c in st["unsigned_changes"])
        await _release(client, admin_token)
        assert (await _check(client, admin_token, a, "db.write"))["decision"] == "allowed"

    @pytest.mark.asyncio
    async def test_an_agent_or_key_not_in_the_release_cannot_act(self, client, admin_token, db_session):
        a = await _agent(client, admin_token)
        await _release(client, admin_token)
        b = await _agent(client, admin_token)
        r = await _check(client, admin_token, b)
        assert r["decision"] == "denied" and "not in the signed policy" in r["reason"]
        # a key replaced behind the release's back
        from app.core.agent_signing import generate_keypair
        from app.models.agent import Agent

        _, pub = generate_keypair()
        await db_session.execute(update(Agent).where(Agent.id == a["id"]).values(public_key=pub))
        await db_session.commit()
        r = await _check(client, admin_token, a)
        assert r["decision"] == "denied" and "key is not the one in the signed manifest" in r["reason"]

    @pytest.mark.asyncio
    async def test_a_row_that_carries_the_call_must_be_signed(self, client, admin_token, db_session, org_and_users):
        from app.models.mcp import MCPServer

        a = await _agent(client, admin_token, tools=("crm.lookup",))
        server = MCPServer(org_id=org_and_users["org"].id, slug="crm", name="CRM", url="https://crm.example/mcp")
        db_session.add(server)
        await db_session.commit()
        await _release(client, admin_token)
        assert "MCP server" not in ((await _check(client, admin_token, a, "crm.lookup"))["reason"] or "")
        await db_session.execute(update(MCPServer).where(MCPServer.id == server.id)
                                 .values(url="https://evil.example/mcp"))
        await db_session.commit()
        r = await _check(client, admin_token, a, "crm.lookup")
        assert r["decision"] == "denied" and "MCP server 'crm' is not configured as in the signed policy" in r["reason"]

    @pytest.mark.asyncio
    async def test_a_release_altered_in_the_database_allows_nothing(self, client, admin_token, db_session,
                                                                    org_and_users):
        a = await _agent(client, admin_token)
        st = await _release(client, admin_token)
        row = await db_session.get(PolicyRelease, st["in_force"]["id"])
        bundle = dict(row.bundle)
        bundle["agents"] = dict(bundle["agents"], **{str(a["id"]): dict(bundle["agents"][str(a["id"])],
                                                                        allowed_tools=["db.read", "db.drop"])})
        await db_session.execute(update(PolicyRelease).where(PolicyRelease.id == row.id).values(bundle=bundle))
        await db_session.commit()
        signed_policy.forget()
        r = await _check(client, admin_token, a)
        assert r["decision"] == "denied" and "does not verify" in r["reason"]
        incident = (await db_session.execute(select(AIIncident).where(
            AIIncident.org_id == org_and_users["org"].id, AIIncident.category == "signed_policy_invalid"))).scalar()
        assert incident is not None
        # a quorum puts a sound release in force again, governed by the last one that verifies (none here)
        await _release(client, admin_token)
        assert (await _check(client, admin_token, a))["decision"] == "allowed"

    @pytest.mark.asyncio
    async def test_an_expired_release_allows_nothing(self, client, admin_token, monkeypatch):
        a = await _agent(client, admin_token)
        st = await _release(client, admin_token)
        later = st["in_force"]["not_after"] + 1
        monkeypatch.setattr(signed_policy.time, "time", lambda: later)
        r = await _check(client, admin_token, a)
        assert r["decision"] == "denied" and "expired" in r["reason"]

    @pytest.mark.asyncio
    async def test_identity_settings_loosen_only_when_signed(self, client, admin_token, db_session, org_and_users):
        from app.models.agent_identity import AgentIdentitySettings
        from app.services.agent_identity import org_settings

        org_id = org_and_users["org"].id
        await db_session.execute(update(AgentIdentitySettings).where(AgentIdentitySettings.org_id == org_id)
                                 .values(require_pq_signatures=True))
        await db_session.commit()
        await _release(client, admin_token)
        await db_session.execute(update(AgentIdentitySettings).where(AgentIdentitySettings.org_id == org_id)
                                 .values(require_pq_signatures=False))
        await db_session.commit()
        assert (await org_settings(db_session, org_id))["require_pq_signatures"] is True
        await _release(client, admin_token)
        assert (await org_settings(db_session, org_id))["require_pq_signatures"] is False


class TestWhoSigns:
    @pytest.mark.asyncio
    async def test_a_quorum_of_two(self, client, admin_token, db_session, org_and_users):
        second = await _second_admin(client, db_session, org_and_users)
        await signer.signer(client, admin_token)
        await signer.signer(client, second)
        r = await client.put(f"{R}/settings", json={"quorum": 2, "validity_days": 30, "offline_seconds": 600},
                             headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        draft = await _prepare(client, admin_token)
        assert draft["quorum"] == 2
        st = (await _sign(client, admin_token, draft["id"])).json()
        assert st["in_force"] is None and len(st["draft"]["signers"]) == 1
        st = (await _sign(client, second, draft["id"])).json()
        assert st["in_force"]["number"] == draft["number"] and st["in_force"]["offline_seconds"] == 600
        # lowering the quorum is itself a change the current quorum must sign
        await client.put(f"{R}/settings", json={"quorum": 1, "validity_days": 30, "offline_seconds": 600},
                         headers=auth_headers(admin_token))
        draft = await _prepare(client, admin_token)
        assert draft["quorum"] == 2
        st = (await _sign(client, admin_token, draft["id"])).json()
        assert st["in_force"]["number"] == draft["number"] - 1

    @pytest.mark.asyncio
    async def test_a_quorum_nobody_can_reach_is_refused(self, client, admin_token):
        await signer.signer(client, admin_token)
        await client.put(f"{R}/settings", json={"quorum": 2, "validity_days": 30, "offline_seconds": 600},
                         headers=auth_headers(admin_token))
        r = await client.post(f"{R}/prepare", headers=auth_headers(admin_token))
        assert r.status_code == 409 and r.json()["detail"]["code"] == "policy_release.quorum_unreachable"

    @pytest.mark.asyncio
    async def test_a_passkey_added_after_the_release_signs_nothing_yet(self, client, admin_token, db_session,
                                                                     org_and_users):
        await _release(client, admin_token)
        second = await _second_admin(client, db_session, org_and_users)
        await signer.signer(client, second)
        draft = await _prepare(client, second)
        r = await client.post(f"{R}/{draft['id']}/challenge", headers=auth_headers(second))
        assert r.status_code == 403 and r.json()["detail"] == "policy_release.not_a_signer"
        assert (await _sign(client, admin_token, draft["id"])).status_code == 200
        # from this release on the second administrator signs too
        draft = await _prepare(client, admin_token)
        assert (await _sign(client, second, draft["id"])).status_code == 200


class TestApprovals:
    @pytest.mark.asyncio
    async def test_an_approvers_passkey_must_be_in_the_manifest(self, client, admin_token, approver_token):
        await client.post(f"{A}/policies/", json={"name": "gate", "rules": {"require_approval_tools": ["db.read"]},
                                                 "priority": 100}, headers=auth_headers(admin_token))
        a = await _agent(client, admin_token)
        await _release(client, admin_token)
        inp = {"q": 7}
        chk = await _check(client, admin_token, a, inp=inp)
        assert chk["decision"] == "pending_approval"
        rec = await client.post(f"{A}/actions/record", json=action_record_body(a, chk["check_id"], "db.read", inp),
                                headers=auth_headers(admin_token))
        held = rec.json()["id"]
        # the approver's passkey is newer than the release
        r = await signer.approve(client, approver_token, held, content_hash(inp))
        assert r.status_code == 200, r.text
        assert (await _check(client, admin_token, a, inp=inp))["decision"] == "pending_approval"
        await _release(client, admin_token)
        assert (await _check(client, admin_token, a, inp=inp))["decision"] == "allowed"


@pytest.mark.asyncio
async def test_release_statement_names_both_documents():
    r = PolicyRelease(org_id=1, number=3, bundle={"version": 3, "not_after": int(time.time())}, bundle_sha256="b",
                      manifest={"version": 2}, manifest_sha256="m")
    st = signed_policy.release_statement(1, 5, r, 10)
    assert st == {"type": "provenza.policy.release", "v": 1, "org_id": 1, "user_id": 5, "release": 3,
                  "bundle": {"version": 3, "sha256": "b"}, "manifest": {"version": 2, "sha256": "m"},
                  "not_after": r.bundle["not_after"], "issued_at": 10}


class TestGateway:
    @pytest.mark.asyncio
    async def test_a_model_goes_only_where_the_signed_route_says(self, client, admin_token, db_session, fake):

        a, provider_id, route_id = await _setup(client, admin_token, db_session)
        await _release(client, admin_token)
        assert (await _chat(client, a, msgs(("user", "hi")))).status_code == 200
        # the route is replaced by one to another connection: it carries nothing until signed
        await client.post(f"{G}/routes/{route_id}/disable", headers=auth_headers(admin_token))
        r = await client.post(G + "/routes", json={"model": "gpt-4o-mini", "provider_id": provider_id,
                                                    "upstream_model": "gpt-4o"}, headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        r = await _chat(client, a, msgs(("user", "hi")))
        assert r.status_code == 403 and r.json()["error"]["code"] == "policy_denied"
        assert "gateway route" in r.json()["error"]["message"]
        assert len(fake.calls) == 1
        await _release(client, admin_token)
        assert (await _chat(client, a, msgs(("user", "hi")))).status_code == 200


class TestOffline:
    @pytest.mark.asyncio
    async def test_a_release_verifies_without_the_server(self, client, admin_token, tmp_path, capsys):
        import copy
        import importlib.util
        import json
        from pathlib import Path

        spec = importlib.util.spec_from_file_location(
            "provenza_audit_tool_release", Path(__file__).resolve().parents[2] / "tools" / "provenza_audit.py")
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)

        await _agent(client, admin_token)
        first = (await _release(client, admin_token))["in_force"]["id"]
        await _agent(client, admin_token)
        second = (await _release(client, admin_token))["in_force"]["id"]
        fp = (await client.get("/api/v1/users/me/passkeys", headers=auth_headers(admin_token))).json()[0]["fingerprint"]
        for rid in (first, second):
            doc = (await client.get(f"{R}/{rid}", headers=auth_headers(admin_token))).json()
            _, signed = tool.check_release(doc, [fp])
            assert list(signed.values()) == [fp]
        path = tmp_path / "release.json"
        path.write_text(json.dumps(doc))
        assert tool.main(["release", str(path), "--passkey", fp]) == 0
        assert f"with passkey {fp}" in capsys.readouterr().out

        def broken(change, match):
            d = copy.deepcopy(doc)
            change(d)
            with pytest.raises(tool.Fail, match=match):
                tool.check_release(d)

        agent_key = next(iter(doc["bundle"]["agents"]))
        broken(lambda d: d["bundle"]["agents"][agent_key].update(allowed_tools=["*"]), "hash")
        broken(lambda d: d["governed_by"]["manifest"].update(quorum=2), "hash")
        broken(lambda d: d["signatures"][0]["assertion"].update(
            signature=d["signatures"][0]["assertion"]["signature"][:-4] + "AAAA"), "valid administrator")
        with pytest.raises(tool.Fail, match="none of the passkeys"):
            tool.check_release(doc, ["SHA256:someoneelse"])
