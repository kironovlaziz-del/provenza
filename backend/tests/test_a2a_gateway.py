# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
A2A gateway (app/pvp/a2a_wire.py, app/pvp/a2a_gateway.py, app/api/a2a_gateway.py).

A fake remote agent answers in A2A 1.0 or 0.3; the calling agent speaks
either. Shown: every client/peer version pair works and the peer gets its
own format; the agent sees only Provenza's card; tasks belong to the agent
that created them; a changed card is refused and drifts; push, streaming
and unknown versions are refused with the A2A error codes; injected or
foreign answers are withheld; every exchange is a recorded PVP action.
"""

import json
import secrets

import httpx
import pytest
from sqlalchemy import select

from app.models.a2a_gateway import A2ATask
from app.models.agent_action import AgentAction
from app.pvp import a2a_gateway, a2a_wire as w, upstream_http
from tests.conftest import auth_headers

PEERS = "/api/v1/a2a-peers"
GW = "/api/v1/a2a-gateway"
CARD_URL = "https://helper.example.com/.well-known/agent-card.json"
ENDPOINT = "https://helper.example.com/a2a"
SECRET = "Bearer peer-" + "k" * 24


# ---------------------------------------------------------------------------
# A fake remote agent
# ---------------------------------------------------------------------------

class FakePeer:
    def __init__(self, version="1.0"):
        self.version = version
        self.reply_text = "summary ready"
        self.task_id = "task-" + secrets.token_hex(4)
        self.skills = [{"id": "summarize", "name": "Summarize", "description": "Summarizes text", "tags": ["text"]}]
        self.endpoint = ENDPOINT
        self.calls = []
        self.down = False

    def card(self):
        base = {"name": "Helper", "description": "Summarizes documents", "version": "2.1",
                "capabilities": {"streaming": True, "pushNotifications": True},
                "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"], "skills": self.skills,
                "securitySchemes": {"peerKey": {"type": "http", "scheme": "bearer"}}}
        if self.version == "1.0":
            return {**base, "supportedInterfaces": [
                {"url": self.endpoint, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]}
        return {**base, "url": self.endpoint, "protocolVersion": "0.3.0", "preferredTransport": "JSONRPC"}

    def task(self, state_v1="TASK_STATE_COMPLETED", state_03="completed"):
        if self.version == "1.0":
            return {"id": self.task_id, "contextId": "ctx-1", "status": {"state": state_v1},
                    "artifacts": [{"artifactId": "a1", "parts": [{"text": self.reply_text}]}]}
        return {"kind": "task", "id": self.task_id, "contextId": "ctx-1", "status": {"state": state_03},
                "artifacts": [{"artifactId": "a1", "parts": [{"kind": "text", "text": self.reply_text}]}]}

    def handle(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("down")
        assert request.headers.get("authorization") == SECRET   # the gateway injects the peer's secret
        if request.method == "GET":
            return httpx.Response(200, json={**self.card(), "signatures": [{"protected": "x", "signature": "y"}]})
        body = json.loads(request.content)
        self.calls.append((dict(request.headers), body))
        method, rid, params = body["method"], body["id"], body["params"]
        if self.version == "1.0":
            assert request.headers.get("a2a-version") == "1.0"
            assert method in ("SendMessage", "GetTask", "CancelTask"), method
            if method == "SendMessage":
                assert all("kind" not in p for p in params["message"]["parts"])
                assert params["message"]["role"] == "ROLE_USER"
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": {"task": self.task()}})
        else:
            assert "a2a-version" not in request.headers
            assert method in ("message/send", "tasks/get", "tasks/cancel"), method
            if method == "message/send":
                assert params["message"]["kind"] == "message" and params["message"]["role"] == "user"
                assert all("kind" in p for p in params["message"]["parts"])
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": self.task()})
        if method in ("CancelTask", "tasks/cancel"):
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid,
                                             "result": self.task("TASK_STATE_CANCELED", "canceled")})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": self.task()})


@pytest.fixture
def peer(monkeypatch):
    fake = FakePeer()
    monkeypatch.setattr(upstream_http, "_client",
                        lambda timeout: httpx.AsyncClient(transport=httpx.MockTransport(fake.handle)))
    a2a_gateway._live.clear()
    yield fake
    a2a_gateway._live.clear()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

async def _agent(client, token, tools=("a2a.helper",)):
    r = await client.post("/api/v1/agents/register", json={
        "name": "a2a-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["read"],
        "allowed_tools": list(tools), "allowed_models": [], "max_delegation_depth": 2,
    }, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _peer(client, token, **extra):
    r = await client.post(PEERS, json={"slug": "helper", "name": "Helper", "card_url": CARD_URL,
                                       "auth_secret": SECRET, **extra}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _ready(client, token):
    p = await _peer(client, token)
    r = await client.post(f"{PEERS}/{p['id']}/sync", headers=auth_headers(token))
    assert r.status_code == 200, r.text
    r = await client.post(f"{PEERS}/{p['id']}/approve", headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return p


def _msg(version, text="Summarize the Q3 report", task_id=None):
    if version == "1.0":
        m = {"messageId": secrets.token_hex(4), "role": "ROLE_USER", "parts": [{"text": text}]}
    else:
        m = {"kind": "message", "messageId": secrets.token_hex(4), "role": "user",
             "parts": [{"kind": "text", "text": text}]}
    if task_id:
        m["taskId"] = task_id
    return m


async def _rpc(client, agent, method, params, version="1.0", slug="helper"):
    headers = {"X-Agent-Key": agent["api_key"]}
    if version == "1.0":
        headers["A2A-Version"] = "1.0"
    return await client.post(f"{GW}/{slug}", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                             headers=headers)


async def _send(client, agent, version="1.0", **kw):
    method = "SendMessage" if version == "1.0" else "message/send"
    return await _rpc(client, agent, method, {"message": _msg(version, **kw)}, version)


def _task_of(resp, version):
    result = resp.json()["result"]
    return result["task"] if version == "1.0" else result


# ---------------------------------------------------------------------------
# Wire formats (pure)
# ---------------------------------------------------------------------------

class TestWire:
    @pytest.mark.parametrize("header,expected", [
        (None, "0.3"), ("", "0.3"), ("1.0", "1.0"), ("1.0.2", "1.0"), ("0.3.0", "0.3"), ("2.0", None), ("x", None),
    ])
    def test_version_header(self, header, expected):
        assert w.version_of(header) == expected

    def test_message_round_trip_between_versions(self):
        legacy = {"kind": "message", "messageId": "m1", "role": "user", "parts": [
            {"kind": "text", "text": "hi"},
            {"kind": "file", "file": {"name": "a.pdf", "mimeType": "application/pdf", "bytes": "AAAA"}},
            {"kind": "file", "file": {"uri": "https://x.example/b"}},
            {"kind": "data", "data": {"k": 1}},
        ]}
        canon = w.message_from_wire(legacy, w.V03)
        assert canon["role"] == "ROLE_USER"
        assert canon["parts"] == [{"text": "hi"}, {"raw": "AAAA", "filename": "a.pdf", "mediaType": "application/pdf"},
                                  {"url": "https://x.example/b"}, {"data": {"k": 1}, "mediaType": "application/json"}]
        back = w.message_to_wire(canon, w.V03)
        assert back["kind"] == "message" and back["role"] == "user"
        assert back["parts"][1] == {"kind": "file", "file": {"bytes": "AAAA", "name": "a.pdf",
                                                             "mimeType": "application/pdf"}}

    @pytest.mark.parametrize("bad", [
        {"messageId": "m", "role": "ROLE_USER", "parts": [{"text": "a", "data": {}}]},       # two contents
        {"messageId": "m", "role": "ROLE_USER", "parts": [{"text": "a"}], "evil": 1},        # unknown field
        {"messageId": "m", "role": "ROLE_ADMIN", "parts": [{"text": "a"}]},                  # role
        {"messageId": "", "role": "ROLE_USER", "parts": [{"text": "a"}]},                    # empty id
        {"messageId": "m", "role": "ROLE_USER", "parts": []},                                # no parts
    ])
    def test_malformed_messages_are_refused(self, bad):
        with pytest.raises(w.A2AError) as exc:
            w.message_from_wire(bad, w.V1)
        assert exc.value.code == w.INVALID_PARAMS

    def test_task_states_map_both_ways(self):
        t = w.task_from_peer({"kind": "task", "id": "t", "status": {"state": "input-required"}}, w.V03)
        assert t["status"]["state"] == "TASK_STATE_INPUT_REQUIRED" and "kind" not in t
        assert w.task_to_wire(t, w.V03)["status"]["state"] == "input-required"

    def test_blocking_is_the_inverse_of_return_immediately(self):
        p = w.send_params_from_wire({"message": _msg("0.3"), "configuration": {"blocking": False}}, w.V03)
        assert p["configuration"] == {"returnImmediately": True}
        assert w.send_params_to_wire(p, w.V03)["configuration"] == {"blocking": False}

    def test_push_config_is_refused(self):
        with pytest.raises(w.A2AError) as exc:
            w.send_params_from_wire({"message": _msg("1.0"),
                                     "configuration": {"taskPushNotificationConfig": {"url": "https://x"}}}, w.V1)
        assert exc.value.code == w.PUSH_NOT_SUPPORTED

    def test_card_endpoint_prefers_1_0(self):
        card = {"supportedInterfaces": [
            {"url": "https://a/03", "protocolBinding": "JSONRPC", "protocolVersion": "0.3"},
            {"url": "https://a/grpc", "protocolBinding": "GRPC", "protocolVersion": "1.0"},
            {"url": "https://a/v1", "protocolBinding": "JSONRPC", "protocolVersion": "1.0.1"}]}
        assert w.card_endpoint(card) == ("https://a/v1", "1.0")
        assert w.card_endpoint({"url": "https://a/x", "protocolVersion": "0.3.0"}) == ("https://a/x", "0.3")
        with pytest.raises(w.A2AError):
            w.card_endpoint({"supportedInterfaces": [{"url": "https://a", "protocolBinding": "GRPC",
                                                       "protocolVersion": "1.0"}]})


# ---------------------------------------------------------------------------
# Through the gateway
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("peer_version", ["1.0", "0.3"])
@pytest.mark.parametrize("client_version", ["1.0", "0.3"])
async def test_every_version_pair(client, admin_token, db_session, peer, peer_version, client_version):
    peer.version = peer_version
    await _ready(client, admin_token)
    agent = await _agent(client, admin_token)
    r = await _send(client, agent, client_version)
    assert r.status_code == 200, r.text
    task = _task_of(r, client_version)
    assert task["id"] == peer.task_id
    if client_version == "1.0":
        assert task["status"]["state"] == "TASK_STATE_COMPLETED" and task["artifacts"][0]["parts"] == [
            {"text": "summary ready"}]
    else:
        assert task["kind"] == "task" and task["status"]["state"] == "completed"
        assert task["artifacts"][0]["parts"] == [{"kind": "text", "text": "summary ready"}]

    action = (await db_session.execute(select(AgentAction).where(AgentAction.agent_id == agent["id"]))).scalar_one()
    assert (action.tool_name, action.action_type, action.policy_check_result, action.executed_by) == (
        "a2a.helper", "a2a.send", "allowed", "a2a_gateway")
    owner = (await db_session.execute(select(A2ATask).where(A2ATask.task_id == peer.task_id))).scalar_one()
    assert owner.agent_id == agent["id"]
    # and it is PVP evidence like any other action
    from app.pvp.orchestrator import PVPOrchestrator
    evidence = PVPOrchestrator.action_out(action)
    assert evidence.executed_by == "a2a_gateway" and evidence.problems() == []   # witnessed, not unsigned


@pytest.mark.asyncio
async def test_the_served_card_is_provenzas(client, admin_token, peer):
    await _ready(client, admin_token)
    agent = await _agent(client, admin_token)
    url = f"{GW}/helper/.well-known/agent-card.json"
    v1 = await client.get(url, headers={"X-Agent-Key": agent["api_key"], "A2A-Version": "1.0"})
    assert v1.status_code == 200, v1.text
    card = v1.json()
    assert card["supportedInterfaces"][0]["url"].endswith("/api/v1/a2a-gateway/helper")
    assert card["capabilities"] == {"streaming": False, "pushNotifications": False, "extendedAgentCard": False}
    assert [s["id"] for s in card["skills"]] == ["summarize"]
    assert ENDPOINT not in v1.text and "peerKey" not in v1.text and SECRET not in v1.text
    legacy = (await client.get(url, headers={"X-Agent-Key": agent["api_key"]})).json()
    assert legacy["protocolVersion"] == "0.3.0" and legacy["url"].endswith("/a2a-gateway/helper")


@pytest.mark.asyncio
async def test_unreachable_peer_looks_like_no_peer(client, admin_token, peer):
    p = await _peer(client, admin_token)
    await client.post(f"{PEERS}/{p['id']}/sync", headers=auth_headers(admin_token))
    agent = await _agent(client, admin_token)
    assert (await _send(client, agent)).status_code == 404               # synced, not approved
    await client.post(f"{PEERS}/{p['id']}/approve", headers=auth_headers(admin_token))
    outsider = await _agent(client, admin_token, tools=("db.read",))
    assert (await _send(client, outsider)).status_code == 404            # approved, not in its rights
    card = await client.get(f"{GW}/helper/.well-known/agent-card.json", headers={"X-Agent-Key": outsider["api_key"]})
    assert card.status_code == 404
    nope = await _rpc(client, agent, "SendMessage", {"message": _msg("1.0")}, slug="nope")
    assert nope.status_code == 404                                       # does not exist: same answer


@pytest.mark.asyncio
async def test_a_task_belongs_to_its_creator(client, admin_token, peer):
    await _ready(client, admin_token)
    alice = await _agent(client, admin_token)
    mallory = await _agent(client, admin_token)
    task_id = _task_of(await _send(client, alice), "1.0")["id"]
    calls_before = len(peer.calls)

    for method, params in (("GetTask", {"id": task_id}), ("CancelTask", {"id": task_id}),
                           ("SendMessage", {"message": _msg("1.0", task_id=task_id)})):
        r = await _rpc(client, mallory, method, params)
        assert r.json()["error"]["code"] == w.TASK_NOT_FOUND, (method, r.text)
    assert len(peer.calls) == calls_before                            # nothing reached the peer

    got = await _rpc(client, alice, "GetTask", {"id": task_id})
    assert got.json()["result"]["id"] == task_id
    canceled = await _rpc(client, alice, "CancelTask", {"id": task_id})
    assert canceled.json()["result"]["status"]["state"] == "TASK_STATE_CANCELED"


@pytest.mark.asyncio
async def test_a_peer_handing_out_someone_elses_task_is_withheld(client, admin_token, peer):
    await _ready(client, admin_token)
    alice = await _agent(client, admin_token)
    bob = await _agent(client, admin_token)
    await _send(client, alice)
    r = await _send(client, bob)                                    # the peer answers with alice's task id
    assert r.json()["error"]["code"] == w.INVALID_AGENT_RESPONSE
    assert "summary ready" not in r.text


@pytest.mark.asyncio
async def test_changed_card_is_refused_then_drifts(client, admin_token, peer):
    p = await _ready(client, admin_token)
    agent = await _agent(client, admin_token)
    peer.endpoint = "https://elsewhere.example.com/a2a"             # the card now sends traffic elsewhere
    r = await _send(client, agent)
    err = r.json()["error"]
    assert err["code"] == -32000 and "card changed" in err["data"]["reason"]
    assert not peer.calls
    sync = await client.post(f"{PEERS}/{p['id']}/sync", headers=auth_headers(admin_token))
    assert sync.json()["changed"] is True and sync.json()["status"] == "drifted"
    assert (await _send(client, agent)).status_code == 404           # no longer served until re-approved


@pytest.mark.asyncio
async def test_denied_by_policy_is_recorded_and_not_sent(client, admin_token, db_session, peer):
    await _ready(client, admin_token)
    agent = await _agent(client, admin_token)
    r = await client.post("/api/v1/agents/policies/", json={"name": "no a2a", "agent_id": agent["id"],
                                                            "rules": {"deny_tools": ["a2a.helper"]}},
                          headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    r = await _send(client, agent)
    err = r.json()["error"]
    assert err["code"] == -32000 and err["data"]["action_id"]
    action = (await db_session.execute(select(AgentAction).where(AgentAction.agent_id == agent["id"]))).scalar_one()
    assert action.policy_check_result == "denied" and action.executed_by == "a2a_gateway"
    assert not peer.calls


@pytest.mark.asyncio
async def test_refused_operations_and_versions(client, admin_token, peer):
    await _ready(client, admin_token)
    agent = await _agent(client, admin_token)
    push = await _rpc(client, agent, "SendMessage", {"message": _msg("1.0"), "configuration": {
        "taskPushNotificationConfig": {"url": "https://hook.example"}}})
    assert push.json()["error"]["code"] == w.PUSH_NOT_SUPPORTED
    assert (await _rpc(client, agent, "SendStreamingMessage", {})).json()["error"]["code"] == w.UNSUPPORTED_OPERATION
    assert (await _rpc(client, agent, "message/stream", {}, "0.3")).json()["error"]["code"] == w.UNSUPPORTED_OPERATION
    assert (await _rpc(client, agent, "message/send", {}, "1.0")).json()["error"]["code"] == -32601   # wrong era
    r = await client.post(f"{GW}/helper", json={"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {}},
                          headers={"X-Agent-Key": agent["api_key"], "A2A-Version": "2.0"})
    assert r.json()["error"]["code"] == w.VERSION_NOT_SUPPORTED
    assert not peer.calls


@pytest.mark.asyncio
async def test_only_an_agent_key_opens_it(client, admin_token, peer):
    await _ready(client, admin_token)
    r = await client.post(f"{GW}/helper", json={"jsonrpc": "2.0", "id": 1, "method": "GetTask", "params": {"id": "x"}},
                          headers=auth_headers(admin_token))
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Administration
# ---------------------------------------------------------------------------

class TestAdmin:
    @pytest.mark.asyncio
    async def test_secret_never_returned_and_card_pinned(self, client, admin_token, peer):
        p = await _ready(client, admin_token)
        listed = await client.get(PEERS, headers=auth_headers(admin_token))
        assert SECRET not in listed.text
        row = listed.json()[0]
        assert row["has_secret"] and row["served"] and row["protocol_version"] == "1.0"
        assert row["endpoint_url"] == ENDPOINT and "signatures" not in row["card"]

    @pytest.mark.asyncio
    async def test_admin_only(self, client, approver_token, peer):
        assert (await client.get(PEERS, headers=auth_headers(approver_token))).status_code == 403

    @pytest.mark.asyncio
    async def test_private_card_url_is_refused(self, client, admin_token, peer):
        r = await client.post(PEERS, json={"slug": "x", "name": "x", "card_url": "http://169.254.169.254/card"},
                              headers=auth_headers(admin_token))
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_approve_needs_a_sync_and_sync_failure_is_502(self, client, admin_token, peer):
        p = await _peer(client, admin_token)
        assert (await client.post(f"{PEERS}/{p['id']}/approve", headers=auth_headers(admin_token))).status_code == 409
        peer.down = True
        r = await client.post(f"{PEERS}/{p['id']}/sync", headers=auth_headers(admin_token))
        assert r.status_code == 502 and r.json()["detail"]["context"]["reason"] == "upstream.unreachable"
