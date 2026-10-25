"""
The egress proxy as an enforcement point, server side (docs/pvp/edge.md,
section 4; app/pvp/witness.py): its own key, registered once; its signed
receipt kept as the action's witness - in the sealed evidence, checked
offline - only when it names exactly the recorded action; its own refusals
under the signed policy recorded through the check; and the signed policy
releases it fetches to verify itself.
"""

import base64
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from app.core.agent_signing import canonical_bytes, content_hash, key_fingerprint
from app.models.agent_action import AgentAction, AgentIncident
from app.pvp import signed_policy
from tests.conftest import auth_headers
from tests.test_egress_proxy import P, _check, _px, _redeem, _setup, charge, tool
from tests.test_policy_release import R, _release


@pytest.fixture(autouse=True)
def _fresh_cache():
    signed_policy.forget()
    yield
    signed_policy.forget()


class ProxyKey:
    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        self.public = base64.b64encode(self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        self.seq, self.prev = 0, ""

    def receipt(self, **fields):
        self.seq += 1
        st = {"type": "provenza.proxy.receipt", "v": 1, "agent_signature": "not_presented", "policy": None,
              "log": {"seq": self.seq, "prev": self.prev}, "issued_at": int(time.time()), **fields}
        self.prev = "f" * 64
        return {"statement": st, "signature": base64.b64encode(self.key.sign(canonical_bytes(st))).decode()}


def _fields(chk, agent, desc, output, decision="allowed"):
    return {"check_id": chk["check_id"], "agent_id": agent["id"], "chain_id": None, "action_type": "proxy",
            "tool_name": "proxy." + desc["route"], "input_sha256": content_hash(desc),
            "output_sha256": content_hash(output), "decision": decision}


async def _registered(client, proxy):
    k = ProxyKey()
    r = await client.post(f"{P}/key", json={"public_key": k.public}, headers=_px(proxy))
    assert r.status_code == 200 and r.json()["key_fingerprint"] == key_fingerprint(k.public), r.text
    return k


@pytest.mark.asyncio
async def test_the_proxy_registers_its_own_key_once(client, admin_token):
    _, proxy, _ = await _setup(client, admin_token)
    k = await _registered(client, proxy)
    assert (await client.post(f"{P}/key", json={"public_key": k.public}, headers=_px(proxy))).status_code == 200
    r = await client.post(f"{P}/key", json={"public_key": ProxyKey().public}, headers=_px(proxy))
    assert r.status_code == 409 and r.json()["detail"] == "egress.proxy_key_changed"
    r = await client.post(f"{P}/key", json={"public_key": "A" * 44}, headers=_px(proxy))
    assert r.status_code == 422
    assert (await client.post(f"{P}/key", json={"public_key": k.public})).status_code == 401


@pytest.mark.asyncio
async def test_a_receipt_becomes_the_actions_witness(client, admin_token, db_session):
    _, proxy, agent = await _setup(client, admin_token)
    k = await _registered(client, proxy)
    chk = await _check(client, agent, charge())
    info = (await client.post(f"{P}/check-info", json={"check_id": chk["check_id"]}, headers=_px(proxy))).json()
    assert (info["agent_id"], info["tool_name"], info["input_sha256"], info["approval"]) == (
        agent["id"], "proxy.stripe", content_hash(charge()), None)
    assert (await _redeem(client, proxy, chk["check_id"], charge())).json()["allowed"]
    output = {"status": 200, "response_sha256": "b" * 64, "response_bytes": 512}
    receipt = k.receipt(**_fields(chk, agent, charge(), output))
    done = await client.post(f"{P}/complete", json={"check_id": chk["check_id"], **output, "receipt": receipt},
                             headers=_px(proxy))
    assert done.status_code == 200, done.text
    action = await db_session.get(AgentAction, done.json()["action_id"])
    assert action.witness["key_fingerprint"] == key_fingerprint(k.public)
    assert action.evidence["witness"]["statement"] == receipt["statement"]

    doc = (await client.get(f"/api/v1/pvp/receipts/{action.id}", headers=auth_headers(admin_token))).json()
    a, _, _ = tool.check_receipt(doc, tool.Trust(), proxy_fps=[key_fingerprint(k.public)])
    assert a["witness"]["statement"]["check_id"] == chk["check_id"]
    with pytest.raises(tool.Fail, match="not one of the keys"):
        tool.check_receipt(doc, tool.Trust(), proxy_fps=["SHA256:other"])
    doc["action"]["witness"]["statement"]["output_sha256"] = "0" * 64
    with pytest.raises(tool.Fail):
        tool.check_receipt(doc, tool.Trust())


@pytest.mark.asyncio
async def test_a_receipt_for_something_else_is_not_kept(client, admin_token, db_session, org_and_users):
    _, proxy, agent = await _setup(client, admin_token)
    k = await _registered(client, proxy)
    chk = await _check(client, agent, charge())
    await _redeem(client, proxy, chk["check_id"], charge())
    output = {"status": 200, "response_sha256": None, "response_bytes": 0}
    other = dict(output, status=500)
    done = await client.post(f"{P}/complete", json={"check_id": chk["check_id"], **output,
                                                   "receipt": k.receipt(**_fields(chk, agent, charge(), other))},
                             headers=_px(proxy))
    action = await db_session.get(AgentAction, done.json()["action_id"])
    assert action.witness is None and action.evidence.get("witness") is None
    incident = (await db_session.execute(select(AgentIncident).where(
        AgentIncident.agent_id == agent["id"], AgentIncident.incident_type == "witness_mismatch"))).scalar_one()
    assert "mismatch:output_sha256" in incident.details["problems"]


@pytest.mark.asyncio
async def test_the_proxy_refuses_on_its_own_and_it_is_recorded(client, admin_token, db_session):
    _, proxy, agent = await _setup(client, admin_token)
    k = await _registered(client, proxy)
    chk = await _check(client, agent, charge())
    assert chk["decision"] == "allowed"
    receipt = k.receipt(**_fields(chk, agent, charge(), None, "denied"))
    r = await client.post(f"{P}/redeem", json={"check_id": chk["check_id"], **charge(), "enforcement": {
        "decision": "denied", "reason": "agent #9 is not in the signed policy (release #4)", "receipt": receipt}},
        headers=_px(proxy))
    assert r.status_code == 200 and r.json()["allowed"] is False, r.text
    action = await db_session.get(AgentAction, r.json()["action_id"])
    assert action.policy_check_result == "denied" and action.reason.startswith(
        "refused by the egress proxy under the signed policy: agent #9")
    assert action.witness["statement"]["decision"] == "denied"
    # the check is spent: it cannot be redeemed again without the proxy's verdict
    assert (await _redeem(client, proxy, chk["check_id"], charge())).status_code == 409


@pytest.mark.asyncio
async def test_the_proxy_fetches_releases_to_verify_itself(client, admin_token):
    _, proxy, agent = await _setup(client, admin_token)
    k = await _registered(client, proxy)
    assert (await client.get(f"{P}/policy-release", headers=_px(proxy))).json() == {"current": None, "chain": []}
    await _release(client, admin_token)
    await _release(client, admin_token)
    got = (await client.get(f"{P}/policy-release", headers=_px(proxy))).json()
    assert got["current"] == 2 and [d["release"]["number"] for d in got["chain"]] == [1, 2]
    for doc in got["chain"]:
        tool.check_release(doc)
    proxies = got["chain"][1]["manifest"]["egress_proxies"]
    assert proxies[str(proxy["id"])]["key_fingerprint"] == key_fingerprint(k.public)
    after = (await client.get(f"{P}/policy-release", params={"after": 1}, headers=_px(proxy))).json()
    assert [d["release"]["number"] for d in after["chain"]] == [2]
    assert (await client.get(f"{P}/policy-release", params={"after": 2}, headers=_px(proxy))).json()["chain"] == []
    # the mediated check names the agent the proxy judges
    r = await client.post(f"{P}/check", json=charge(), headers={**_px(proxy), "X-Agent-Key": agent["api_key"]})
    assert r.json()["agent_id"] == agent["id"]
    assert (await client.get(f"{R}/state", headers=auth_headers(admin_token))).status_code == 200
