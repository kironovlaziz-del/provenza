"""
When the server was unreachable (docs/pvp/edge.md, sections 6-7;
app/pvp/proxy_offline.py): what an egress proxy did offline comes back as
actions with their evidence; its local kill switch is reported with a
reconciliation report signed by its key, each difference an incident; the
quorum of the release it held before the outage signs the lift, which the
proxy checks itself (proxy/internal/trust/lift.go, sdk/testdata/lift-vectors.json).
"""

import base64
import json
import secrets
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from app.core import webauthn
from app.core.agent_signing import canonical_bytes, content_hash, sign_payload
from app.models.agent_action import AgentAction, AgentIncident
from app.models.ai_incident import AIIncident
from app.models.egress_proxy import ProxyKillSwitch
from app.pvp import signed_policy
from app.pvp.model import PVPActionRequest
from app.pvp.proxy_offline import lift_statement
from tests import signer
from tests.conftest import auth_headers

ROOT = Path(__file__).resolve().parents[2]
LV = json.loads((ROOT / "sdk" / "testdata" / "lift-vectors.json").read_text(encoding="utf-8"))
E = "/api/v1/egress"
P = "/api/v1/egress-proxy"
R = "/api/v1/policy-releases"


@pytest.fixture(autouse=True)
def _fresh_cache():
    signed_policy.forget()
    yield
    signed_policy.forget()


def _raw(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,
                                                          serialization.PublicFormat.Raw)).decode()


def _sign(key: Ed25519PrivateKey, doc) -> str:
    return base64.b64encode(key.sign(canonical_bytes(doc))).decode()


async def _proxy(client, token):
    proxy = (await client.post(f"{E}/proxies", json={"name": "cut-off"}, headers=auth_headers(token))).json()
    key = Ed25519PrivateKey.generate()
    r = await client.post(f"{P}/key", json={"public_key": _raw(key)}, headers={"X-Proxy-Key": proxy["key"]})
    assert r.status_code == 200, r.text
    return proxy, key


async def _release(client, token):
    s = await signer.signer(client, token)
    draft = (await client.post(f"{R}/prepare", headers=auth_headers(token))).json()["draft"]
    ch = (await client.post(f"{R}/{draft['id']}/challenge", headers=auth_headers(token))).json()
    r = await client.post(f"{R}/{draft['id']}/sign", json={"statement": ch["statement"],
                                                           "assertion": s.device.get(ch["challenge"])},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return draft


def _receipt(key, typ, fields, seq=1):
    st = {"type": typ, "v": 1, "issued_at": int(time.time()), "log": {"seq": seq, "prev": ""}, **fields}
    return {"statement": st, "signature": _sign(key, st)}


def test_the_lift_vectors_are_what_the_server_asks_to_sign():
    for s in LV["signatures"] + [LV["approver"], LV["partial_accept"]]:
        st = s["statement"]
        assert st == lift_statement(st["org_id"], st["user_id"], st["proxy_id"], st["report_sha256"], st["accept"],
                                    st["issued_at"])
        key = LV["manifest"]["signers"][str(s["user_id"])]["passkeys"][s["credential_id"]]
        webauthn.verify_assertion_spki(public_key_spki=key["public_key"], alg=int(key["alg"]),
                                       challenge=webauthn.statement_challenge(st), **s["assertion"])


@pytest.mark.asyncio
async def test_a_kill_switch_is_reported_and_the_quorum_lifts_it(client, admin_token, approver_token, db_session):
    proxy, key = await _proxy(client, admin_token)
    pk = {"X-Proxy-Key": proxy["key"]}
    draft = await _release(client, admin_token)
    state = (await client.get(f"{P}/reconciliation", headers=pk)).json()
    assert "signers" in state["manifest"] and "entries" in state["tool_registry"]

    report = {"type": "provenza.reconciliation", "v": 1, "org_id": await proxy_org(db_session, proxy),
              "proxy_id": proxy["id"],
              "engaged_at": int(time.time()) - 600, "reason": "Provenza unreachable for more than 900 s",
              "release_before": {"number": draft["number"], "manifest_sha256": "m" * 64},
              "release_now": {"number": draft["number"], "manifest_sha256": "m" * 64},
              "differences": [
                  {"id": "manifest.agents.9", "area": "manifest", "section": "agents", "key": "9", "label": "agents 9",
                   "before": None, "now": "a" * 64, "signed": False},
                  {"id": "manifest.quorum", "area": "manifest", "section": "quorum", "key": "", "label": "quorum",
                   "before": "b" * 64, "now": "c" * 64, "signed": True}]}
    sha = content_hash(report)
    bad = _receipt(Ed25519PrivateKey.generate(), "provenza.reconciliation", {"report_sha256": sha})
    r = await client.post(f"{P}/kill-switch", json={"report": report, "receipt": bad}, headers=pk)
    assert r.status_code == 422 and r.json()["detail"] == "kill_switch.bad_receipt"
    receipt = _receipt(key, "provenza.reconciliation", {"report_sha256": sha, "engaged_at": report["engaged_at"],
                                                        "differences": 2})
    r = await client.post(f"{P}/kill-switch", json={"report": report, "receipt": receipt}, headers=pk)
    assert r.status_code == 200, r.text
    assert (await client.post(f"{P}/kill-switch", json={"report": report, "receipt": receipt},
                              headers=pk)).status_code == 200
    incidents = (await db_session.execute(select(AIIncident).where(AIIncident.category == "reconciliation"))
                 ).scalars().all()
    assert len(incidents) == 2 and any("without a signed release" in i.summary for i in incidents)

    ks = (await client.get(f"{E}/proxies/{proxy['id']}/kill-switch", headers=auth_headers(admin_token))).json()[
        "kill_switch"]
    assert ks["report_sha256"] == sha and ks["unsigned"] == ["manifest.agents.9"] and ks["quorum"] == 1
    assert ks["can_sign"] is True and ks["signers"] == []

    # every unsigned difference must be accepted
    r = await client.post(f"{E}/proxies/{proxy['id']}/kill-switch/challenge", json={"accept": []},
                          headers=auth_headers(admin_token))
    assert r.status_code == 422 and r.json()["detail"]["code"] == "kill_switch.accept_all"
    r = await client.post(f"{E}/proxies/{proxy['id']}/kill-switch/challenge", json={"accept": ["manifest.nope"]},
                          headers=auth_headers(admin_token))
    assert r.status_code == 422 and r.json()["detail"] == "kill_switch.bad_accept"
    # an approver is not among those who lift
    r = await client.post(f"{E}/proxies/{proxy['id']}/kill-switch/challenge", json={"accept": ["manifest.agents.9"]},
                          headers=auth_headers(approver_token))
    assert r.status_code == 403

    s = await signer.signer(client, admin_token)
    ch = (await client.post(f"{E}/proxies/{proxy['id']}/kill-switch/challenge", json={"accept": ["manifest.agents.9"]},
                            headers=auth_headers(admin_token))).json()
    st = ch["statement"]
    assert st["type"] == "provenza.kill_switch.lift" and st["report_sha256"] == sha and st["proxy_id"] == proxy["id"]
    changed = dict(st, accept=["manifest.agents.9", "manifest.quorum"])
    r = await client.post(f"{E}/proxies/{proxy['id']}/kill-switch/sign",
                          json={"statement": changed, "assertion": s.device.get(ch["challenge"])},
                          headers=auth_headers(admin_token))
    assert r.status_code in (403, 422), r.text
    ch = (await client.post(f"{E}/proxies/{proxy['id']}/kill-switch/challenge", json={"accept": ["manifest.agents.9"]},
                            headers=auth_headers(admin_token))).json()
    r = await client.post(f"{E}/proxies/{proxy['id']}/kill-switch/sign",
                          json={"statement": ch["statement"], "assertion": s.device.get(ch["challenge"])},
                          headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    ks = r.json()["kill_switch"]
    assert len(ks["signers"]) == 1 and ks["can_sign"] is False

    lift = (await client.get(f"{P}/kill-switch/lift", headers=pk)).json()
    assert lift["report_sha256"] == sha and len(lift["signatures"]) == 1
    sig = lift["signatures"][0]
    rel = (await client.get(f"{R}/{draft['id']}", headers=auth_headers(admin_token))).json()
    passkey = rel["manifest"]["signers"][str(sig["user_id"])]["passkeys"][sig["credential_id"]]
    webauthn.verify_assertion_spki(public_key_spki=passkey["public_key"], alg=int(passkey["alg"]),
                                   challenge=webauthn.statement_challenge(sig["statement"]), **sig["assertion"])

    # a new report (a difference undone or added): the signatures were for the old one
    report2 = dict(report, differences=report["differences"][:1])
    sha2 = content_hash(report2)
    receipt2 = _receipt(key, "provenza.reconciliation", {"report_sha256": sha2}, seq=2)
    assert (await client.post(f"{P}/kill-switch", json={"report": report2, "receipt": receipt2},
                              headers=pk)).status_code == 200
    lift = (await client.get(f"{P}/kill-switch/lift", headers=pk)).json()
    assert lift["report_sha256"] == sha2 and lift["signatures"] == []
    assert (await client.post(f"{P}/kill-switch/lifted", json={"report_sha256": sha, "signers": ["1"]},
                              headers=pk)).status_code == 409
    assert (await client.post(f"{P}/kill-switch/lifted", json={"report_sha256": sha2, "signers": ["1"]},
                              headers=pk)).status_code == 200
    assert (await client.get(f"{E}/proxies/{proxy['id']}/kill-switch",
                             headers=auth_headers(admin_token))).json()["kill_switch"] is None
    row = (await db_session.execute(select(ProxyKillSwitch))).scalar_one()
    assert row.status == "lifted" and row.lifted_by == ["1"]


async def proxy_org(db_session, proxy):
    from app.models.egress_proxy import EgressProxy

    return (await db_session.get(EgressProxy, proxy["id"])).org_id


def _offline_entry(client, agent, desc, key, *, decision="allowed", outcome=None, nonce=None, receipt_fields=None):
    nonce = nonce or secrets.token_hex(16)
    req = PVPActionRequest(agent_id=agent["id"], chain_id=None, action_type="proxy", tool_name="proxy." + desc["route"],
                           input=desc, nonce=nonce, issued_at=int(time.time()) - 300)
    payload = req.signed_payload()
    request = {"payload": payload, "signature": sign_payload(payload, agent["private_key"]),
               "public_key": agent["public_key"]}
    outcome = outcome if decision == "allowed" else None
    fields = {"check_id": "offline-" + nonce, "agent_id": agent["id"], "chain_id": None, "action_type": "proxy",
              "tool_name": "proxy." + desc["route"], "input_sha256": content_hash(desc),
              "output_sha256": content_hash(outcome), "decision": decision, "agent_signature": "verified",
              "policy": {"release": 1, "bundle_sha256": "b" * 64}, **(receipt_fields or {})}
    return {"request": request, "descriptor": desc, "decision": decision, "outcome": outcome, "duration_ms": 12,
            "receipt": _receipt(key, "provenza.proxy.receipt", fields), "release": 1, "at": int(time.time())}


@pytest.mark.asyncio
async def test_offline_actions_are_recorded_with_their_evidence(client, admin_token, db_session):
    proxy, key = await _proxy(client, admin_token)
    pk = {"X-Proxy-Key": proxy["key"]}
    agent = (await client.post("/api/v1/agents/register", json={
        "name": "offline-bot", "agent_type": "custom", "capabilities": ["pay"], "allowed_tools": ["proxy.stripe"],
        "allowed_models": [], "max_delegation_depth": 1}, headers=auth_headers(admin_token))).json()
    desc = {"route": "stripe", "method": "POST", "path": "/v1/charges", "query_sha256": None,
            "body_sha256": "d" * 64, "body_bytes": 12}
    outcome = {"status": 201, "response_sha256": "e" * 64, "response_bytes": 14}
    good = _offline_entry(client, agent, desc, key, outcome=outcome)
    refused = _offline_entry(client, agent, desc, key, decision="denied")
    forged = _offline_entry(client, agent, desc, key, outcome=outcome)
    forged["request"]["payload"] = dict(forged["request"]["payload"], issued_at=1)   # not what the agent signed
    bad_receipt = _offline_entry(client, agent, desc, Ed25519PrivateKey.generate(), outcome=outcome)
    other = dict(_offline_entry(client, agent, desc, key, outcome=outcome), descriptor=dict(desc, path="/v1/refunds"))
    r = await client.post(f"{P}/offline-actions", json={"actions": [good, refused, forged, bad_receipt, other, 7]},
                          headers=pk)
    assert r.status_code == 200, r.text
    res = r.json()["results"]
    assert [x["status"] for x in res] == ["recorded", "recorded", "recorded", "recorded", "rejected", "rejected"]
    assert "problems" not in res[0] and "problems" not in res[1]
    assert res[2]["problems"] == ["agent_signature"] and res[3]["problems"] == ["receipt"]

    a = await db_session.get(AgentAction, res[0]["action_id"])
    assert a.executed_by == "egress_proxy" and a.policy_check_result == "allowed" and a.witness is not None
    assert a.output_data == outcome and a.signature and "unreachable" in a.reason
    d = await db_session.get(AgentAction, res[1]["action_id"])
    assert d.policy_check_result == "denied" and d.output_data is None
    incidents = (await db_session.execute(select(AgentIncident).where(
        AgentIncident.incident_type == "offline_action_unverified"))).scalars().all()
    assert len(incidents) == 2
    # handed over twice: recorded once
    again = (await client.post(f"{P}/offline-actions", json={"actions": [good]}, headers=pk)).json()["results"]
    assert again == [{"status": "duplicate", "action_id": res[0]["action_id"]}]
    assert (await client.post(f"{P}/offline-actions", json={"actions": [good]})).status_code == 401
