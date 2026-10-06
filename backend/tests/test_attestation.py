# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Workload attestation with Kubernetes ServiceAccount tokens: agents of a role
that requires it act only with a current, passing attestation; the token is
bound to the agent by the agent's own signature over a server challenge.
"""

import hashlib
import json
import time
from datetime import timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select, update

from app.models.attestation import AgentAttestation
from app.models.audit_log import AIAuditLog
from app.services import attestation as svc
from tests.conftest import auth_headers
from app.models.agent_action import AgentIncident
from tests.enrollment_helpers import enroll, new_keys, rotate, sign_both

ISSUER = "https://kubernetes.default.svc.cluster.local"
P = "/api/v1/attestation"
A = "/api/v1/agents"
T = "/api/v1/teams"


class Cluster:
    """A cluster's service-account issuer: signs projected tokens."""

    def __init__(self, kid="sa-key-1"):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = kid
        jwk = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update(kid=kid, use="sig", alg="RS256")
        self.jwks = {"keys": [jwk]}

    def token(self, ns="agents", sa="billing", aud="provenza", pod=True, **over):
        now = int(time.time())
        k8s = {"namespace": ns, "serviceaccount": {"name": sa, "uid": "sa-uid"}}
        if pod:
            k8s["pod"] = {"name": f"{sa}-7f9c", "uid": "pod-uid-1"}
            k8s["node"] = {"name": "node-1", "uid": "node-uid"}
        claims = {"iss": ISSUER, "sub": f"system:serviceaccount:{ns}:{sa}", "aud": [aud], "iat": now,
                  "nbf": now, "exp": now + 3600, "kubernetes.io": k8s, **over}
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": self.kid})


@pytest.fixture
def cluster():
    svc._jwks_cache.clear()
    svc._last_refetch.clear()
    return Cluster()


def _code(r):
    d = r.json().get("detail")
    return d["code"] if isinstance(d, dict) else d


async def _policy(client, token, cluster, **kw):
    body = {"name": "prod-cluster", "issuer": ISSUER, "jwks": cluster.jwks, "namespaces": ["agents"], **kw}
    r = await client.post(f"{P}/policies", json=body, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _attested_agent(client, admin_token, cluster, **policy_kw):
    """A policy, a role that requires it, and an agent enrolled with the role."""
    pol = await _policy(client, admin_token, cluster, **policy_kw)
    r = await client.post(f"{T}/roles", headers=auth_headers(admin_token), json={
        "name": "prod-runner", "capabilities": ["read"], "allowed_tools": ["kb.search"],
        "require_attestation": True, "attestation_policy_id": pol["id"]})
    assert r.status_code == 200, r.text
    agent = await enroll(client, admin_token, "prod-bot", role_id=r.json()["id"])
    return pol, r.json(), agent


async def attest(client, agent, token, *, keys=None, challenge=None):
    hdr = {"X-Agent-Key": agent["api_key"]}
    if challenge is None:
        r = await client.post(f"{A}/{agent['id']}/attestation/challenge", headers=hdr)
        assert r.status_code == 200, r.text
        challenge = r.json()["challenge"]
    stmt = {"type": "provenza.agent.attestation", "v": 1, "challenge": challenge, "agent_id": agent["id"],
            "kind": "k8s_sa", "evidence_sha256": hashlib.sha256(token.encode()).hexdigest()}
    s, pq = sign_both(keys or agent, stmt)
    return await client.post(f"{A}/{agent['id']}/attestation", headers=hdr, json={
        "challenge": challenge, "kind": "k8s_sa", "evidence": token, "signature": s, "pq_signature": pq})


async def act(client, agent):
    return await client.post(f"{A}/actions/check", headers={"X-Agent-Key": agent["api_key"]},
                             json={"agent_id": agent["id"], "tool_name": "kb.search", "input": {}})


async def test_an_agent_acts_only_after_attesting(client, admin_token, cluster):
    pol, role, agent = await _attested_agent(client, admin_token, cluster)
    r = await act(client, agent)
    assert r.status_code == 403 and r.json()["detail"] == "agent.attestation_required"

    r = await attest(client, agent, cluster.token())
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["ok"] is True and res["policy"] == "prod-cluster"
    assert res["identity"]["namespace"] == "agents" and res["identity"]["pod_uid"] == "pod-uid-1"

    r = await act(client, agent)
    assert r.status_code == 200 and r.json()["decision"] == "allowed", r.text

    st = (await client.get(f"{P}/agents/{agent['id']}", headers=auth_headers(admin_token))).json()
    assert st["required"] and st["refusal"] is None and st["current"]["ok"]


async def test_an_attestation_never_outlives_its_token(client, admin_token, cluster):
    _, _, agent = await _attested_agent(client, admin_token, cluster)  # validity 60 minutes
    exp = int(time.time()) + 300
    res = (await attest(client, agent, cluster.token(exp=exp))).json()
    assert res["ok"] is True
    from datetime import datetime
    assert datetime.fromisoformat(res["valid_until"]).timestamp() <= exp


async def test_every_attempt_is_audited(client, admin_token, cluster, db_session):
    _, _, agent = await _attested_agent(client, admin_token, cluster)
    await attest(client, agent, cluster.token())                       # passes
    await attest(client, agent, cluster.token(ns="other"))             # evidence refused
    await attest(client, agent, cluster.token(), keys=new_keys())      # not the agent's signature
    await attest(client, agent, cluster.token(), challenge="ab" * 32)  # no such challenge
    actions = [a for (a,) in (await db_session.execute(select(AIAuditLog.action).where(
        AIAuditLog.entity_type == "agent", AIAuditLog.entity_id == agent["id"],
        AIAuditLog.action.like("attest%")).order_by(AIAuditLog.seq))).all()]
    assert actions == ["attested", "attestation_failed", "attestation_refused", "attestation_refused"], actions


async def test_the_enrollment_token_names_the_audience(client, admin_token, cluster):
    pol = await _policy(client, admin_token, cluster, audience="provenza-prod")
    role = (await client.post(f"{T}/roles", headers=auth_headers(admin_token), json={
        "name": "r", "require_attestation": True, "attestation_policy_id": pol["id"]})).json()
    tok = (await client.post("/api/v1/agent-enrollment/tokens", headers=auth_headers(admin_token),
                             json={"name": "a", "role_id": role["id"]})).json()
    assert tok["attestation"]["audience"] == "provenza-prod" and tok["attestation"]["policy"] == "prod-cluster"
    ch = (await client.post("/api/v1/agent-enrollment/challenge", json={"token": tok["token"]})).json()
    assert ch["attestation"]["audience"] == "provenza-prod"
    # and the attestation challenge repeats it, so the agent can check its token first
    agent = await enroll(client, admin_token, "aud-bot", role_id=role["id"])
    r = await client.post(f"{A}/{agent['id']}/attestation/challenge", headers={"X-Agent-Key": agent["api_key"]})
    assert r.json()["audience"] == "provenza-prod"
    res = (await attest(client, agent, cluster.token(aud="provenza"))).json()
    assert res["reason"] == "attestation.wrong_audience"


async def test_wrong_workloads_and_tokens_fail(client, admin_token, cluster):
    _, _, agent = await _attested_agent(client, admin_token, cluster)
    other_cluster = Cluster()
    for token, reason in (
        (cluster.token(ns="kube-system", sa="default"), "attestation.workload_not_allowed"),
        (cluster.token(aud="https://kubernetes.default.svc"), "attestation.wrong_audience"),
        (cluster.token(pod=False), "attestation.not_pod_bound"),
        (other_cluster.token(), "attestation.bad_signature"),
        (cluster.token(exp=int(time.time()) - 600, iat=int(time.time()) - 4000, nbf=int(time.time()) - 4000),
         "attestation.token_expired"),
    ):
        r = await attest(client, agent, token)
        assert r.status_code == 200, r.text
        assert r.json()["ok"] is False and r.json()["reason"] == reason, (reason, r.json())
    assert (await act(client, agent)).status_code == 403
    rows = (await client.get(f"{P}/records?agent_id={agent['id']}", headers=auth_headers(admin_token))).json()
    assert len(rows) == 5 and not any(x["ok"] for x in rows)
    assert rows[-1]["identity"] == {"workload": "kube-system/default"}  # helps fix the policy


async def test_a_token_is_bound_to_the_agent_and_the_challenge(client, admin_token, cluster):
    _, _, agent = await _attested_agent(client, admin_token, cluster)
    token = cluster.token()
    # someone holding the token but not the agent's key
    r = await attest(client, agent, token, keys=new_keys())
    assert r.status_code == 401 and _code(r) == "attestation.bad_agent_signature"
    # the challenge was spent by that attempt
    hdr = {"X-Agent-Key": agent["api_key"]}
    ch = (await client.post(f"{A}/{agent['id']}/attestation/challenge", headers=hdr)).json()["challenge"]
    assert (await attest(client, agent, token, challenge=ch)).status_code == 200
    r = await attest(client, agent, token, challenge=ch)
    assert r.status_code == 401 and _code(r) == "enrollment.bad_challenge"
    # a user session cannot attest in the agent's name
    r = await client.post(f"{A}/{agent['id']}/attestation/challenge", headers=auth_headers(admin_token))
    assert r.status_code == 403


async def test_a_new_or_revoked_key_takes_the_attestation_with_it(client, admin_token, cluster):
    _, _, agent = await _attested_agent(client, admin_token, cluster)
    # rotating the key stays open before attesting (and so does attesting)
    r, new = await rotate(client, agent)
    assert r.status_code == 200, r.text
    agent = {**agent, **new}
    assert (await attest(client, agent, cluster.token())).json()["ok"]
    assert (await act(client, agent)).status_code == 200

    # the attestation was signed by a key the agent no longer has
    r, new = await rotate(client, agent)
    assert r.status_code == 200, r.text
    agent = {**agent, **new}
    r = await act(client, agent)
    assert r.status_code == 403 and r.json()["detail"] == "agent.attestation_required"
    assert (await attest(client, agent, cluster.token())).json()["ok"]
    assert (await act(client, agent)).status_code == 200

    # a revoked key: the attestation goes, and no new one without a key
    keys = (await client.get(f"{A}/{agent['id']}/signing-keys", headers=auth_headers(admin_token))).json()
    current = next(k for k in keys if not k["retired_at"])
    r = await client.post(f"{A}/{agent['id']}/signing-keys/{current['id']}/revoke", headers=auth_headers(admin_token),
                          json={"reason": "leaked"})
    assert r.status_code == 200, r.text
    assert (await act(client, agent)).status_code == 403
    r = await client.post(f"{A}/{agent['id']}/attestation/challenge", headers={"X-Agent-Key": agent["api_key"]})
    assert r.status_code == 403 and _code(r) == "agent.key_required"


async def test_one_token_attests_one_agent(client, admin_token, cluster):
    pol, role, first = await _attested_agent(client, admin_token, cluster)
    second = await enroll(client, admin_token, "copycat", role_id=role["id"])
    token = cluster.token()
    assert (await attest(client, first, token)).json()["ok"]
    assert (await attest(client, first, token)).json()["ok"]  # the same agent again: fine
    res = (await attest(client, second, token)).json()
    assert res["ok"] is False and res["reason"] == "attestation.token_reused"


async def test_others_cannot_use_up_an_agents_attempts(client, admin_token, cluster):
    _, _, agent = await _attested_agent(client, admin_token, cluster)
    for _ in range(35):
        r = await client.post(f"{A}/{agent['id']}/attestation/challenge", headers=auth_headers(admin_token))
        assert r.status_code == 403
    r = await client.post(f"{A}/{agent['id']}/attestation/challenge", headers={"X-Agent-Key": agent["api_key"]})
    assert r.status_code == 200, r.text


async def test_a_borrowed_key_still_leaves_an_incident(client, admin_token, cluster, db_session):
    _, role, agent = await _attested_agent(client, admin_token, cluster)  # not attested
    other = await enroll(client, admin_token, "victim", capabilities=["read"], allowed_tools=["kb.search"])
    r = await client.post(f"{A}/actions/check", headers={"X-Agent-Key": agent["api_key"]},
                          json={"agent_id": other["id"], "tool_name": "kb.search", "input": {}})
    assert r.status_code == 403 and "agent_mismatch" in r.json()["detail"]
    hit = (await db_session.execute(select(AgentIncident).where(
        AgentIncident.agent_id == agent["id"], AgentIncident.incident_type == "agent_impersonation_attempt"))).first()
    assert hit is not None


async def test_attestations_lapse(client, admin_token, cluster, db_session):
    pol, _, agent = await _attested_agent(client, admin_token, cluster)
    assert (await attest(client, agent, cluster.token())).json()["ok"]
    assert (await act(client, agent)).status_code == 200

    # changing the policy re-opens the question
    r = await client.patch(f"{P}/policies/{pol['id']}", headers=auth_headers(admin_token),
                           json={"namespaces": ["agents", "batch"]})
    assert r.status_code == 200, r.text
    assert (await act(client, agent)).status_code == 403
    assert (await attest(client, agent, cluster.token())).json()["ok"]
    assert (await act(client, agent)).status_code == 200

    # and time does
    await db_session.execute(update(AgentAttestation).where(AgentAttestation.agent_id == agent["id"]).values(
        valid_until=AgentAttestation.created_at - timedelta(seconds=1)))
    await db_session.flush()
    r = await act(client, agent)
    assert r.status_code == 403 and r.json()["detail"] == "agent.attestation_required"


async def test_user_sessions_cannot_bypass_it(client, admin_token, cluster):
    """In a relaxed organization a user session may act in an agent's name:
    the attestation requirement still holds, on every agent-acting route."""
    _, _, agent = await _attested_agent(client, admin_token, cluster)
    h = auth_headers(admin_token)
    for path, body in (
        (f"{A}/actions/check", {"agent_id": agent["id"], "tool_name": "kb.search", "input": {}}),
        ("/api/v1/memory/write", {"agent_id": agent["id"], "namespace": "n", "content": "x", "source": "user"}),
        ("/api/v1/memory/verify", {"agent_id": agent["id"], "items": [{"sha256": "0" * 64}]}),
        ("/api/v1/a2a/receive", {"agent_id": agent["id"], "message_id": 1}),
        # other spellings the endpoint would read as the same id
        ("/api/v1/memory/write", {"agent_id": float(agent["id"]), "namespace": "n", "content": "x", "source": "user"}),
        ("/api/v1/memory/write", {"agent_id": str(agent["id"]), "namespace": "n", "content": "x", "source": "user"}),
    ):
        r = await client.post(path, headers=h, json=body)
        assert r.status_code == 403 and r.json()["detail"] == "agent.attestation_required", (path, r.text)


async def test_roles_and_policies_rules(client, admin_token, approver_token, cluster):
    h = auth_headers(admin_token)
    r = await client.post(f"{T}/roles", headers=h, json={"name": "x", "require_attestation": True})
    assert r.status_code == 422 and _code(r) == "role.attestation_policy_required"
    r = await client.post(f"{P}/policies", headers=h, json={"name": "any", "issuer": ISSUER, "jwks": cluster.jwks})
    assert r.status_code == 422 and _code(r) == "attestation.no_workload_rule"
    r = await client.post(f"{P}/policies", headers=h,
                          json={"name": "http", "issuer": "http://k8s", "jwks": cluster.jwks, "namespaces": ["a"]})
    assert r.status_code == 422 and _code(r) == "attestation.https_required"
    r = await client.post(f"{P}/policies", headers=h,
                          json={"name": "bad", "issuer": ISSUER, "jwks": {"keys": []}, "namespaces": ["a"]})
    assert r.status_code == 422 and _code(r) == "attestation.bad_jwks"
    r = await client.post(f"{P}/policies", headers=h, json={
        "name": "api", "issuer": ISSUER, "audience": ISSUER, "jwks": cluster.jwks, "namespaces": ["a"]})
    assert r.status_code == 422 and _code(r) == "attestation.audience_is_api_server"
    r = await client.post(f"{P}/policies", headers=auth_headers(approver_token),
                          json={"name": "p", "issuer": ISSUER, "jwks": cluster.jwks, "namespaces": ["a"]})
    assert r.status_code == 403

    pol, role, _ = await _attested_agent(client, admin_token, cluster)
    r = await client.delete(f"{P}/policies/{pol['id']}", headers=h)
    assert r.status_code == 409 and _code(r) == "attestation.policy_in_use"
    listed = (await client.get(f"{P}/policies", headers=h)).json()
    assert listed[0]["roles"] == 1 and listed[0]["jwks_keys"] == [cluster.kid]

    # dry run: an admin checks a token before rolling it out
    r = await client.post(f"{P}/policies/{pol['id']}/test", headers=h, json={"token": cluster.token(ns="other")})
    assert r.json()["ok"] is False and r.json()["reason"] == "attestation.workload_not_allowed"
    r = await client.post(f"{P}/policies/{pol['id']}/test", headers=h, json={"token": cluster.token()})
    assert r.json()["ok"] is True and r.json()["identity"]["service_account"] == "billing"


async def test_without_a_required_role_nothing_changes(client, admin_token, cluster):
    agent = await enroll(client, admin_token, "plain", capabilities=["read"], allowed_tools=["kb.search"])
    assert (await act(client, agent)).status_code == 200
    r = await client.post(f"{A}/{agent['id']}/attestation/challenge", headers={"X-Agent-Key": agent["api_key"]})
    assert r.status_code == 409 and _code(r) == "attestation.no_policy"


async def test_jwks_by_discovery_and_key_rotation(client, admin_token, cluster, monkeypatch):
    calls = []
    served = {"jwks": cluster.jwks}

    async def fake_fetch(url):
        calls.append(url)
        if url.endswith("/.well-known/openid-configuration"):
            return {"issuer": ISSUER, "jwks_uri": ISSUER + "/openid/v1/jwks"}
        return served["jwks"]

    monkeypatch.setattr(svc, "_fetch_json", fake_fetch)
    pol = await _policy(client, admin_token, cluster, jwks=None)
    r = await client.post(f"{P}/policies/{pol['id']}/test", headers=auth_headers(admin_token),
                          json={"token": cluster.token()})
    assert r.json()["ok"] is True, r.json()
    n = len(calls)
    await client.post(f"{P}/policies/{pol['id']}/test", headers=auth_headers(admin_token),
                      json={"token": cluster.token()})
    assert len(calls) == n  # discovery result and keys both cached (an hour)

    # the cluster rotates its signing key: an unknown kid refetches once
    rotated = Cluster(kid="sa-key-2")
    served["jwks"] = {"keys": cluster.jwks["keys"] + rotated.jwks["keys"]}
    r = await client.post(f"{P}/policies/{pol['id']}/test", headers=auth_headers(admin_token),
                          json={"token": rotated.token()})
    assert r.json()["ok"] is True, r.json()


async def test_a_role_without_a_policy_refuses(client, admin_token, cluster, db_session):
    """Roles flagged before attestation existed: refused until a policy is named."""
    from app.models.team import RoleTemplate

    pol, role, agent = await _attested_agent(client, admin_token, cluster)
    await db_session.execute(update(RoleTemplate).where(RoleTemplate.id == role["id"]).values(
        attestation_policy_id=None))
    await db_session.flush()
    r = await act(client, agent)
    assert r.status_code == 403 and r.json()["detail"] == "agent.attestation_policy_missing"
    rows = (await db_session.execute(select(AgentAttestation))).scalars().all()
    assert rows == []
