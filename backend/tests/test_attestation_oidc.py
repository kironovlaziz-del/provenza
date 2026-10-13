# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Runtime attestation beyond Kubernetes, for every agent, bound to one workload:

  - kind "oidc": an OIDC workload identity token (GitHub Actions, Google
    Cloud, Azure, GitLab, SPIFFE) checked against claim rules;
  - the organization's default policy: every agent must attest, not only
    agents of a role that requires it;
  - the first passing attestation binds the agent to its workload (iss +
    sub); another workload with the agent's key is refused, with an incident,
    until an admin releases the binding.
"""

import hashlib
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select

from app.core.k8s_attest import AttestationError
from app.core.oidc_attest import normalize_rules
from app.models.agent_action import AgentIncident
from app.services import attestation as svc
from tests.conftest import auth_headers
from tests.enrollment_helpers import enroll, sign_both

GITHUB = "https://token.actions.githubusercontent.com"
P = "/api/v1/attestation"
A = "/api/v1/agents"
RULES = {"repository": ["acme/agents"], "ref": ["refs/heads/main"]}


class Issuer:
    def __init__(self, iss=GITHUB):
        self.iss = iss
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update(kid="gh-1", use="sig", alg="RS256")
        self.jwks = {"keys": [jwk]}

    def token(self, repository="acme/agents", ref="refs/heads/main", run="1", aud="provenza", **over):
        now = int(time.time())
        claims = {"iss": self.iss, "aud": aud, "iat": now, "nbf": now, "exp": now + 600,
                  "sub": f"repo:{repository}:ref:{ref}", "repository": repository,
                  "repository_owner": repository.split("/")[0], "ref": ref, "run_id": run, **over}
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "gh-1"})


@pytest.fixture
def github():
    svc._jwks_cache.clear()
    svc._last_refetch.clear()
    return Issuer()


async def _policy(client, token, issuer, **kw):
    body = {"name": "ci-runners", "kind": "oidc", "issuer": issuer.iss, "jwks": issuer.jwks,
            "claim_rules": RULES, **kw}
    r = await client.post(f"{P}/policies", json=body, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _default(client, token, policy_id):
    r = await client.put("/api/v1/agent-identity/settings", json={
        "require_agent_key": True, "rotation_grace_minutes": 60, "default_attestation_policy_id": policy_id},
        headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def attest(client, agent, token, kind="oidc"):
    hdr = {"X-Agent-Key": agent["api_key"]}
    r = await client.post(f"{A}/{agent['id']}/attestation/challenge", headers=hdr)
    assert r.status_code == 200, r.text
    ch = r.json()
    stmt = {"type": "provenza.agent.attestation", "v": 1, "challenge": ch["challenge"], "agent_id": agent["id"],
            "kind": kind, "evidence_sha256": hashlib.sha256(token.encode()).hexdigest()}
    s, pq = sign_both(agent, stmt)
    r = await client.post(f"{A}/{agent['id']}/attestation", headers=hdr, json={
        "challenge": ch["challenge"], "kind": kind, "evidence": token, "signature": s, "pq_signature": pq})
    assert r.status_code == 200, r.text
    return r.json()


async def act(client, agent):
    return await client.post(f"{A}/actions/check", headers={"X-Agent-Key": agent["api_key"]},
                             json={"agent_id": agent["id"], "tool_name": "kb.search", "input": {}})


def test_rules_must_name_a_workload():
    for bad in ({}, {"iss": ["x"]}, {"aud": ["provenza"]}, {"repository": ["*"]}, {"repository": ["**?"]},
                {"bad path!": ["x"]}, {"repository": []}):
        with pytest.raises(AttestationError):
            normalize_rules(bad)
    assert normalize_rules({"repository": "acme/agents"}) == {"repository": ["acme/agents"]}


@pytest.mark.asyncio
async def test_an_oidc_policy_needs_claim_rules(client, admin_token, github):
    body = {"name": "x", "kind": "oidc", "issuer": github.iss, "jwks": github.jwks}
    for rules in ({}, {"repository": ["*"]}, {"aud": ["provenza"]}):
        r = await client.post(f"{P}/policies", json={**body, "claim_rules": rules}, headers=auth_headers(admin_token))
        assert r.status_code == 422, rules
    assert (await client.get(f"{P}/presets", headers=auth_headers(admin_token))).json()["github_actions"]["issuer"] == GITHUB


@pytest.mark.asyncio
async def test_the_organization_default_makes_every_agent_attest(client, admin_token, github):
    pol = await _policy(client, admin_token, github)
    agent = await enroll(client, admin_token, "ci-bot", allowed_tools=("kb.search",))
    assert (await act(client, agent)).status_code == 200            # no default yet: not required
    await _default(client, admin_token, pol["id"])
    try:
        r = await act(client, agent)
        assert r.status_code == 403 and r.json()["detail"] == "agent.attestation_required"
        # another repository, another branch, another audience: refused
        assert (await attest(client, agent, github.token(repository="evil/fork")))["reason"] == \
            "attestation.workload_not_allowed"
        assert (await attest(client, agent, github.token(ref="refs/heads/dev")))["ok"] is False
        assert (await attest(client, agent, github.token(aud="other")))["reason"] == "attestation.wrong_audience"
        assert (await attest(client, agent, Issuer().token()))["ok"] is False    # someone else's key
        res = await attest(client, agent, github.token())
        assert res["ok"] is True and res["identity"]["claims"] == {"repository": "acme/agents", "ref": "refs/heads/main"}
        assert (await act(client, agent)).status_code == 200
        st = (await client.get(f"{P}/agents/{agent['id']}", headers=auth_headers(admin_token))).json()
        assert st["required"] and st["binding"]["subject"] == "repo:acme/agents:ref:refs/heads/main"
        # the default policy cannot be deleted from under the organization
        r = await client.delete(f"{P}/policies/{pol['id']}", headers=auth_headers(admin_token))
        assert r.status_code == 409
    finally:
        assert (await _default(client, admin_token, 0))["default_attestation_policy_id"] is None


@pytest.mark.asyncio
async def test_an_agent_is_bound_to_its_workload(client, admin_token, github, db_session):
    pol = await _policy(client, admin_token, github, claim_rules={"repository_owner": ["acme"]})
    agent = await enroll(client, admin_token, "bound-bot", allowed_tools=("kb.search",))
    await _default(client, admin_token, pol["id"])
    try:
        assert (await attest(client, agent, github.token(repository="acme/agents")))["ok"] is True
        # another workload the policy allows, with this agent's key: refused, incident
        moved = await attest(client, agent, github.token(repository="acme/other"))
        assert moved["ok"] is False and moved["reason"] == "attestation.workload_changed"
        incident = (await db_session.execute(select(AgentIncident).where(
            AgentIncident.agent_id == agent["id"], AgentIncident.incident_type == "attestation_workload_changed"))
        ).scalar_one()
        assert incident.severity == "critical"
        assert (await act(client, agent)).status_code == 200      # its own earlier attestation still counts

        # an admin releases the binding: the current attestation stops counting, the next one binds again
        assert (await client.post(f"{P}/agents/{agent['id']}/unbind",
                                  headers=auth_headers(admin_token))).status_code == 200
        assert (await act(client, agent)).status_code == 403
        assert (await attest(client, agent, github.token(repository="acme/other")))["ok"] is True
        st = (await client.get(f"{P}/agents/{agent['id']}", headers=auth_headers(admin_token))).json()
        assert st["binding"]["subject"] == "repo:acme/other:ref:refs/heads/main"
    finally:
        await _default(client, admin_token, 0)


@pytest.mark.asyncio
async def test_unbind_is_admin_only(client, admin_token, approver_token):
    agent = await enroll(client, admin_token, "nobind-bot")
    r = await client.post(f"{P}/agents/{agent['id']}/unbind", headers=auth_headers(approver_token))
    assert r.status_code == 403
