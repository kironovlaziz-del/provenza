"""Enroll an agent the way a real one does (tools/provenza_sign.py enroll):
keys generated on the agent's side, possession proven by signing the
server's challenge. Mirrors enroll_statement / rotation_statement in
app/services/enrollment.py."""

from app.core.agent_signing import (generate_keypair, generate_pq_keypair, key_fingerprint, pq_available,
                                    sign_payload, sign_payload_pq)
from tests.conftest import auth_headers

E = "/api/v1/agent-enrollment"


def new_keys(hybrid=False):
    priv, pub = generate_keypair()
    keys = {"private_key": priv, "public_key": pub, "pq_private_key": None, "pq_public_key": None}
    if hybrid and pq_available():
        keys["pq_private_key"], keys["pq_public_key"] = generate_pq_keypair()
    return keys


def sign_both(keys, statement):
    s = sign_payload(statement, keys["private_key"])
    pq = sign_payload_pq(statement, keys["pq_private_key"]) if keys.get("pq_private_key") else None
    return s, pq


async def issue(client, admin_token, **template):
    body = {"name": template.pop("name", None), **template}
    r = await client.post(f"{E}/tokens", json=body, headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    return r.json()


async def enroll_with(client, token, keys, *, name=None, tamper=None):
    ch = (await client.post(f"{E}/challenge", json={"token": token})).json()
    final = (ch.get("name") or name or "").strip()
    statement = {"type": "provenza.agent.enroll", "v": 1, "challenge": ch["challenge"], "org_id": ch["org_id"],
                 "enrollment_id": ch["enrollment_id"], "public_key": keys["public_key"],
                 "pq_public_key": keys["pq_public_key"], "name": final}
    s, pq = sign_both(keys, statement)
    body = {"token": token, "challenge": ch["challenge"], "public_key": keys["public_key"],
            "pq_public_key": keys["pq_public_key"], "name": name, "signature": s, "pq_signature": pq}
    if tamper:
        tamper(body)
    return await client.post(f"{E}/enroll", json=body)


async def enroll(client, admin_token, name="agent", *, capabilities=("read",), allowed_tools=("kb.search",),
                 hybrid=False, **template):
    """A new agent via a token; returns a dict like /agents/register did:
    id, api_key, private_key, public_key (+ pq keys)."""
    tok = await issue(client, admin_token, name=name, capabilities=list(capabilities),
                      allowed_tools=list(allowed_tools), **template)
    keys = new_keys(hybrid)
    r = await enroll_with(client, tok["token"], keys)
    assert r.status_code == 200, r.text
    d = r.json()
    return {"id": d["agent_id"], "api_key": d["api_key"], **keys}


async def rotate(client, agent, *, hybrid=False, sign_old=None, sign_new=None):
    """The agent rotates its own key. Returns (response, new_keys)."""
    hdr = {"X-Agent-Key": agent["api_key"]}
    ch = (await client.post(f"/api/v1/agents/{agent['id']}/signing-key/challenge", headers=hdr)).json()
    new = new_keys(hybrid)
    statement = {"type": "provenza.agent.key_rotation", "v": 1, "challenge": ch["challenge"], "agent_id": agent["id"],
                 "old_key_fingerprint": ch["old_key_fingerprint"],
                 "new_key_fingerprint": key_fingerprint(new["public_key"], new["pq_public_key"]),
                 "new_public_key": new["public_key"], "new_pq_public_key": new["pq_public_key"]}
    os_, opq = sign_both(sign_old or agent, statement)
    ns, npq = sign_both(sign_new or new, statement)
    r = await client.post(f"/api/v1/agents/{agent['id']}/signing-key/rotate", headers=hdr, json={
        "challenge": ch["challenge"], "new_public_key": new["public_key"], "new_pq_public_key": new["pq_public_key"],
        "old_signature": os_, "old_pq_signature": opq, "new_signature": ns, "new_pq_signature": npq})
    return r, new
