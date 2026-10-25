"""
A reviewer's browser in the tests (docs/pvp/edge.md, sections 2-3): a
passkey on a software authenticator, a session key it certifies, and
decisions on held agent actions signed with that session key - the way the
web interface approves and denies.
"""

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.agent_signing import canonical_bytes
from tests.webauthn_helpers import SoftAuthenticator

PASSWORD = "TestPass123!"         # tests/conftest.py
A = "/api/v1/agents"


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@dataclass
class Signer:
    token: str
    device: SoftAuthenticator
    key: Ed25519PrivateKey
    public_key: str
    session_id: str

    def sign(self, statement: dict) -> str:
        return base64.b64encode(self.key.sign(canonical_bytes(statement))).decode()


_signers: dict = {}


async def signer(client, token: str, password: str = PASSWORD) -> Signer:
    """The session of `token`, certified once: a passkey is registered (the
    person has none yet) and certifies a fresh session key."""
    if token in _signers:
        return _signers[token]
    device = SoftAuthenticator()
    opts = await client.post("/api/v1/users/me/passkeys/options", headers=auth(token))
    assert opts.status_code == 200, opts.text
    assert not opts.json()["vouch_required"], "the person already has a passkey"
    r = await client.post("/api/v1/users/me/passkeys",
                          json={"label": "test", "password": password, **device.create(opts.json()["challenge"])},
                          headers=auth(token))
    assert r.status_code == 201 or r.status_code == 200, r.text
    key = Ed25519PrivateKey.generate()
    pub = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,
                                                         serialization.PublicFormat.Raw)).decode()
    ch = await client.post("/api/v1/auth/session/challenge",
                           json={"purpose": "session.certificate", "params": {"public_key": pub}}, headers=auth(token))
    assert ch.status_code == 200, ch.text
    ch = ch.json()
    r = await client.post("/api/v1/auth/session/certificate",
                          json={"public_key": pub, "statement": ch["statement"], "assertion": device.get(ch["challenge"])},
                          headers=auth(token))
    assert r.status_code == 204, r.text
    s = Signer(token, device, key, pub, ch["statement"]["session_id"])
    _signers[token] = s
    return s


async def signed_statement(client, token: str, action_id: int, decision: str):
    """(statement, signature), or the refusing response of the statement call."""
    s = await signer(client, token)
    r = await client.post(f"{A}/actions/{action_id}/statement", json={"decision": decision}, headers=auth(token))
    if r.status_code != 200:
        return r
    st = r.json()["statement"]
    return st, s.sign(st)


async def approve(client, token: str, action_id: int, input_sha256: str, confirmation=None):
    """Approve as the web interface does: the statement, signed with the
    session key, sent with the reviewed input hash."""
    got = await signed_statement(client, token, action_id, "approved")
    if not isinstance(got, tuple):
        return got
    body = {"input_sha256": input_sha256, "statement": got[0], "signature": got[1]}
    if confirmation is not None:
        body["confirmation"] = confirmation
    return await client.post(f"{A}/actions/{action_id}/approve", json=body, headers=auth(token))


async def deny(client, token: str, action_id: int, reason=None):
    got = await signed_statement(client, token, action_id, "denied")
    if not isinstance(got, tuple):
        return got
    return await client.post(f"{A}/actions/{action_id}/deny",
                             json={"reason": reason, "statement": got[0], "signature": got[1]}, headers=auth(token))


async def seal(client, token: str, path: str, envelopes: list):
    """Store envelopes as the web interface does: the statement over them,
    signed with the session key (app/services/credentials.py). The response of
    the first call that refuses, else of the PUT."""
    s = await signer(client, token)
    r = await client.post(path + "/statement", json={"envelopes": envelopes}, headers=auth(token))
    if r.status_code != 200:
        return r
    st = r.json()["statement"]
    return await client.put(path, json={"envelopes": envelopes, "statement": st, "signature": s.sign(st)},
                            headers=auth(token))
