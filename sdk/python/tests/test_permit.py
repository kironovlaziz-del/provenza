# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""provenza.permit: a tool runs only with a valid permit for exactly this call."""

import asyncio
import base64
import json
import secrets
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from provenza.agent import Check
from provenza.crypto import canonical, content_hash
from provenza.permit import HEADER, PermitError, PermitMiddleware, PermitVerifier, require_permit

SERVER = "https://provenza.test"
INPUT = {"customer": 42, "fields": {"tier": "gold"}}


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class FakeProvenza:
    """JWKS + redeem, as the server answers them."""

    def __init__(self, org="acme"):
        self.org, self.keys, self.redeemed, self.jwks_calls, self.down = org, {}, set(), 0, False
        self.kid = self.rotate()

    def rotate(self):
        kid = "pk_" + secrets.token_hex(4)
        self.keys[kid] = Ed25519PrivateKey.generate()
        self.kid = kid
        return kid

    def permit(self, tool="crm.update", input=INPUT, exp_in=300, iss=None, kid=None, **over):
        now = int(time.time())
        claims = {"iss": iss or f"provenza:org:{self.org}", "sub": "agent:7", "aud": tool,
                  "jti": secrets.token_urlsafe(8), "iat": now, "nbf": now, "exp": now + exp_in,
                  "act": "tool_call", "chain": None, "ish": content_hash(input), **over}
        kid = kid or self.kid
        header = {"alg": "EdDSA", "typ": "provenza-permit+jwt", "kid": kid}
        si = f"{b64(canonical(header))}.{b64(canonical(claims))}"
        return si + "." + b64(self.keys[kid].sign(si.encode()))

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("down", request=request)
        if request.url.path == f"/api/v1/pvp/permits/{self.org}/jwks.json":
            self.jwks_calls += 1
            keys = [{"kty": "OKP", "crv": "Ed25519", "kid": kid, "use": "sig", "alg": "EdDSA",
                     "x": b64(k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))}
                    for kid, k in self.keys.items()]
            return httpx.Response(200, json={"keys": keys})
        if request.url.path == "/api/v1/pvp/permits/redeem":
            body = json.loads(request.content)
            jti = json.loads(base64.urlsafe_b64decode(body["permit"].split(".")[1] + "=="))["jti"]
            if jti in self.redeemed:
                return httpx.Response(409, json={"detail": "permit.redeemed"})
            self.redeemed.add(jti)
            return httpx.Response(200, json={"redeemed": True, "jti": jti})
        return httpx.Response(404)


@pytest.fixture
def fake():
    return FakeProvenza()


def verifier(fake, **kw):
    return PermitVerifier(SERVER, fake.org, transport=httpx.MockTransport(fake.handler),
                          async_transport=httpx.MockTransport(fake.handler), **kw)


def test_a_valid_permit_runs_once(fake):
    v = verifier(fake)
    token = fake.permit()
    p = v.verify(token, tool="crm.update", input=INPUT)
    assert p.agent_id == 7 and p.tool == "crm.update" and p.redeemed and p.input_sha256 == content_hash(INPUT)
    with pytest.raises(PermitError) as e:
        v.verify(token, tool="crm.update", input=INPUT)
    assert e.value.code == "permit.redeemed"
    assert fake.jwks_calls == 1                                  # cached


@pytest.mark.parametrize("tool,input,code", [
    ("crm.delete", INPUT, "permit.mismatch"),                     # another tool
    ("crm.update", {**INPUT, "customer": 43}, "permit.mismatch"),  # another input
])
def test_anything_else_is_refused(fake, tool, input, code):
    with pytest.raises(PermitError) as e:
        verifier(fake).verify(fake.permit(), tool=tool, input=input)
    assert e.value.code == code
    assert not fake.redeemed                                     # refused before it was used


def test_missing_forged_expired_foreign(fake):
    v = verifier(fake)
    for token, code in [
        (None, "permit.missing"),
        ("a.b", "permit.invalid"),
        (fake.permit(exp_in=-120), "permit.expired"),
        (fake.permit(iss="provenza:org:other"), "permit.invalid"),
        (fake.permit()[:-6] + "AAAAAA", "permit.invalid"),
    ]:
        with pytest.raises(PermitError) as e:
            v.verify(token, tool="crm.update", input=INPUT)
        assert e.value.code == code, token
    # signed by a key the organization does not publish
    stranger = FakeProvenza()
    with pytest.raises(PermitError) as e:
        v.verify(stranger.permit(), tool="crm.update", input=INPUT)
    assert e.value.code == "permit.invalid"


def test_a_rotated_key_is_fetched_once_it_appears(fake):
    v = verifier(fake)
    v.verify(fake.permit(), tool="crm.update", input=INPUT)
    fake.rotate()
    assert v.verify(fake.permit(), tool="crm.update", input=INPUT).redeemed
    assert fake.jwks_calls == 2


def test_fails_closed_when_provenza_cannot_be_reached(fake):
    v = verifier(fake)
    fake.down = True
    with pytest.raises(PermitError) as e:
        v.verify(fake.permit(), tool="crm.update", input=INPUT)
    assert e.value.code == "permit.unverifiable"


def test_offline_mode_remembers_what_it_has_seen(fake):
    v = verifier(fake, redeem=False)
    token = fake.permit()
    assert not v.verify(token, tool="crm.update", input=INPUT).redeemed
    with pytest.raises(PermitError) as e:
        v.verify(token, tool="crm.update", input=INPUT)
    assert e.value.code == "permit.redeemed" and not fake.redeemed


def test_require_permit_decorator(fake):
    v = verifier(fake)

    @require_permit(v, "crm.update")
    def update(customer, fields):
        return f"updated {customer}"

    assert update(permit=fake.permit(), **INPUT) == "updated 42"
    with pytest.raises(PermitError):
        update(**INPUT)

    @require_permit(v, "crm.update")
    async def aupdate(customer, fields):
        return customer

    assert asyncio.run(aupdate(permit=fake.permit(), **INPUT)) == 42


def _asgi_call(app, body: bytes, headers):
    sent, scope = [], {"type": "http", "method": "POST", "path": "/update", "headers": headers}
    chunks = [{"type": "http.request", "body": body[:5], "more_body": True},
              {"type": "http.request", "body": body[5:], "more_body": False}]

    async def receive():
        return chunks.pop(0)

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    return sent, scope


def test_asgi_middleware(fake):
    seen = {}

    async def tool_app(scope, receive, send):
        msg = await receive()
        seen["body"], seen["permit"] = msg["body"], scope["state"]["permit"]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    app = PermitMiddleware(tool_app, verifier(fake), tool="crm.update")
    body = json.dumps(INPUT).encode()
    sent, _ = _asgi_call(app, body, [(HEADER.lower().encode(), fake.permit().encode())])
    assert sent[0]["status"] == 200 and seen["body"] == body and seen["permit"].agent_id == 7

    sent, _ = _asgi_call(app, body, [])
    assert sent[0]["status"] == 403 and json.loads(sent[1]["body"]) == {"error": "permit.missing"}
    sent, _ = _asgi_call(app, b'{"customer": 1}', [(HEADER.lower().encode(), fake.permit().encode())])
    assert json.loads(sent[1]["body"]) == {"error": "permit.mismatch"}
    fake.down = True
    sent, _ = _asgi_call(app, body, [(HEADER.lower().encode(), fake.permit().encode())])
    assert sent[0]["status"] == 503


def test_the_agent_sends_the_permit_with_the_call():
    chk = Check(check_id="c", decision="allowed", reason="", tool="crm.update", action_type="tool_call",
                input=INPUT, permit="h.c.s")
    assert chk.permit_headers == {HEADER: "h.c.s"}
    assert "h.c.s" not in repr(chk)
    assert Check(check_id="c", decision="denied", reason="", tool="t", action_type="tool_call",
                 input={}).permit_headers == {}
