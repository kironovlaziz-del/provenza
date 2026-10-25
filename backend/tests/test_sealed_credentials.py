"""
Credentials sealed to the egress proxies (app/pvp/sealed.py,
app/services/credentials.py): this server takes none in clear text, stores
only envelopes it cannot open, hands each proxy only its own, erases the
ones it held before once they are sealed - and its own gateways refuse an
upstream whose credential is sealed.
"""

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from app.core.agent_signing import canonical_bytes, key_fingerprint
from app.core.crypto import encrypt_secret
from app.models.a2a_gateway import A2APeer
from app.models.ai_provider import AIProvider
from app.models.egress_proxy import EgressRoute
from app.models.http_tool import HttpTool
from app.models.mcp import MCPServer
from app.models.sealed_credential import SealedCredential
from app.pvp import mcp_client, mcp_gateway, sealed, signed_policy
from app.pvp import policy_bundle as pb
from tests import signer
from tests.conftest import auth_headers

E, P = "/api/v1/egress", "/api/v1/egress-proxy"
SECRET = "Bearer sk_live_sealed_" + "z" * 12


@pytest.fixture(autouse=True)
def _fresh_cache():
    signed_policy.forget()
    yield
    signed_policy.forget()


class Proxy:
    """A proxy's two keys, as proxy/internal/egress makes them."""

    def __init__(self, created):
        self.id, self.key = created["id"], created["key"]
        self.seed = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        self.signing = Ed25519PrivateKey.from_private_bytes(self.seed)
        self.public = base64.b64encode(self.signing.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        self.enc = sealed.proxy_encryption_key(self.seed)
        self.enc_public = base64.b64encode(self.enc.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

    @property
    def headers(self):
        return {"X-Proxy-Key": self.key}

    def registration(self, enc_public=None, signer=None):
        enc_public = enc_public or self.enc_public
        sig = (signer or self.signing).sign(canonical_bytes(sealed.key_statement(enc_public)))
        return {"public_key": self.public, "encryption_key": enc_public,
                "encryption_key_signature": base64.b64encode(sig).decode()}


async def _proxy(client, token, name="host-a", register=True):
    r = await client.post(f"{E}/proxies", json={"name": name}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    p = Proxy(r.json())
    if register:
        r = await client.post(f"{P}/key", json=p.registration(), headers=p.headers)
        assert r.status_code == 200, r.text
        assert r.json()["encryption_key_fingerprint"] == key_fingerprint(p.enc_public)
    return p


async def _route(client, token, slug="stripe", source="sealed"):
    r = await client.post(f"{E}/routes", json={
        "slug": slug, "name": slug, "upstream_url": "https://api.stripe.com", "methods": ["POST"],
        "path_prefixes": ["/v1/charges"], "credential_source": source}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _org(db_session, route):
    return (await db_session.get(EgressRoute, route["id"])).org_id


@pytest.mark.asyncio
async def test_the_encryption_key_is_registered_once_and_only_signed(client, admin_token):
    p = await _proxy(client, admin_token, register=False)
    # not signed by the proxy's own signing key
    r = await client.post(f"{P}/key", json=p.registration(signer=Ed25519PrivateKey.generate()), headers=p.headers)
    assert r.status_code == 422 and r.json()["detail"] == "egress.bad_proxy_encryption_key"
    r = await client.post(f"{P}/key", json={**p.registration(), "encryption_key_signature": None}, headers=p.headers)
    assert r.status_code == 422
    r = await client.post(f"{P}/key", json=p.registration(), headers=p.headers)
    assert r.status_code == 200 and r.json()["org_id"] and r.json()["proxy_id"] == p.id
    assert (await client.post(f"{P}/key", json=p.registration(), headers=p.headers)).status_code == 200
    # another encryption key later: a new key is a new proxy
    other = sealed.proxy_encryption_key(b"\x01" * 32).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    r = await client.post(f"{P}/key", json=p.registration(base64.b64encode(other).decode()), headers=p.headers)
    assert r.status_code == 409 and r.json()["detail"] == "egress.proxy_key_changed"

    [pk] = (await client.get(f"{E}/proxy-keys", headers=auth_headers(admin_token))).json()
    assert (pk["proxy_id"], pk["encryption_key"], pk["key_fingerprint"]) == (
        p.id, p.enc_public, key_fingerprint(p.public))
    listed = (await client.get(f"{E}/proxies", headers=auth_headers(admin_token))).json()
    assert listed[0]["encryption_key_fingerprint"] == key_fingerprint(p.enc_public)


@pytest.mark.asyncio
async def test_a_credential_is_sealed_in_the_browser_and_only_its_proxy_gets_it(client, admin_token, db_session):
    a = await _proxy(client, admin_token, "host-a")
    b = await _proxy(client, admin_token, "host-b")
    route = await _route(client, admin_token)
    org_id = await _org(db_session, route)
    st = (await client.get(f"{E}/credentials/route/{route['id']}", headers=auth_headers(admin_token))).json()
    assert st == {"source": "sealed", "upstream": "https://api.stripe.com", "sealed_for": [], "missing": [a.id, b.id],
                  "stale": [], "unsigned": [], "awaiting_sealing": False}

    def env(proxy, **ctx):
        c = {**sealed.context(org_id, "route", route["id"], proxy.id, "https://api.stripe.com"), **ctx}
        return sealed.seal(SECRET, proxy.enc_public, c)

    put = f"{E}/credentials/route/{route['id']}"
    # addressed wrong: another object, another proxy's key, an unknown proxy, junk
    for bad, why in ((env(a, object_id=route["id"] + 1), "sealed for another object or proxy"),
                     (env(a, upstream="https://evil.example"), "sealed for another object or proxy"),
                     (dict(env(a), key_fingerprint=key_fingerprint(b.enc_public)), "sealed to another key"),
                     (dict(env(a), extra=1), "unexpected fields")):
        r = await signer.seal(client, admin_token, put, [bad])
        assert r.status_code == 422 and r.json()["detail"]["code"] == "credential.bad_envelope", r.text
        assert why in r.json()["detail"]["context"]["problem"]
    r = await signer.seal(client, admin_token, put, [dict(env(a), proxy_id=999)])
    assert r.status_code == 422
    r = await signer.seal(client, admin_token, put, [env(a), env(a)])
    assert r.status_code == 422 and r.json()["detail"] == "credential.unknown_proxy"

    r = await signer.seal(client, admin_token, put, [env(a)])
    assert r.status_code == 200 and r.json()["sealed_for"] == [a.id] and r.json()["missing"] == [b.id]
    # the envelopes come with the administrator's signature over exactly them
    e_a, e_b = env(a), env(b)
    r = await client.put(put, json={"envelopes": [e_a, e_b]}, headers=auth_headers(admin_token))
    assert r.status_code == 422                                # not signed
    s = await signer.signer(client, admin_token)
    st = (await client.post(f"{put}/statement", json={"envelopes": [e_a]}, headers=auth_headers(admin_token))).json()
    r = await client.put(put, json={"envelopes": [e_a, e_b], "statement": st["statement"],
                                    "signature": s.sign(st["statement"])}, headers=auth_headers(admin_token))
    assert r.status_code == 422 and r.json()["detail"] == "session.statement_mismatch"   # signed for one only
    r = await signer.seal(client, admin_token, put, [e_a, e_b])
    assert r.json()["missing"] == [] and r.json()["unsigned"] == []

    # each proxy gets only its own envelope, and only it can open it
    got_a = (await client.get(f"{P}/credentials", headers=a.headers)).json()["credentials"]
    got_b = (await client.get(f"{P}/credentials", headers=b.headers)).json()["credentials"]
    assert [(c["object"], c["object_id"]) for c in got_a] == [("route", route["id"])]
    proof = got_a[0]["sealer"]
    assert proof["statement"]["type"] == "provenza.credential.sealed" and proof["statement"]["object"] == "route"
    assert proof["statement"]["envelopes"] == {str(a.id): pb.sha256(got_a[0]["envelope"]),
                                               str(b.id): pb.sha256(got_b[0]["envelope"])}
    assert proof["statement"]["upstream"] == "https://api.stripe.com" and proof["certificate"]["credential_id"]
    assert sealed.open_sealed(got_a[0]["envelope"], a.enc) == SECRET
    assert sealed.open_sealed(got_b[0]["envelope"], b.enc) == SECRET
    with pytest.raises(Exception):
        sealed.open_sealed(got_a[0]["envelope"], b.enc)
    # nothing the server stores or returns holds it in clear text
    rows = (await db_session.execute(select(SealedCredential))).scalars().all()
    assert len(rows) == 2 and all(SECRET not in str(r.envelope) for r in rows)
    cfg = (await client.get(f"{P}/config", headers=a.headers)).json()
    assert SECRET not in str(cfg) and cfg["routes"][0]["credential_source"] == "sealed"
    assert SECRET not in (await client.get(f"{E}/routes", headers=auth_headers(admin_token))).text
    assert (await client.get(f"{P}/credentials")).status_code == 401

    # the route now points elsewhere: its envelopes no longer open there, they must be sealed again
    r = await client.patch(f"{E}/routes/{route['id']}", json={"upstream_url": "https://api.other.example"},
                           headers=auth_headers(admin_token))
    st = (await client.get(f"{E}/credentials/route/{route['id']}", headers=auth_headers(admin_token))).json()
    assert st["upstream"] == "https://api.other.example" and st["sealed_for"] == [] and st["stale"] == [a.id, b.id]
    assert st["missing"] == [a.id, b.id]

    # local: the proxies' configuration holds it; the envelopes go
    r = await client.post(f"{put}/source", json={"source": "local"}, headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["source"] == "local" and r.json()["sealed_for"] == []
    assert (await client.get(f"{P}/credentials", headers=a.headers)).json()["credentials"] == []


@pytest.mark.asyncio
async def test_a_deleted_object_takes_its_envelopes_along(client, admin_token, db_session):
    a = await _proxy(client, admin_token)
    route = await _route(client, admin_token)
    org_id = await _org(db_session, route)
    env = sealed.seal(SECRET, a.enc_public, sealed.context(org_id, "route", route["id"], a.id, "https://api.stripe.com"))
    await signer.seal(client, admin_token, f"{E}/credentials/route/{route['id']}", [env])
    assert (await client.delete(f"{E}/routes/{route['id']}", headers=auth_headers(admin_token))).status_code == 200
    assert (await client.get(f"{P}/credentials", headers=a.headers)).json()["credentials"] == []


@pytest.mark.asyncio
async def test_plaintext_is_refused_everywhere(client, admin_token):
    h = auth_headers(admin_token)
    refused = [
        await client.post(f"{E}/routes", json={"slug": "x", "name": "x", "upstream_url": "https://api.example.com",
                                               "credential_source": "sealed", "secret": SECRET}, headers=h),
        await client.post("/api/v1/providers/", json={"name": "p", "type": "openai", "api_key": SECRET}, headers=h),
        await client.post("/api/v1/mcp-servers", json={"slug": "m", "name": "m", "url": "https://mcp.example.com/mcp",
                                                       "auth_secret": SECRET}, headers=h),
        await client.post("/api/v1/a2a-peers", json={"slug": "a", "name": "a",
                                                     "card_url": "https://a.example.com/.well-known/agent-card.json",
                                                     "auth_secret": SECRET}, headers=h),
        await client.post("/api/v1/http-tools", json={"name": "t.x", "method": "GET", "url": "https://api.example.com/x",
                                                      "auth_secret": SECRET}, headers=h),
    ]
    for r in refused:
        assert r.status_code == 422 and r.json()["detail"] == "credential.plaintext_refused", r.text


@pytest.mark.asyncio
async def test_held_credentials_are_sealed_once_and_erased(client, admin_token, db_session):
    route = await _route(client, admin_token, source="none")
    org_id = await _org(db_session, route)
    row = await db_session.get(EgressRoute, route["id"])
    row.secret_encrypted, row.credential_source = encrypt_secret(SECRET, org_id), "sealed"
    provider = AIProvider(org_id=org_id, name="old", type="openai", status="active",
                          api_key_encrypted=encrypt_secret("sk-old", org_id), credential_source="sealed")
    db_session.add(provider)
    await db_session.commit()
    provider_id = provider.id

    legacy = (await client.get(f"{E}/credentials/legacy", headers=auth_headers(admin_token))).json()
    assert legacy == {"count": 2, "proxies_with_keys": 0}
    st = (await client.get(f"{E}/credentials/route/{route['id']}", headers=auth_headers(admin_token))).json()
    assert st["awaiting_sealing"] is True
    # nowhere to seal them to yet
    r = await client.post(f"{E}/credentials/seal-legacy", headers=auth_headers(admin_token))
    assert r.status_code == 409 and r.json()["detail"] == "credential.no_proxy_keys"

    a = await _proxy(client, admin_token)
    r = await client.post(f"{E}/credentials/seal-legacy", headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["sealed"] == {"route": 1, "provider": 1} and r.json()["failed"] == []
    assert (await client.get(f"{E}/credentials/legacy", headers=auth_headers(admin_token))).json()["count"] == 0
    await db_session.refresh(row)
    assert row.secret_encrypted is None
    p = await db_session.get(AIProvider, provider_id)
    await db_session.refresh(p)
    assert p.api_key_encrypted is None and p.credential_source == "sealed"
    got = {(c["object"], c["object_id"]): c["envelope"]
           for c in (await client.get(f"{P}/credentials", headers=a.headers)).json()["credentials"]}
    assert sealed.open_sealed(got[("route", route["id"])], a.enc) == SECRET
    assert sealed.open_sealed(got[("provider", provider_id)], a.enc) == "sk-old"
    # sealed here, so nobody vouched for them yet: an administrator countersigns
    put = f"{E}/credentials/route/{route['id']}"
    st = (await client.get(put, headers=auth_headers(admin_token))).json()
    assert st["unsigned"] == [a.id]
    s = await signer.signer(client, admin_token)
    ch = (await client.post(f"{put}/statement", json={}, headers=auth_headers(admin_token))).json()["statement"]
    assert ch["envelopes"] == {str(a.id): pb.sha256(got[("route", route["id"])])}
    r = await client.post(f"{put}/countersign", json={"statement": ch, "signature": s.sign(ch)},
                          headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["unsigned"] == [], r.text
    creds = (await client.get(f"{P}/credentials", headers=a.headers)).json()["credentials"]
    assert {c["object"]: bool(c["sealer"]) for c in creds} == {"route": True, "provider": False}
    r = await client.post(f"{E}/credentials/mcp_server/999/statement", json={}, headers=auth_headers(admin_token))
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_this_servers_gateways_refuse_a_sealed_upstream(client, admin_token, db_session):
    route = await _route(client, admin_token, source="none")
    org_id = await _org(db_session, route)
    server = MCPServer(org_id=org_id, slug="m", name="m", url="https://mcp.example.com/mcp", credential_source="sealed")
    peer = A2APeer(org_id=org_id, slug="a", name="a", card_url="https://a.example.com/card", credential_source="sealed")
    db_session.add_all([server, peer])
    await db_session.commit()
    with pytest.raises(mcp_client.UpstreamError, match="credential") as exc:
        mcp_gateway.upstream_for(server)
    assert exc.value.code == "upstream.credential_at_proxy"
    from app.pvp import a2a_gateway

    with pytest.raises(a2a_gateway.UpstreamError):
        await a2a_gateway.fetch_card(peer)

    # an HTTP tool whose credential is sealed: the call is refused, and recorded
    r = await client.post("/api/v1/http-tools", json={"name": "t.sealed", "method": "GET",
                                                      "url": "https://api.example.com/x"},
                          headers=auth_headers(admin_token))
    tool = await db_session.get(HttpTool, r.json()["id"])
    tool.credential_source = "sealed"
    await db_session.commit()
    agent = (await client.post("/api/v1/agents/register", json={
        "name": "sealed-bot", "agent_type": "custom", "capabilities": [], "allowed_tools": ["t.sealed"],
        "allowed_models": [], "max_delegation_depth": 1}, headers=auth_headers(admin_token))).json()
    headers = {"X-Agent-Key": agent["api_key"]}
    body = client._signed({"agent_id": agent["id"], "tool_name": "t.sealed", "input": {}}, headers)
    out = (await client.post("/api/v1/http-tools/call", json=body, headers=headers)).json()
    assert out["decision"] == "denied" and "sealed to the egress proxies" in out["reason"]
    assert out["action_id"]


@pytest.mark.asyncio
async def test_the_signed_manifest_pins_the_encryption_key(client, admin_token):
    from tests.test_policy_release import _release

    a = await _proxy(client, admin_token)
    await _release(client, admin_token)
    got = (await client.get(f"{P}/policy-release", headers=a.headers)).json()
    entry = got["chain"][-1]["manifest"]["egress_proxies"][str(a.id)]
    assert entry["encryption_key_fingerprint"] == key_fingerprint(a.enc_public)
