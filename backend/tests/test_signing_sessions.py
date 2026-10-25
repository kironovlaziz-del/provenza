"""
Passkeys and signing sessions (docs/pvp/edge.md, section 2): one session of
an administrator or approver at a time - a second sign-in waits until the
open session lets it in with the passkey - and a session key the passkey
certifies. Plus the strict CBOR and WebAuthn checks underneath.
"""

import base64
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from app.core import cbor, webauthn
from app.core.agent_signing import canonical_bytes
from app.models.ai_incident import AIIncident
from app.models.signing import SigningSession
from tests.conftest import auth_headers
from tests.webauthn_helpers import ORIGIN, SoftAuthenticator, b64url
from tests.webauthn_helpers import cbor as encode

S = "/api/v1/auth/session"
P = "/api/v1/users/me/passkeys"


async def _login(client, users, who="admin"):
    r = await client.post("/api/v1/auth/login", json={"org_slug": users["org"].slug, "email": users[who].email,
                                                     "password": users["password"]})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


async def _state(client, token):
    r = await client.get(S, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _register(client, token, users, device, vouch_device=None, label="laptop"):
    opts = (await client.post(f"{P}/options", headers=auth_headers(token))).json()
    made = device.create(opts["challenge"])
    body = {"label": label, "password": users["password"], **made}
    if vouch_device is not None:
        ch = await _challenge(client, token, "passkey.add", {"credential_id": device.id})
        body["vouch"] = {"statement": ch["statement"], "assertion": vouch_device.get(ch["challenge"])}
    return await client.post(P, json=body, headers=auth_headers(token))


async def _challenge(client, token, purpose, params=None):
    r = await client.post(f"{S}/challenge", json={"purpose": purpose, "params": params or {}},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


def _session_key():
    k = Ed25519PrivateKey.generate()
    raw = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return k, base64.b64encode(raw).decode()


# ---------------------------------------------------------------------- CBOR / WebAuthn

class TestStrictParsing:
    def test_cbor_round_trip_and_refusals(self):
        value = {"a": [1, -2, b"\x00", True, None], 3: {"x": "y"}}
        assert cbor.loads(encode(value)) == value
        for bad in (b"\x9f\x01\xff",            # indefinite array
                    encode(1) + b"\x00",          # trailing byte
                    b"\xa2\x01\x01\x01\x02",      # duplicate key
                    b"\xfb" + b"\x00" * 8,        # float
                    b"\xc1\x01",                  # tag
                    b"\x18\x05",                  # non-minimal length
                    b"\x82\x01"):                 # truncated
            with pytest.raises(cbor.CBORError):
                cbor.loads(bad)
        deep = b"\x81" * 20 + b"\x01"
        with pytest.raises(cbor.CBORError):
            cbor.loads(deep)

    @pytest.mark.parametrize("alg", [-7, -8, -257])
    def test_registration_and_assertion(self, alg):
        dev = SoftAuthenticator(alg)
        reg = webauthn.verify_registration(**dev.create(b64url(b"c" * 32)), challenge=b"c" * 32)
        assert reg.alg == alg and reg.credential_id == dev.id
        a = dev.get(b64url(b"s" * 32))
        n = webauthn.verify_assertion(public_key_cose=reg.public_key, stored_sign_count=reg.sign_count,
                                      client_data_json=a["client_data_json"],
                                      authenticator_data=a["authenticator_data"], signature=a["signature"],
                                      challenge=b"s" * 32)
        assert n == 2

    def test_what_is_refused(self):
        dev = SoftAuthenticator()
        reg = webauthn.verify_registration(**dev.create(b64url(b"c" * 32)), challenge=b"c" * 32)

        def check(a, challenge=b"s" * 32, stored=reg.sign_count):
            webauthn.verify_assertion(public_key_cose=reg.public_key, stored_sign_count=stored,
                                      client_data_json=a["client_data_json"],
                                      authenticator_data=a["authenticator_data"], signature=a["signature"],
                                      challenge=challenge)

        cases = [
            (dev.get(b64url(b"s" * 32), origin="https://evil.example"), "webauthn.origin_mismatch"),
            (dev.get(b64url(b"s" * 32), rp_id="evil.example"), "webauthn.rp_mismatch"),
            (dev.get(b64url(b"x" * 32)), "webauthn.challenge_mismatch"),
        ]
        for a, code in cases:
            with pytest.raises(webauthn.WebAuthnError) as e:
                check(a)
            assert e.value.code == code
        forged = dev.get(b64url(b"s" * 32))
        forged["signature"] = b64url(b"\x30\x06\x02\x01\x01\x02\x01\x01")
        with pytest.raises(webauthn.WebAuthnError):
            check(forged)
        with pytest.raises(webauthn.WebAuthnError) as e:      # a clone: the counter goes back
            check(dev.get(b64url(b"s" * 32)), stored=1000)
        assert e.value.code == "webauthn.counter_regressed"
        no_pin = SoftAuthenticator(user_verified=False)
        with pytest.raises(webauthn.WebAuthnError) as e:
            webauthn.verify_registration(**no_pin.create(b64url(b"c" * 32)), challenge=b"c" * 32)
        assert e.value.code == "webauthn.user_not_verified"


# ---------------------------------------------------------------------- sessions

class TestOneSessionAtATime:
    @pytest.mark.asyncio
    async def test_second_sign_in_waits_and_the_first_is_told(self, client, admin_token, org_and_users,
                                                             db_session):
        first = await _state(client, admin_token)
        assert first["signing"] and first["status"] == "active"

        second = await _login(client, org_and_users)
        st = await _state(client, second)
        assert st["status"] == "blocked" and len(st["active_elsewhere"]) == 1
        r = await client.get("/api/v1/users/me", headers=auth_headers(second))
        assert r.status_code == 403 and r.json()["detail"] == "auth.session_blocked"
        assert (await client.get("/api/v1/users/me", headers=auth_headers(admin_token))).status_code == 200

        waiting = (await _state(client, admin_token))["waiting"]
        assert [w["session_id"] for w in waiting] == [st["session_id"]]
        incident = (await db_session.execute(select(AIIncident).where(
            AIIncident.category == "session_conflict"))).scalars().all()
        assert len(incident) == 1 and incident[0].severity == "high"

        # no passkey yet: the open session lets it in with the password
        r = await client.post(f"{S}/admit", json={"blocked_session_id": st["session_id"], "password": "nope"},
                              headers=auth_headers(admin_token))
        assert r.status_code == 403
        r = await client.post(f"{S}/admit", json={"blocked_session_id": st["session_id"],
                                                  "password": org_and_users["password"]},
                              headers=auth_headers(admin_token))
        assert r.status_code == 204, r.text
        assert (await client.get("/api/v1/users/me", headers=auth_headers(second))).status_code == 200

    @pytest.mark.asyncio
    async def test_refused_session_is_over(self, client, admin_token, org_and_users):
        second = await _login(client, org_and_users)
        sid = (await _state(client, second))["session_id"]
        r = await client.post(f"{S}/refuse", json={"blocked_session_id": sid}, headers=auth_headers(admin_token))
        assert r.status_code == 204
        r = await client.get(S, headers=auth_headers(second))
        assert r.status_code == 401 and r.json()["detail"] == "auth.session_ended"

    @pytest.mark.asyncio
    async def test_a_blocked_session_cannot_admit_or_sign(self, client, admin_token, org_and_users):
        second = await _login(client, org_and_users)
        third = await _login(client, org_and_users)
        sid3 = (await _state(client, third))["session_id"]
        r = await client.post(f"{S}/admit", json={"blocked_session_id": sid3, "password": org_and_users["password"]},
                              headers=auth_headers(second))
        assert r.status_code == 403
        r = await client.post(f"{S}/challenge", json={"purpose": "session.certificate",
                                                      "params": {"public_key": _session_key()[1]}},
                              headers=auth_headers(second))
        assert r.status_code == 403 and r.json()["detail"] == "auth.session_blocked"

    @pytest.mark.asyncio
    async def test_people_who_do_not_sign_have_no_sessions(self, client, org_and_users, db_session):
        from app.core.security import get_password_hash
        from app.models.user import User

        u = User(org_id=org_and_users["org"].id, email="reader@example.com", name="Reader",
                 hashed_password=get_password_hash(org_and_users["password"]), role="user", status="active")
        db_session.add(u)
        await db_session.commit()
        org_and_users["reader"] = u
        a, b = await _login(client, org_and_users, "reader"), await _login(client, org_and_users, "reader")
        for t in (a, b):
            st = await _state(client, t)
            assert st["signing"] is False and st["status"] == "active"

    @pytest.mark.asyncio
    async def test_signing_out_ends_the_session(self, client, admin_token, org_and_users):
        await client.post("/api/v1/auth/logout", headers=auth_headers(admin_token))
        assert (await client.get(S, headers=auth_headers(admin_token))).status_code == 401
        after = await _login(client, org_and_users)
        assert (await _state(client, after))["status"] == "active"     # nothing open any more

    @pytest.mark.asyncio
    async def test_a_password_change_ends_every_session(self, client, admin_token, org_and_users):
        second = await _login(client, org_and_users)
        r = await client.post("/api/v1/users/me/password", json={"current_password": org_and_users["password"],
                                                                 "new_password": "An0ther-Passw0rd!x"},
                              headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        new = r.json()["access_token"]
        assert (await _state(client, new))["status"] == "active"
        for old in (admin_token, second):
            assert (await client.get(S, headers=auth_headers(old))).status_code == 401


class TestPasskeys:
    @pytest.mark.asyncio
    async def test_register_certify_and_sign_out(self, client, admin_token, org_and_users, db_session):
        dev = SoftAuthenticator()
        r = await _register(client, admin_token, org_and_users, dev)
        assert r.status_code == 200, r.text
        assert [k["label"] for k in (await client.get(P, headers=auth_headers(admin_token))).json()] == ["laptop"]

        key, pub = _session_key()
        ch = await _challenge(client, admin_token, "session.certificate", {"public_key": pub})
        st = ch["statement"]
        assert st["type"] == "provenza.session.certificate" and st["public_key"] == pub
        assert ch["challenge"] == b64url(webauthn.statement_challenge(st))
        body = {"public_key": pub, "statement": st, "assertion": dev.get(ch["challenge"])}
        r = await client.post(f"{S}/certificate", json=body, headers=auth_headers(admin_token))
        assert r.status_code == 204, r.text
        state = await _state(client, admin_token)
        assert state["certified"] and state["public_key"] == pub
        body["assertion"] = dev.get(ch["challenge"])
        assert (await client.post(f"{S}/certificate", json=body, headers=auth_headers(admin_token))).status_code == 409

        revoke = {"type": "provenza.session.revoke", "v": 1, "session_id": state["session_id"],
                  "issued_at": int(time.time())}
        sig = base64.b64encode(key.sign(canonical_bytes(revoke))).decode()
        r = await client.post("/api/v1/auth/logout", json={"revocation": {"statement": revoke, "signature": sig}},
                              headers=auth_headers(admin_token))
        assert r.status_code == 204
        row = await db_session.get(SigningSession, state["session_id"])
        await db_session.refresh(row)
        assert row.status == "ended" and row.revocation["signature"] == sig

    @pytest.mark.asyncio
    async def test_a_statement_is_checked_exactly(self, client, admin_token, org_and_users):
        dev = SoftAuthenticator()
        assert (await _register(client, admin_token, org_and_users, dev)).status_code == 200
        _, pub = _session_key()
        _, other = _session_key()
        ch = await _challenge(client, admin_token, "session.certificate", {"public_key": pub})
        # the passkey signed a certificate for pub; the request asks for another key
        r = await client.post(f"{S}/certificate", json={"public_key": other, "statement": ch["statement"],
                                                         "assertion": dev.get(ch["challenge"])},
                              headers=auth_headers(admin_token))
        assert r.status_code == 422 and r.json()["detail"] == "passkey.statement_mismatch"
        stale = {**ch["statement"], "issued_at": int(time.time()) - 3600}
        r = await client.post(f"{S}/certificate", json={"public_key": pub, "statement": stale,
                                                         "assertion": dev.get(b64url(
                                                             webauthn.statement_challenge(stale)))},
                              headers=auth_headers(admin_token))
        assert r.status_code == 422 and r.json()["detail"] == "passkey.statement_stale"
        stranger = SoftAuthenticator()
        stranger.credential_id = dev.credential_id                     # the right id, another key
        r = await client.post(f"{S}/certificate", json={"public_key": pub, "statement": ch["statement"],
                                                         "assertion": stranger.get(ch["challenge"])},
                              headers=auth_headers(admin_token))
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_a_second_passkey_needs_the_first(self, client, admin_token, org_and_users):
        phone, laptop = SoftAuthenticator(-8), SoftAuthenticator()
        assert (await _register(client, admin_token, org_and_users, phone, label="phone")).status_code == 200
        r = await _register(client, admin_token, org_and_users, laptop)
        assert r.status_code == 422                                     # no vouch: refused
        r = await _register(client, admin_token, org_and_users, laptop, vouch_device=phone)
        assert r.status_code == 200, r.text
        opts = (await client.post(f"{P}/options", headers=auth_headers(admin_token))).json()
        bad = {"label": "x", "password": "wrong", **SoftAuthenticator().create(opts["challenge"])}
        assert (await client.post(P, json=bad, headers=auth_headers(admin_token))).status_code == 403

    @pytest.mark.asyncio
    async def test_with_a_passkey_only_the_passkey_admits(self, client, admin_token, org_and_users):
        dev = SoftAuthenticator()
        assert (await _register(client, admin_token, org_and_users, dev)).status_code == 200
        second = await _login(client, org_and_users)
        sid = (await _state(client, second))["session_id"]
        r = await client.post(f"{S}/admit", json={"blocked_session_id": sid, "password": org_and_users["password"]},
                              headers=auth_headers(admin_token))
        assert r.status_code == 422                                     # a password is not enough now
        ch = await _challenge(client, admin_token, "session.admit", {"blocked_session_id": sid})
        r = await client.post(f"{S}/admit", json={"blocked_session_id": sid, "statement": ch["statement"],
                                                  "assertion": dev.get(ch["challenge"])},
                              headers=auth_headers(admin_token))
        assert r.status_code == 204, r.text
        assert (await _state(client, second))["status"] == "active"

    @pytest.mark.asyncio
    async def test_a_blocked_session_takes_over_only_with_the_passkey(self, client, admin_token, org_and_users,
                                                                       db_session):
        dev = SoftAuthenticator()
        assert (await _register(client, admin_token, org_and_users, dev)).status_code == 200
        second = await _login(client, org_and_users)
        ch = await _challenge(client, second, "session.takeover")
        wrong = SoftAuthenticator()
        r = await client.post(f"{S}/takeover", json={"statement": ch["statement"],
                                                     "assertion": wrong.get(ch["challenge"])},
                              headers=auth_headers(second))
        assert r.status_code == 403
        r = await client.post(f"{S}/takeover", json={"statement": ch["statement"],
                                                     "assertion": dev.get(ch["challenge"])},
                              headers=auth_headers(second))
        assert r.status_code == 204, r.text
        assert (await _state(client, second))["status"] == "active"
        assert (await client.get(S, headers=auth_headers(admin_token))).status_code == 401
        n = (await db_session.execute(select(AIIncident).where(AIIncident.category == "session_conflict"))
             ).scalars().all()
        assert len(n) == 2                                               # the sign-in and the takeover

    @pytest.mark.asyncio
    async def test_removing_a_passkey(self, client, admin_token, org_and_users):
        dev = SoftAuthenticator()
        r = await _register(client, admin_token, org_and_users, dev)
        pid = r.json()["id"]
        ch = await _challenge(client, admin_token, "passkey.remove", {"passkey_id": pid})
        body = {"password": org_and_users["password"], "statement": ch["statement"],
                "assertion": dev.get(ch["challenge"])}
        r = await client.post(f"{P}/{pid}/remove", json=body, headers=auth_headers(admin_token))
        assert r.status_code == 204, r.text
        assert (await client.get(P, headers=auth_headers(admin_token))).json() == []

    @pytest.mark.asyncio
    async def test_approvers_sign_too(self, client, approver_token, org_and_users):
        assert (await _state(client, approver_token))["signing"] is True
        second = await _login(client, org_and_users, "approver")
        assert (await _state(client, second))["status"] == "blocked"
        assert ORIGIN.startswith("http://localhost")
