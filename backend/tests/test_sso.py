# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Single sign-on with OpenID Connect (app/services/sso.py, app/api/sso.py),
against a real provider over HTTP: discovery, keys, the token endpoint with
PKCE and the client secret, then everything Provenza checks.
"""

import base64
import hashlib
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select, update

from app.core.config import settings
from app.models.organization import Organization
from app.models.user import User
from app.services import sso as sso_svc
from tests.conftest import auth_headers

A = "/api/v1/auth/sso"
ADMIN = "/api/v1/sso"
CLIENT_ID, SECRET = "provenza-app", "s3cret-of-the-client"


class Provider:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update(kid="idp-1", use="sig", alg="RS256")
        self.jwks = {"keys": [jwk]}
        self.codes = {}          # code -> (challenge, claims)
        self.overrides = {}      # claim changes for the next token
        outer = self

        class H(BaseHTTPRequestHandler):
            def _json(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                if self.path == "/.well-known/openid-configuration":
                    self._json(200, {"issuer": outer.issuer, "authorization_endpoint": outer.issuer + "/authorize",
                                     "token_endpoint": outer.issuer + "/token", "jwks_uri": outer.issuer + "/jwks"})
                elif self.path == "/jwks":
                    self._json(200, outer.jwks)
                else:
                    self._json(404, {})

            def do_POST(self):
                form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
                code = form.get("code", [""])[0]
                if code not in outer.codes or form.get("client_secret") != [SECRET] \
                        or form.get("client_id") != [CLIENT_ID]:
                    return self._json(400, {"error": "invalid_grant"})
                challenge, claims = outer.codes.pop(code)
                verifier = form["code_verifier"][0]
                if base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode() != challenge:
                    return self._json(400, {"error": "invalid_grant", "error_description": "PKCE"})
                token = jwt.encode(claims, outer.key, algorithm="RS256", headers={"kid": "idp-1"})
                self._json(200, {"access_token": "at", "token_type": "Bearer", "id_token": token})

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.issuer = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def authorize(self, location: str, **claims) -> str:
        """What the provider does after the user signs in there: a code for these claims."""
        q = {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
        assert q["code_challenge_method"] == "S256" and q["client_id"] == CLIENT_ID
        now = int(time.time())
        base = {"iss": self.issuer, "aud": CLIENT_ID, "sub": "idp-user-1", "iat": now, "exp": now + 300,
                "nonce": q["nonce"], "email": "ann@acme.example", "email_verified": True, "name": "Ann"}
        code = secrets.token_urlsafe(16)
        self.codes[code] = (q["code_challenge"], {**base, **claims})
        return f"{A}/callback?code={code}&state={q['state']}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def idp(monkeypatch):
    monkeypatch.setattr(settings, "OUTBOUND_PRIVATE_ALLOWLIST", "127.0.0.1")
    sso_svc._cache.clear()
    p = Provider()
    yield p
    p.close()


async def _configure(client, token, idp, **over):
    body = {"issuer": idp.issuer, "client_id": CLIENT_ID, "client_secret": SECRET, **over}
    r = await client.put(f"{ADMIN}/settings", json=body, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _slug(db_session):
    return (await db_session.execute(select(Organization.slug))).scalars().first()


async def _sign_in(client, idp, slug, **claims):
    """The browser's whole trip; returns (where it lands, the session token or None)."""
    r = await client.get(f"{A}/{slug}/start", follow_redirects=False)
    assert r.status_code == 302, r.text
    r = await client.get(idp.authorize(r.headers["location"], **claims), follow_redirects=False)
    assert r.status_code == 302
    landing = r.headers["location"]
    if not landing.startswith("/login/sso#code="):
        return landing, None
    code = landing.split("#code=", 1)[1]
    r = await client.post(f"{A}/exchange", json={"code": code})
    assert r.status_code == 200, r.text
    return landing, r.json()["access_token"]


async def _user(db_session, email="ann@acme.example"):
    org_id = (await db_session.execute(select(Organization.id))).scalars().first()
    db_session.add(User(org_id=org_id, email=email, name="Ann", hashed_password="!", role="user", status="active"))
    await db_session.commit()


@pytest.mark.asyncio
async def test_settings(client, admin_token, approver_token, idp):
    body = {"issuer": idp.issuer, "client_id": CLIENT_ID, "client_secret": SECRET}
    assert (await client.put(f"{ADMIN}/settings", json=body, headers=auth_headers(approver_token))).status_code == 403
    r = await client.put(f"{ADMIN}/settings", json={**body, "issuer": "http://idp.example.com"},
                         headers=auth_headers(admin_token))
    assert r.status_code == 422 and r.json()["detail"]["code"] == "sso.bad_issuer"       # https only
    r = await client.put(f"{ADMIN}/settings", json={**body, "issuer": idp.issuer + "/nope"},
                         headers=auth_headers(admin_token))
    assert r.status_code == 422                                                        # discovery checked first
    out = await _configure(client, admin_token, idp, allowed_domains=["@ACME.example"])
    assert out["has_secret"] and "client_secret" not in out and out["allowed_domains"] == ["acme.example"]
    assert out["redirect_uri"].endswith("/api/v1/auth/sso/callback")


@pytest.mark.asyncio
async def test_a_full_sign_in(client, admin_token, idp, db_session):
    await _configure(client, admin_token, idp)
    await _user(db_session)
    slug = await _slug(db_session)
    assert (await client.get(f"{A}/{slug}/info")).json() == {"sso": True, "password": True}
    assert (await client.get(f"{A}/no-such-org/info")).json() == {"sso": False, "password": True}
    landing, token = await _sign_in(client, idp, slug)
    me = await client.get("/api/v1/users/me", headers=auth_headers(token))
    assert me.status_code == 200 and me.json()["email"] == "ann@acme.example"
    # the hand-off code works once
    code = landing.split("#code=", 1)[1]
    assert (await client.post(f"{A}/exchange", json={"code": code})).status_code == 401
    u = (await db_session.execute(select(User).where(User.email == "ann@acme.example"))).scalar_one()
    await db_session.refresh(u)
    assert u.oidc_subject == f"{idp.issuer} idp-user-1"


@pytest.mark.asyncio
@pytest.mark.parametrize("claims,code", [
    ({"nonce": "forged"}, "sso.bad_token"),
    ({"aud": "another-app"}, "sso.bad_token"),
    ({"iss": "http://127.0.0.1:1"}, "sso.bad_token"),
    ({"exp": int(time.time()) - 3600}, "sso.bad_token"),
    ({"email_verified": False}, "sso.email_unverified"),
    ({"email": "eve@evil.example"}, "sso.domain_not_allowed"),
    ({"email": "nobody@acme.example"}, "sso.no_account"),
])
async def test_what_is_refused(client, admin_token, idp, db_session, claims, code):
    await _configure(client, admin_token, idp, allowed_domains=["acme.example"])
    await _user(db_session)
    landing, token = await _sign_in(client, idp, await _slug(db_session), **claims)
    assert token is None and landing == f"/login?sso_error={code}"


@pytest.mark.asyncio
async def test_no_state_no_sign_in(client, admin_token, idp, db_session):
    await _configure(client, admin_token, idp)
    r = await client.get(f"{A}/callback?code=x&state=y", follow_redirects=False)
    assert r.headers["location"] == "/login?sso_error=sso.bad_state"


@pytest.mark.asyncio
async def test_a_signed_by_someone_else_token_is_refused(client, admin_token, idp, db_session):
    await _configure(client, admin_token, idp)
    await _user(db_session)
    idp.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)    # signs with a key it never published
    landing, token = await _sign_in(client, idp, await _slug(db_session))
    assert landing == "/login?sso_error=sso.bad_token"


@pytest.mark.asyncio
async def test_bound_to_the_provider_account(client, admin_token, idp, db_session):
    await _configure(client, admin_token, idp)
    await _user(db_session)
    slug = await _slug(db_session)
    assert (await _sign_in(client, idp, slug))[1]
    # the provider gives the e-mail to another account
    landing, _ = await _sign_in(client, idp, slug, sub="idp-user-2")
    assert landing == "/login?sso_error=sso.subject_mismatch"


@pytest.mark.asyncio
async def test_jit_creates_with_the_default_role(client, admin_token, idp, db_session):
    await _configure(client, admin_token, idp, jit=True, default_role="approver", allowed_domains=["acme.example"])
    _, token = await _sign_in(client, idp, await _slug(db_session), email="new@acme.example")
    assert (await client.get("/api/v1/users/me", headers=auth_headers(token))).json()["role"] == "approver"


@pytest.mark.asyncio
async def test_the_mfa_policy_needs_the_providers_second_factor(client, admin_token, idp, db_session):
    await _configure(client, admin_token, idp)
    await _user(db_session)
    await db_session.execute(update(Organization).values(mfa_required="all"))
    await db_session.commit()
    slug = await _slug(db_session)
    landing, _ = await _sign_in(client, idp, slug, amr=["pwd"])
    assert landing == "/login?sso_error=sso.mfa_required"
    _, token = await _sign_in(client, idp, slug, amr=["pwd", "mfa"])
    # a password session without our TOTP is held to enrolling ...
    held = await client.get("/api/v1/agents/", headers=auth_headers(admin_token))
    assert held.status_code == 403 and held.json()["detail"] == "auth.mfa_setup_required"
    # ... the provider vouched for this one's second factor: no TOTP of ours is asked
    assert (await client.get("/api/v1/agents/", headers=auth_headers(token))).status_code == 200
    await db_session.execute(update(Organization).values(mfa_required="none"))
    await db_session.commit()


@pytest.mark.asyncio
async def test_sso_only_leaves_passwords_to_admins(client, admin_token, approver_token, idp, db_session):
    await _configure(client, admin_token, idp, enforce=True)
    slug = await _slug(db_session)
    assert (await client.get(f"{A}/{slug}/info")).json() == {"sso": True, "password": False}
    r = await client.post("/api/v1/auth/login", json={"org_slug": slug, "email": "approver@test.example.com",
                                                       "password": "TestPass123!"})
    assert r.status_code == 403 and r.json()["detail"] == "auth.sso_required"
    r = await client.post("/api/v1/auth/login", json={"org_slug": slug, "email": "admin@test.example.com",
                                                       "password": "TestPass123!"})
    assert r.status_code == 200                       # the break-glass way in


@pytest.mark.asyncio
async def test_jit_needs_allowed_domains(client, admin_token, idp, db_session):
    body = {"issuer": idp.issuer, "client_id": CLIENT_ID, "client_secret": SECRET, "jit": True}
    r = await client.put(f"{ADMIN}/settings", json=body, headers=auth_headers(admin_token))
    assert r.status_code == 422
    assert r.json()["detail"] == "sso.jit_needs_domains"


@pytest.mark.asyncio
async def test_an_unconfirmed_email_needs_a_domain(client, admin_token, idp, db_session):
    await _configure(client, admin_token, idp)
    await _user(db_session)
    landing, token = await _sign_in(client, idp, await _slug(db_session), email_verified=None)
    assert token is None and landing == "/login?sso_error=sso.email_unverified"
