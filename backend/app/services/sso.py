# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Single sign-on with OpenID Connect (authorization code + PKCE): Okta,
Microsoft Entra ID, Google Workspace, Keycloak, Authentik, any OIDC provider.

  start      a state, a nonce and a PKCE verifier, sealed in a short-lived
             HttpOnly cookie (encrypted with the server key); the browser
             goes to the provider's authorization endpoint
  callback   the state must match the cookie; the code is exchanged (with
             the verifier and the client secret); the id_token is verified -
             signature against the provider's keys (discovery), iss, aud,
             exp / iat, nonce; e-mail verified when the provider says so,
             and in an allowed domain
  the user   found by e-mail in the organization (created when "jit" is on);
             bound to the provider's account on the first sign-in (iss + sub):
             if the provider later gives that e-mail to someone else, their
             sign-in is refused
  MFA        where the organization requires a second factor of this user,
             the provider must say it used one (amr), and then Provenza does
             not ask for its own; with require_idp_mfa, for everyone
  hand-off   a one-time code (60 s, single use) in the URL fragment of
             /login/sso - not in the query, so it reaches no server log - which
             the web app exchanges for a normal session token

"enforce" leaves passwords to admins only: the break-glass way in when the
provider is down.
"""

import base64
import hashlib
import json
import secrets
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from fastapi import status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_secret, encrypt_secret
from app.core.errors import api_error
from app.core.outbound import guarded_async_client
from app.models.scim import OidcSettings
from app.models.user import User

STATE_TTL = 600
EXCHANGE_TTL = 60
CACHE_TTL = 3600
ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]
MFA_AMR = {"mfa", "otp", "hwk", "swk", "sms", "fpt", "face", "iris", "retina", "sc", "tel", "kba"}
DEFAULT_ROLES = ("user", "approver")
_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}


class SsoError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


# ---------------------------------------------------------------- provider

def check_issuer(url: str) -> str:
    """https, or http to this very host (a provider in development)."""
    url = (url or "").strip().rstrip("/")
    parts = urlsplit(url)
    if not parts.hostname or parts.username or parts.password:
        raise SsoError("sso.bad_issuer", "an https URL")
    if parts.scheme != "https" and not (parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1")):
        raise SsoError("sso.bad_issuer", "https is required")
    return url


async def _get_json(url: str) -> Dict[str, Any]:
    check_issuer(url)
    try:
        async with guarded_async_client(timeout=10.0) as c:
            r = await c.get(url, headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        raise SsoError("sso.provider_unreachable", type(exc).__name__)
    if r.status_code != 200 or len(r.content) > 512 * 1024:
        raise SsoError("sso.provider_error", f"HTTP {r.status_code}")
    try:
        data = r.json()
    except ValueError:
        raise SsoError("sso.provider_error", "not JSON")
    if not isinstance(data, dict):
        raise SsoError("sso.provider_error", "not a JSON object")
    return data


async def discovery(issuer: str, refresh: bool = False) -> Dict[str, Any]:
    """The provider's metadata; it must name this issuer."""
    hit = _cache.get("d:" + issuer)
    if hit and not refresh and hit[0] > time.monotonic():
        return hit[1]
    doc = await _get_json(issuer + "/.well-known/openid-configuration")
    if str(doc.get("issuer", "")).rstrip("/") != issuer:
        raise SsoError("sso.provider_error", "the discovery document names another issuer")
    for k in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not isinstance(doc.get(k), str):
            raise SsoError("sso.provider_error", f"no {k}")
        check_issuer(doc[k])
    _cache["d:" + issuer] = (time.monotonic() + CACHE_TTL, doc)
    return doc


async def _jwks(uri: str, refresh: bool = False) -> Dict[str, Any]:
    hit = _cache.get("k:" + uri)
    if hit and not refresh and hit[0] > time.monotonic():
        return hit[1]
    doc = await _get_json(uri)
    if not isinstance(doc.get("keys"), list):
        raise SsoError("sso.provider_error", "no keys")
    _cache["k:" + uri] = (time.monotonic() + CACHE_TTL, doc)
    return doc


def _key(jwks: Dict[str, Any], kid: Optional[str], alg: str):
    keys = [k for k in jwks.get("keys", []) if isinstance(k, dict) and (kid is None or k.get("kid") == kid)]
    if len(keys) != 1:
        return None
    try:
        return jwt.PyJWK(keys[0], algorithm=alg).key
    except jwt.PyJWTError:
        return None


async def verify_id_token(token: str, cfg: OidcSettings, nonce: str) -> Dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise SsoError("sso.bad_token", "not a JWT")
    alg = header.get("alg")
    if alg not in ALGORITHMS:
        raise SsoError("sso.bad_token", f"algorithm {alg}")
    doc = await discovery(cfg.issuer)
    key = _key(await _jwks(doc["jwks_uri"]), header.get("kid"), alg)
    if key is None:   # the provider may have rotated its keys
        key = _key(await _jwks(doc["jwks_uri"], refresh=True), header.get("kid"), alg)
    if key is None:
        raise SsoError("sso.bad_token", "signed by an unknown key")
    try:
        claims = jwt.decode(token, key, algorithms=[alg], audience=cfg.client_id, issuer=cfg.issuer, leeway=60,
                            options={"require": ["iss", "aud", "exp", "iat", "sub"]})
    except jwt.PyJWTError as exc:
        raise SsoError("sso.bad_token", type(exc).__name__)
    aud = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
    if len(aud) > 1 and claims.get("azp") != cfg.client_id:
        raise SsoError("sso.bad_token", "azp")
    if not nonce or not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise SsoError("sso.bad_token", "nonce")
    return claims


# ---------------------------------------------------------------- settings

async def get_settings(db: AsyncSession, org_id: int) -> Optional[OidcSettings]:
    return (await db.execute(select(OidcSettings).where(OidcSettings.org_id == org_id))).scalar_one_or_none()


def settings_out(row: Optional[OidcSettings], redirect_uri: str) -> Dict[str, Any]:
    base = {"redirect_uri": redirect_uri}
    if row is None:
        return {**base, "enabled": False, "issuer": None, "client_id": None, "has_secret": False, "email_claim": "email",
                "allowed_domains": [], "jit": False, "default_role": "user", "enforce": False, "require_idp_mfa": False}
    return {**base, "enabled": row.enabled, "issuer": row.issuer, "client_id": row.client_id,
            "has_secret": bool(row.client_secret_encrypted), "email_claim": row.email_claim,
            "allowed_domains": list(row.allowed_domains or []), "jit": row.jit, "default_role": row.default_role,
            "enforce": row.enforce, "require_idp_mfa": row.require_idp_mfa}


# ---------------------------------------------------------------- the flow

def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


async def start(cfg: OidcSettings, redirect_uri: str, org_id: int) -> Tuple[str, str]:
    """(the provider URL to send the browser to, the sealed state cookie)."""
    doc = await discovery(cfg.issuer)
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    challenge = _b64(hashlib.sha256(verifier.encode()).digest())
    sealed = encrypt_secret(json.dumps({"org": org_id, "state": state, "nonce": nonce, "verifier": verifier,
                                        "at": int(time.time())}))
    params = {"response_type": "code", "client_id": cfg.client_id, "redirect_uri": redirect_uri,
              "scope": "openid email profile", "state": state, "nonce": nonce,
              "code_challenge": challenge, "code_challenge_method": "S256"}
    return doc["authorization_endpoint"] + ("&" if "?" in doc["authorization_endpoint"] else "?") + urlencode(params), sealed


def unseal(cookie: Optional[str], state: Optional[str]) -> Dict[str, Any]:
    if not cookie or not state:
        raise SsoError("sso.bad_state", "no sign-in in progress")
    try:
        data = json.loads(decrypt_secret(cookie))
    except (ValueError, TypeError):
        raise SsoError("sso.bad_state", "unreadable")
    if not secrets.compare_digest(str(data.get("state", "")), state) or time.time() - data.get("at", 0) > STATE_TTL:
        raise SsoError("sso.bad_state", "the sign-in expired or was started elsewhere")
    return data


async def exchange_code(cfg: OidcSettings, code: str, verifier: str, redirect_uri: str) -> Dict[str, Any]:
    doc = await discovery(cfg.issuer)
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
            "client_id": cfg.client_id, "code_verifier": verifier}
    if cfg.client_secret_encrypted:
        form["client_secret"] = decrypt_secret(cfg.client_secret_encrypted)
    try:
        async with guarded_async_client(timeout=10.0) as c:
            r = await c.post(doc["token_endpoint"], data=form, headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        raise SsoError("sso.provider_unreachable", type(exc).__name__)
    try:
        body = r.json()
    except ValueError:
        body = {}
    if r.status_code != 200 or not isinstance(body, dict) or not isinstance(body.get("id_token"), str):
        raise SsoError("sso.code_refused", str(body.get("error", r.status_code))[:80] if isinstance(body, dict) else "")
    return body


async def user_for(db: AsyncSession, cfg: OidcSettings, claims: Dict[str, Any]) -> Tuple[User, bool]:
    """(the user, whether the provider vouched for a second factor)."""
    from app.services import mfa as mfa_svc
    from app.core.security import get_password_hash
    from app.services.audit_service import AuditService

    email = claims.get(cfg.email_claim) or (claims.get("email") if cfg.email_claim != "email" else None)
    if not isinstance(email, str) or "@" not in email:
        raise SsoError("sso.no_email", f"the provider sent no {cfg.email_claim}")
    if claims.get("email_verified") is False:
        raise SsoError("sso.email_unverified")
    email = email.strip().lower()
    domains = [d.lower().lstrip("@") for d in (cfg.allowed_domains or [])]
    if domains and email.rsplit("@", 1)[1] not in domains:
        raise SsoError("sso.domain_not_allowed", email.rsplit("@", 1)[1])
    subject = f"{claims['iss']} {claims['sub']}"[:600]
    user = (await db.execute(select(User).where(User.org_id == cfg.org_id,
                                                func.lower(User.email) == email))).scalar_one_or_none()
    if user is None:
        if not cfg.jit:
            raise SsoError("sso.no_account", "ask an admin to add you, or provision users from the provider")
        name = str(claims.get("name") or email.split("@")[0])[:255]
        user = User(org_id=cfg.org_id, email=email, name=name, hashed_password=get_password_hash(secrets.token_urlsafe(32)),
                    role=cfg.default_role if cfg.default_role in DEFAULT_ROLES else "user", status="active",
                    oidc_subject=subject)
        db.add(user)
        await db.commit()
        await db.refresh(user)
        await AuditService(db).log(cfg.org_id, None, "user", user.id, "sso_created", {"email": email, "role": user.role})
    if user.status != "active":
        raise SsoError("sso.account_disabled")
    if user.oidc_subject is None:
        user.oidc_subject = subject   # bound to this provider account from now on
        await db.commit()
    elif not secrets.compare_digest(user.oidc_subject, subject):
        raise SsoError("sso.subject_mismatch", "this e-mail belongs to another account at the provider")
    amr = claims.get("amr") if isinstance(claims.get("amr"), list) else []
    idp_mfa = bool(MFA_AMR & {str(a).lower() for a in amr})
    if not idp_mfa and (cfg.require_idp_mfa or await mfa_svc.required_for(db, user)):
        raise SsoError("sso.mfa_required", "the provider did not report a second factor (amr)")
    return user, idp_mfa
