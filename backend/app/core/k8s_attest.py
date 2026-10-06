# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Kubernetes ServiceAccount tokens as workload attestation (pure functions).

A pod gets a projected ServiceAccount token from the kubelet: a JWT signed by
the cluster's service-account issuer key, naming the namespace, the service
account and the pod it is bound to, for the audience the pod spec asked for.
Checked here: signature against the issuer's JWKS, iss, aud, exp/nbf/iat,
that it is bound to a pod, and that its namespace / service account are
allowed. Binding to the agent (the agent signs the token's hash with its own
key over a server challenge) is done by services/attestation.py.

    volumes:
    - name: provenza-token
      projected:
        sources:
        - serviceAccountToken: {audience: provenza, expirationSeconds: 3600, path: token}
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import jwt

# asymmetric only: an HMAC or "none" token proves nothing about the cluster
ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]
LEEWAY_SECONDS = 30
# a token living longer than this is refused: a copied long-lived token would
# otherwise re-attest from anywhere (kubelet-projected tokens: 10 min - a few
# hours; an apiserver without --service-account-max-token-expiration accepts
# a year)
MAX_TOKEN_LIFETIME_SECONDS = 24 * 3600
SA_PREFIX = "system:serviceaccount:"


class AttestationError(ValueError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def token_sha256(token: str) -> str:
    return hashlib.sha256(token.strip().encode()).hexdigest()


def check_jwks(jwks: Any) -> Dict[str, Any]:
    """A JWKS document with at least one usable asymmetric key."""
    if isinstance(jwks, str):
        try:
            jwks = json.loads(jwks)
        except ValueError:
            raise AttestationError("attestation.bad_jwks", "not JSON")
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list) or not jwks["keys"]:
        raise AttestationError("attestation.bad_jwks", 'expected {"keys": [...]}')
    usable = 0
    for k in jwks["keys"]:
        if not isinstance(k, dict) or k.get("kty") not in ("RSA", "EC"):
            continue
        try:
            jwt.PyJWK(k)
            usable += 1
        except Exception:  # noqa: BLE001 - a key PyJWT cannot load is just not usable
            continue
    if not usable:
        raise AttestationError("attestation.bad_jwks", "no RSA or EC key in it")
    return jwks


def unverified_header(token: str) -> Dict[str, Any]:
    try:
        return jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise AttestationError("attestation.bad_token", "not a JWT")


def unverified_issuer(token: str) -> Optional[str]:
    try:
        return jwt.decode(token, options={"verify_signature": False}).get("iss")
    except jwt.PyJWTError:
        return None


def _key_for(jwks: Dict[str, Any], kid: Optional[str], alg: str):
    keys = [k for k in jwks.get("keys", []) if isinstance(k, dict) and k.get("kty") in ("RSA", "EC")]
    if kid is not None:
        keys = [k for k in keys if k.get("kid") == kid]
    elif len(keys) != 1:
        raise AttestationError("attestation.unknown_key", "the token names no key id")
    if not keys:
        raise AttestationError("attestation.unknown_key", f"no key {kid!r} in the issuer's JWKS")
    try:
        return jwt.PyJWK(keys[0], algorithm=alg).key
    except jwt.PyJWTError as e:
        raise AttestationError("attestation.unknown_key", str(e))


def verify_token(token: str, *, issuer: str, audience: str, jwks: Dict[str, Any],
                 now: Optional[datetime] = None) -> Dict[str, Any]:
    """Verify a ServiceAccount token. Returns the normalized identity:
    sub, namespace, service_account, service_account_uid, pod, pod_uid, node,
    iat, exp (epoch seconds)."""
    token = (token or "").strip()
    header = unverified_header(token)
    alg = header.get("alg")
    if alg not in ALGORITHMS:
        raise AttestationError("attestation.bad_algorithm", str(alg))
    key = _key_for(jwks, header.get("kid"), alg)
    now = now or datetime.now(timezone.utc)
    try:
        claims = jwt.decode(
            token, key, algorithms=[alg], audience=audience, issuer=issuer, leeway=LEEWAY_SECONDS,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        raise AttestationError("attestation.token_expired")
    except jwt.InvalidAudienceError:
        raise AttestationError("attestation.wrong_audience", f"expected {audience!r}")
    except jwt.InvalidIssuerError:
        raise AttestationError("attestation.wrong_issuer", f"expected {issuer!r}")
    except jwt.InvalidSignatureError:
        raise AttestationError("attestation.bad_signature")
    except jwt.MissingRequiredClaimError as e:
        raise AttestationError("attestation.bad_token", str(e))
    except jwt.ImmatureSignatureError:
        raise AttestationError("attestation.token_not_yet_valid")
    except jwt.PyJWTError as e:
        raise AttestationError("attestation.bad_token", str(e))
    # PyJWT checks against the wall clock; `now` lets tests and the caller agree
    if claims["exp"] + LEEWAY_SECONDS < now.timestamp():
        raise AttestationError("attestation.token_expired")
    if claims["iat"] - LEEWAY_SECONDS > now.timestamp():
        raise AttestationError("attestation.token_not_yet_valid")
    k8s = claims.get("kubernetes.io") or {}
    if not isinstance(k8s, dict):
        k8s = {}
    # an auto-extended token (requested for ~1h, issued for a year so old
    # clients keep working) says when it should have expired: that counts
    exp = int(claims["exp"])
    warn_after = k8s.get("warnafter")
    if isinstance(warn_after, (int, float)) and not isinstance(warn_after, bool) and warn_after < exp:
        exp = int(warn_after)
    if exp + LEEWAY_SECONDS < now.timestamp():
        raise AttestationError("attestation.token_expired")
    if exp - claims["iat"] > MAX_TOKEN_LIFETIME_SECONDS:
        raise AttestationError("attestation.token_too_long_lived",
                               f"{int(exp - claims['iat'])} s")

    sub = claims["sub"]
    if not isinstance(sub, str) or not sub.startswith(SA_PREFIX) or sub.count(":") != 3:
        raise AttestationError("attestation.not_a_service_account", str(sub)[:120])
    namespace, sa = sub[len(SA_PREFIX):].split(":")
    # the structured claims must say the same as sub
    if k8s.get("namespace", namespace) != namespace or (k8s.get("serviceaccount") or {}).get("name", sa) != sa:
        raise AttestationError("attestation.bad_token", "kubernetes.io claims disagree with sub")
    pod = k8s.get("pod") or {}
    node = k8s.get("node") or {}
    return {
        "iss": claims["iss"], "sub": sub, "namespace": namespace, "service_account": sa,
        "service_account_uid": (k8s.get("serviceaccount") or {}).get("uid"),
        "pod": pod.get("name"), "pod_uid": pod.get("uid"), "node": node.get("name"),
        "iat": int(claims["iat"]), "exp": exp,
    }


def _matches(value: str, patterns: List[str]) -> bool:
    return any(fnmatch.fnmatchcase(value, p) for p in patterns)


def check_identity(identity: Dict[str, Any], *, namespaces: List[str], service_accounts: List[str],
                   require_pod: bool) -> None:
    """namespaces: patterns like "agents" or "team-*"; service_accounts:
    "namespace/name" patterns. A token passes when its namespace matches a
    namespace pattern OR its namespace/name matches a service-account pattern."""
    if require_pod and not identity.get("pod_uid"):
        raise AttestationError("attestation.not_pod_bound")
    ns, sa = identity["namespace"], identity["service_account"]
    if _matches(ns, namespaces) or _matches(f"{ns}/{sa}", service_accounts):
        return
    raise AttestationError("attestation.workload_not_allowed", f"{ns}/{sa}")


# audiences that make a token an API-server credential: a token Provenza
# accepts must be good for nothing else
API_SERVER_AUDIENCES = ("https://kubernetes.default.svc", "https://kubernetes.default.svc.cluster.local",
                        "kubernetes", "api", "")


def check_audience(audience: str, issuer: str) -> None:
    a = (audience or "").strip()
    if a.rstrip("/") in API_SERVER_AUDIENCES or a.rstrip("/") == (issuer or "").strip().rstrip("/"):
        raise AttestationError("attestation.audience_is_api_server",
                               "use an audience only Provenza accepts, e.g. provenza")


def normalize_patterns(values: Optional[List[str]], *, with_slash: bool) -> List[str]:
    out = []
    for v in values or []:
        v = str(v).strip()
        if not v:
            continue
        if len(v) > 253 or any(c.isspace() for c in v) or (with_slash and v.count("/") != 1) \
                or (not with_slash and "/" in v):
            raise AttestationError("attestation.bad_pattern", v[:80])
        out.append(v)
    return sorted(set(out))
