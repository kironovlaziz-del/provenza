# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
OIDC workload identity tokens as attestation (pure functions) - beside the
Kubernetes kind (core/k8s_attest.py), for workloads outside a cluster:

  GitHub Actions   iss https://token.actions.githubusercontent.com
                   rules on repository / repository_owner / ref / environment ...
  Google Cloud     iss https://accounts.google.com (metadata server identity token)
                   rules on google.compute_engine.project_id / instance_name, email ...
  Azure            iss https://sts.windows.net/<tenant>/ (managed identity token)
                   rules on xms_mirid, oid ...
  GitLab CI        iss https://gitlab.com, rules on project_path / ref ...
  SPIFFE           JWT-SVID, rules on sub (spiffe://trust-domain/workload)

The token's signature is checked against the issuer's keys (pasted, or
fetched over https by discovery), with iss, aud and the validity window;
then every claim rule must match. Rules are what make a public issuer safe:
without one, any repository on GitHub would pass - so a policy without a
rule on a workload claim is refused.
"""

from __future__ import annotations

import fnmatch
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import jwt

from app.core.k8s_attest import (ALGORITHMS, LEEWAY_SECONDS, MAX_TOKEN_LIFETIME_SECONDS, AttestationError, _key_for,
                                 unverified_header)

# claims that say nothing about which workload it is
NOT_WORKLOAD_CLAIMS = {"iss", "aud", "exp", "iat", "nbf", "jti", "azp"}
CLAIM_PATH = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_:/-]{0,63}(\.[A-Za-z0-9_][A-Za-z0-9_:/-]{0,63}){0,4}$")
MAX_RULES = 20
MAX_PATTERNS = 20

PRESETS = {
    "github_actions": {"issuer": "https://token.actions.githubusercontent.com",
                       "claim_rules": {"repository": ["your-org/your-repo"], "ref": ["refs/heads/main"]}},
    "gcp": {"issuer": "https://accounts.google.com",
            "claim_rules": {"google.compute_engine.project_id": ["your-project"], "email": ["agent@your-project.iam.gserviceaccount.com"]}},
    "azure": {"issuer": "https://sts.windows.net/<tenant-id>/",
              "claim_rules": {"xms_mirid": ["/subscriptions/<subscription>/resourcegroups/<group>/*"]}},
    "gitlab": {"issuer": "https://gitlab.com", "claim_rules": {"project_path": ["your-group/your-project"],
                                                               "ref_protected": ["true"]}},
    "spiffe": {"issuer": "https://spire.example.com", "claim_rules": {"sub": ["spiffe://example.org/agents/*"]}},
}


def normalize_rules(rules: Any) -> Dict[str, List[str]]:
    """{claim path: [patterns]}: dotted paths into the claims, fnmatch patterns.
    At least one rule on a workload claim; no rule that matches everything."""
    if not isinstance(rules, dict) or not rules:
        raise AttestationError("attestation.rules_required", "a claim rule names the workload")
    if len(rules) > MAX_RULES:
        raise AttestationError("attestation.bad_rule", "too many rules")
    out: Dict[str, List[str]] = {}
    for path, patterns in rules.items():
        if not isinstance(path, str) or not CLAIM_PATH.match(path):
            raise AttestationError("attestation.bad_rule", str(path)[:80])
        if isinstance(patterns, str):
            patterns = [patterns]
        if not isinstance(patterns, list) or not patterns or len(patterns) > MAX_PATTERNS:
            raise AttestationError("attestation.bad_rule", f"{path}: one to {MAX_PATTERNS} patterns")
        clean = []
        for p in patterns:
            p = str(p).strip()
            if not p or len(p) > 300 or any(c in "\r\n\t" for c in p):
                raise AttestationError("attestation.bad_rule", f"{path}: {p[:60]!r}")
            if not p.strip("*?"):
                raise AttestationError("attestation.rule_matches_everything", path)
            clean.append(p)
        out[path] = sorted(set(clean))
    if not set(out) - NOT_WORKLOAD_CLAIMS:
        raise AttestationError("attestation.rules_required", "a rule on a workload claim (sub, repository, ...)")
    return out


def claim(claims: Dict[str, Any], path: str) -> Optional[str]:
    """A scalar claim at a dotted path, as text (true/false for booleans)."""
    value: Any = claims
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    return None


def verify_token(token: str, *, issuer: str, audience: str, jwks: Dict[str, Any], rules: Dict[str, List[str]],
                 now: Optional[datetime] = None) -> Dict[str, Any]:
    """The identity in a verified token that passes every rule:
    {iss, sub, claims: {rule path: value}, iat, exp}."""
    token = (token or "").strip()
    header = unverified_header(token)
    alg = header.get("alg")
    if alg not in ALGORITHMS:
        raise AttestationError("attestation.bad_algorithm", str(alg))
    key = _key_for(jwks, header.get("kid"), alg)
    now = now or datetime.now(timezone.utc)
    try:
        claims = jwt.decode(token, key, algorithms=[alg], audience=audience, issuer=issuer, leeway=LEEWAY_SECONDS,
                            options={"require": ["exp", "iat", "iss", "aud", "sub"]})
    except jwt.ExpiredSignatureError:
        raise AttestationError("attestation.token_expired")
    except jwt.InvalidAudienceError:
        raise AttestationError("attestation.wrong_audience", f"expected {audience!r}")
    except jwt.InvalidIssuerError:
        raise AttestationError("attestation.wrong_issuer", f"expected {issuer!r}")
    except jwt.InvalidSignatureError:
        raise AttestationError("attestation.bad_signature")
    except jwt.ImmatureSignatureError:
        raise AttestationError("attestation.token_not_yet_valid")
    except jwt.PyJWTError as e:
        raise AttestationError("attestation.bad_token", str(e))
    if claims["exp"] + LEEWAY_SECONDS < now.timestamp():
        raise AttestationError("attestation.token_expired")
    if claims["iat"] - LEEWAY_SECONDS > now.timestamp():
        raise AttestationError("attestation.token_not_yet_valid")
    if claims["exp"] - claims["iat"] > MAX_TOKEN_LIFETIME_SECONDS:
        raise AttestationError("attestation.token_too_long_lived", f"{int(claims['exp'] - claims['iat'])} s")
    if not isinstance(claims["sub"], str) or not claims["sub"]:
        raise AttestationError("attestation.bad_token", "no subject")
    seen: Dict[str, Optional[str]] = {}
    for path, patterns in rules.items():
        value = claim(claims, path)
        seen[path] = value
        if value is None or not any(fnmatch.fnmatchcase(value, p) for p in patterns):
            raise AttestationError("attestation.workload_not_allowed", f"{path}={value!r}"[:200])
    return {"iss": claims["iss"], "sub": claims["sub"], "claims": seen, "iat": int(claims["iat"]),
            "exp": int(claims["exp"])}
