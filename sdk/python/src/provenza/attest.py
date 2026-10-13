# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Workload attestation: the agent proves where it runs (server side:
app/services/attestation.py). The evidence is a token the platform gives the
workload; the agent signs its hash with its own key over a server challenge,
so a token copied elsewhere is useless without the agent's key.

    from provenza import attest
    agent.attest(attest.token_file())                    # Kubernetes projected ServiceAccount token
    agent.attest(attest.github_actions("provenza"))      # GitHub Actions OIDC
    agent.attest(attest.gcp_metadata("provenza"))        # Google Cloud metadata server
    agent.attest(attest.azure_imds("api://provenza"))    # Azure managed identity

Attest at start-up and again before the attestation's validity ends (the
policy's validity, never past the token's expiry).
"""

import os
from typing import Optional

import httpx

K8S_TOKEN_PATH = "/var/run/secrets/provenza/token"


def token_file(path: Optional[str] = None) -> str:
    """A token mounted as a file - the Kubernetes projected ServiceAccount
    token (audience "provenza"), or any platform's token written to disk."""
    with open(path or os.environ.get("PROVENZA_ATTESTATION_TOKEN_FILE", K8S_TOKEN_PATH), encoding="utf-8") as f:
        return f.read().strip()


def github_actions(audience: str = "provenza", timeout: float = 10.0) -> str:
    """The job's OIDC token (the workflow needs `permissions: id-token: write`)."""
    url, bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"), os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise RuntimeError("not in a GitHub Actions job with id-token: write")
    r = httpx.get(url, params={"audience": audience}, headers={"Authorization": f"Bearer {bearer}"}, timeout=timeout)
    r.raise_for_status()
    return r.json()["value"]


def gcp_metadata(audience: str = "provenza", timeout: float = 5.0) -> str:
    """The instance's service-account identity token, with its instance claims."""
    r = httpx.get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity",
                  params={"audience": audience, "format": "full"}, headers={"Metadata-Flavor": "Google"},
                  timeout=timeout, trust_env=False)
    r.raise_for_status()
    return r.text.strip()


def azure_imds(resource: str, timeout: float = 5.0) -> str:
    """A managed identity token for `resource` (the policy's audience)."""
    r = httpx.get("http://169.254.169.254/metadata/identity/oauth2/token",
                  params={"api-version": "2018-02-01", "resource": resource}, headers={"Metadata": "true"},
                  timeout=timeout, trust_env=False)
    r.raise_for_status()
    return r.json()["access_token"]
