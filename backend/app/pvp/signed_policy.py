# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The signed policy in force, and how decisions use it (docs/pvp/edge.md,
section 3).

Once an organization has a release in force, an action is allowed only when
BOTH the working copy (what admins edit, as today) AND the signed release
allow it:

  - tightening in the interface (suspending an agent, taking a tool away,
    adding a deny rule, blocking a domain) takes effect at once;
  - loosening takes effect only when a quorum of administrators has signed
    a release that contains it - an edit made through a stolen session, a
    rogue administrator below the quorum, or a write straight into the
    database does not loosen anything;
  - an agent, an agent key, a gateway route, an MCP server, an A2A peer, an
    HTTP tool or an egress route that is not in the release exactly as it
    is configured now serves nothing until it is signed.

The release is checked whenever it is loaded: the documents hash to what was
signed, and the quorum of the release that governed it (the previous one;
for the first release its own manifest) signed it with passkeys listed in
that manifest - back to the first release. A release that does not verify,
or whose not_after has passed, allows nothing.
"""

import logging
import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import webauthn
from app.core.agent_signing import key_fingerprint
from app.models.policy_release import PolicyRelease, PolicyReleaseSignature
from app.pvp import policy_bundle as pb

logger = logging.getLogger(__name__)

RELEASE_TYPE = "provenza.policy.release"
V = 1


def release_statement(org_id: int, user_id: int, release: PolicyRelease, issued_at: int) -> Dict[str, Any]:
    """What an administrator's passkey signs: this release - its number, both
    documents by version and hash, and how long it is valid."""
    return {"type": RELEASE_TYPE, "v": V, "org_id": org_id, "user_id": user_id, "release": release.number,
            "bundle": {"version": release.bundle["version"], "sha256": release.bundle_sha256},
            "manifest": {"version": release.manifest["version"], "sha256": release.manifest_sha256},
            "not_after": release.bundle["not_after"], "issued_at": issued_at}


def signer_key(manifest: Dict[str, Any], user_id: int, credential_id: str) -> Optional[Dict[str, Any]]:
    """The passkey of an administrator as the manifest lists it, or None."""
    s = (manifest.get("signers") or {}).get(str(user_id))
    if not s or s.get("role") != pb.QUORUM_ROLE:
        return None
    return (s.get("passkeys") or {}).get(credential_id)


def valid_signers(release: PolicyRelease, governing: Dict[str, Any],
                  signatures: List[PolicyReleaseSignature]) -> Set[int]:
    """Administrators of the governing manifest whose passkey signed exactly
    this release."""
    out: Set[int] = set()
    for sig in signatures:
        st = sig.statement or {}
        issued = st.get("issued_at")
        if not isinstance(issued, int) or st != release_statement(release.org_id, sig.user_id, release, issued):
            continue
        key = signer_key(governing, sig.user_id, sig.credential_id)
        a = sig.assertion or {}
        if key is None:
            continue
        try:
            webauthn.verify_assertion_spki(
                public_key_spki=key["public_key"], alg=int(key["alg"]),
                client_data_json=str(a.get("client_data_json") or ""),
                authenticator_data=str(a.get("authenticator_data") or ""),
                signature=str(a.get("signature") or ""), challenge=webauthn.statement_challenge(st))
        except (webauthn.WebAuthnError, KeyError, TypeError, ValueError):
            continue
        out.add(sig.user_id)
    return out


def follows(release: PolicyRelease, parent: PolicyRelease) -> bool:
    """Each document either is the previous one, or names its hash as
    `previous` with the next version."""
    b, m = release.bundle, release.manifest
    bundle_ok = b.get("previous") == parent.bundle_sha256 and b.get("version") == parent.bundle.get("version", 0) + 1
    manifest_ok = release.manifest_sha256 == parent.manifest_sha256 or (
        m.get("previous") == parent.manifest_sha256 and m.get("version") == parent.manifest.get("version", 0) + 1)
    return bundle_ok and manifest_ok


def quorum_of(manifest: Dict[str, Any]) -> int:
    return max(1, int(manifest.get("quorum") or 1))


@dataclass
class SignedPolicy:
    release_id: int
    number: int
    bundle: Dict[str, Any]
    manifest: Dict[str, Any]
    problem: Optional[str] = None           # set: the release does not verify - nothing is allowed
    _registry: Optional[list] = field(default=None, repr=False)

    @property
    def not_after(self) -> int:
        return int(self.bundle.get("not_after") or 0)

    @property
    def expired(self) -> bool:
        return time.time() > self.not_after

    def refusal(self, now: Optional[float] = None) -> Optional[str]:
        """Why nothing is allowed under this release, or None."""
        if self.problem:
            return f"the signed policy (release #{self.number}) does not verify: {self.problem}"
        if (time.time() if now is None else now) > self.not_after:
            return f"the signed policy (release #{self.number}) expired; administrators must sign a new release"
        return None

    # ------------------------------------------------------------------ agents
    def agent(self, live) -> Tuple[Optional[Any], Optional[str]]:
        """(the agent with its signed rights, None) or (None, why it may not act)."""
        entry = (self.bundle.get("agents") or {}).get(str(live.id))
        if entry is None:
            return None, f"agent #{live.id} is not in the signed policy (release #{self.number})"
        signed_fp = (self.manifest.get("agents") or {}).get(str(live.id))
        if signed_fp != key_fingerprint(live.public_key, live.pq_public_key):
            return None, (f"agent #{live.id}'s key is not the one in the signed manifest "
                          f"(release #{self.number})")
        return SignedAgent(live, entry), None

    def policies(self, agent_id: int) -> List[Dict[str, Any]]:
        out = [(int(k), p) for k, p in (self.bundle.get("agent_policies") or {}).items()
               if p.get("enabled") and p.get("agent_id") in (None, agent_id)]
        out.sort(key=lambda x: (-int(x[1].get("priority") or 0), x[0]))
        return [{"id": pid, "name": p.get("name"), "rules": p.get("rules") or {}} for pid, p in out]

    def layer(self, scope: str, target: Optional[int]) -> Dict[str, Any]:
        return dict((self.bundle.get("policy_layers") or {}).get(pb.layer_key(scope, target)) or {})

    def team(self, team_id: int) -> Optional[Dict[str, Any]]:
        return (self.bundle.get("teams") or {}).get(str(team_id))

    # ------------------------------------------------------------------ Tool Registry
    @property
    def registry_mode(self) -> str:
        return (self.bundle.get("tool_registry") or {}).get("mode") or "enforce"

    def registry_entries(self) -> list:
        if self._registry is None:
            self._registry = [SimpleNamespace(pattern=p, **e) for p, e in
                              ((self.bundle.get("tool_registry") or {}).get("entries") or {}).items()]
        return self._registry

    # ------------------------------------------------------------------ settings and rows
    def identity(self) -> Dict[str, Any]:
        return dict(self.bundle.get("identity") or {})

    def provider_policy(self) -> str:
        return self.bundle.get("provider_policy") or "any"

    def ai_domains(self) -> Dict[str, str]:
        return dict(self.bundle.get("ai_domains") or {})

    def gateway_settings(self) -> Dict[str, Any]:
        return dict((self.bundle.get("gateway") or {}).get("settings") or {})

    def row(self, section: str, row_id: int) -> Optional[Dict[str, Any]]:
        if section == "gateway.routes":
            return ((self.bundle.get("gateway") or {}).get("routes") or {}).get(str(row_id))
        return (self.bundle.get(section) or {}).get(str(row_id))


class SignedAgent:
    """An agent as the signed policy sees it: its signed rights over its
    live row (identity, keys and the rest are the row's)."""

    SIGNED = ("status", "team_id", "capabilities", "allowed_tools", "allowed_models", "max_delegation_depth")

    def __init__(self, live, entry: Dict[str, Any]):
        object.__setattr__(self, "_live", live)
        object.__setattr__(self, "_entry", entry)

    def __getattr__(self, name):
        if name in SignedAgent.SIGNED:
            return self._entry.get(name)
        return getattr(self._live, name)

    def __setattr__(self, name, value):
        raise AttributeError("a signed view of an agent is read-only")


# ---------------------------------------------------------------------- loading and verifying

_verified: Set[Tuple[int, str, str]] = set()
_cache: Dict[int, SignedPolicy] = {}
_reported: Set[Tuple[int, int]] = set()


async def _verify_chain(db: AsyncSession, release: PolicyRelease, depth: int = 0) -> Optional[str]:
    """None when this release and every release that governed it verify."""
    mark = (release.id, release.bundle_sha256, release.manifest_sha256)
    if mark in _verified:
        return None
    if depth > 10_000:
        return "the release history is too long to check"
    if pb.sha256(release.bundle) != release.bundle_sha256 or pb.sha256(release.manifest) != release.manifest_sha256:
        return "a document does not match the hash that was signed"
    if release.governed_by_id is None:
        governing = release.manifest
    else:
        parent = await db.get(PolicyRelease, release.governed_by_id)
        if parent is None or parent.org_id != release.org_id or parent.number >= release.number:
            return "the release that governed it is missing"
        problem = await _verify_chain(db, parent, depth + 1)
        if problem:
            return problem
        governing = parent.manifest
        if not follows(release, parent):
            return "it does not follow the release before it"
    sigs = list((await db.execute(select(PolicyReleaseSignature).where(
        PolicyReleaseSignature.release_id == release.id))).scalars())
    if len(valid_signers(release, governing, sigs)) < quorum_of(governing):
        return "it does not carry the quorum's signatures"
    _verified.add(mark)
    return None


async def current_release(db: AsyncSession, org_id: int) -> Optional[PolicyRelease]:
    return (await db.execute(select(PolicyRelease).where(
        PolicyRelease.org_id == org_id, PolicyRelease.status == "in_force")
        .order_by(PolicyRelease.number.desc()).limit(1))).scalar_one_or_none()


async def in_force(db: AsyncSession, org_id: int) -> Optional[SignedPolicy]:
    """The signed policy decisions are checked against, or None while the
    organization has never signed one (then the working copy alone decides,
    as before)."""
    head = (await db.execute(select(PolicyRelease.id, PolicyRelease.bundle_sha256, PolicyRelease.manifest_sha256)
                             .where(PolicyRelease.org_id == org_id, PolicyRelease.status == "in_force")
                             .order_by(PolicyRelease.number.desc()).limit(1))).first()
    if head is None:
        return None
    cached = _cache.get(org_id)
    if cached is not None and cached.release_id == head[0] and \
            (head[0], head[1], head[2]) in _verified:
        return cached
    release = await db.get(PolicyRelease, head[0])
    problem = await _verify_chain(db, release)
    sp = SignedPolicy(release.id, release.number, release.bundle, release.manifest, problem)
    if problem is None:
        _cache[org_id] = sp
    elif (org_id, release.id) not in _reported:
        _reported.add((org_id, release.id))
        logger.error("signed policy of org %s (release #%s) does not verify: %s", org_id, release.number, problem)
        from app.models.ai_incident import AIIncident

        db.add(AIIncident(org_id=org_id, severity="critical", category="signed_policy_invalid", status="open",
                          summary=f"The signed policy in force (release #{release.number}) does not verify: "
                                  f"{problem}. No agent action is allowed until a quorum signs a new release.",
                          impact="every agent action is refused"))
        await db.commit()
    return sp


def forget(org_id: Optional[int] = None) -> None:
    """Drop cached releases (tests; a new release replaces the cache anyway)."""
    if org_id is None:
        _cache.clear()
        _verified.clear()
        _reported.clear()
    else:
        _cache.pop(org_id, None)
