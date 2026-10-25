# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The policy bundle and the key manifest as data (docs/pvp/edge.md, section 3).

The working copy is what admins edit in the interface, as today. Its
snapshot - only what decides allow or deny, and the keys - is what a release
freezes and administrators sign:

  bundle    agents' rights (status, team, capabilities, tools, models,
            delegation depth), agent policies, the policy hierarchy and
            teams, the Tool Registry (mode, approved and blocked entries with
            their pins and required capabilities), agent identity settings,
            the provider policy, the AI domain catalog, the LLM gateway's
            settings and routes, MCP servers, A2A peers, HTTP tools and
            egress routes (what they connect to, not their credentials)
  manifest  the quorum, the people who sign (administrators and approvers)
            with their passkeys' public keys, each agent's key fingerprint,
            egress proxies and sensors, the sensor command key

The same view of a row is used to build a snapshot and to compare a live
row with its signed form (app/pvp/signed_policy.py), so the two cannot
drift apart. No secrets are in either: credentials stay where they are and
are referred to by their configuration only.
"""

import hashlib
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_signing import canonical_bytes, key_fingerprint

BUNDLE_TYPE = "provenza.policy.bundle"
MANIFEST_TYPE = "provenza.key.manifest"
V = 1
SIGNER_ROLES = ("admin", "approver")
QUORUM_ROLE = "admin"
# members of a document that describe it, not the policy (not compared as changes)
META = ("type", "v", "org_id", "version", "previous", "not_after", "offline_seconds")
SECTIONS = ("agents", "agent_policies", "policy_layers", "teams", "tool_registry", "identity", "provider_policy",
            "ai_domains", "gateway", "ai_providers", "mcp_servers", "a2a_peers", "http_tools", "egress_routes",
            "egress_workloads", "enforcement")
MANIFEST_SECTIONS = ("quorum", "signers", "agents", "egress_proxies", "egress_sensors", "sensor_command_key",
                     "proxy_binaries", "proxy_configs")


def sha256(doc: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(doc)).hexdigest()


def _list(v) -> List[str]:
    return sorted({str(x) for x in v}) if v else []


# ---------------------------------------------------------------------- row views

def agent_view(a) -> Dict[str, Any]:
    return {"name": a.name, "status": a.status, "team_id": a.team_id, "capabilities": _list(a.capabilities),
            "allowed_tools": _list(a.allowed_tools), "allowed_models": _list(a.allowed_models),
            "max_delegation_depth": int(a.max_delegation_depth)}


def policy_view(p) -> Dict[str, Any]:
    return {"agent_id": p.agent_id, "name": p.name, "rules": p.rules or {}, "priority": int(p.priority),
            "enabled": bool(p.enabled)}


def registry_view(e) -> Dict[str, Any]:
    return {"kind": e.kind, "status": e.status, "pinned_version": e.pinned_version,
            "pinned_digest": e.pinned_digest, "required_capabilities": _list(e.required_capabilities) or None}


def route_view(r) -> Dict[str, Any]:
    return {"model": r.model, "provider_id": r.provider_id, "upstream_model": r.upstream_model,
            "enabled": bool(r.enabled)}


def provider_view(p) -> Dict[str, Any]:
    """Where an AI connection sends prompts - signed, so a server cannot
    point a model at another host (an enforcement point checks it)."""
    return {"name": p.name, "type": p.type, "base_url": p.base_url, "status": p.status}


def mcp_server_view(s) -> Dict[str, Any]:
    return {"slug": s.slug, "url": s.url, "protocol": s.protocol, "auth_header": s.auth_header,
            "enabled": bool(s.enabled)}


def a2a_peer_view(p) -> Dict[str, Any]:
    return {"slug": p.slug, "card_url": p.card_url, "endpoint_url": p.endpoint_url, "card_digest": p.card_digest,
            "auth_header": p.auth_header, "enabled": bool(p.enabled)}


def http_tool_view(t) -> Dict[str, Any]:
    return {"name": t.name, "method": t.method, "url": t.url, "digest": t.digest, "auth_header": t.auth_header,
            "send_permit": bool(t.send_permit), "enabled": bool(t.enabled)}


def egress_route_view(r) -> Dict[str, Any]:
    return {"slug": r.slug, "upstream_url": r.upstream_url, "methods": _list(r.methods),
            "path_prefixes": _list(r.path_prefixes), "credential_source": r.credential_source,
            "auth_header": r.auth_header, "max_body_bytes": int(r.max_body_bytes), "enabled": bool(r.enabled)}


def _allow_view(rules) -> List[Dict[str, Any]]:
    out = []
    for r in rules or []:
        if not isinstance(r, dict):
            continue
        item = {"ports": sorted({int(p) for p in r.get("ports") or []}),
                "protocols": sorted({str(p).lower() for p in r.get("protocols") or []})}
        for k in ("dest", "source"):
            if r.get(k):
                item[k] = str(r[k])
        out.append(item)
    return out


def egress_workload_view(w) -> Dict[str, Any]:
    """What a sensor that follows the signed policy holds a workload to
    (sensor/internal/daemon/signedwl.go): the server's workload may be
    tighter, never looser."""
    return {"name": w.name, "agent_id": w.agent_id, "cgroup_patterns": _list(w.cgroup_patterns),
            "run_as_users": _list(w.run_as_users), "egress_allow": _allow_view(w.egress_allow),
            "ingress_allow": _allow_view(w.ingress_allow), "dns": w.dns or "off", "mode": w.mode or "observe",
            "isolated": bool(w.isolated), "enabled": bool(w.enabled)}


def layer_key(scope: str, target: Optional[int]) -> str:
    return "org" if scope == "org" else f"{scope}:{target}"


# ---------------------------------------------------------------------- snapshots

async def bundle_content(db: AsyncSession, org_id: int) -> Dict[str, Any]:
    """The sections of the working copy (without META)."""
    from app.models.a2a_gateway import A2APeer
    from app.models.agent import Agent, AgentPolicy
    from app.models.agent_identity import AgentIdentitySettings
    from app.models.ai_provider import AIProvider
    from app.models.ai_domain_catalog import AIDomainCatalog
    from app.models.egress_proxy import EgressRoute
    from app.models.egress_sensor import EgressWorkload
    from app.models.gateway import GatewayRoute, GatewaySettings
    from app.models.http_tool import HttpTool
    from app.models.mcp import MCPServer
    from app.models.organization import Organization
    from app.models.policy_layer import PolicyLayer
    from app.models.team import Team
    from app.models.tool_registry import SupplyChainSettings, ToolRegistryEntry
    from app.services import agent_identity, gateway_service, supply_chain

    async def rows(model, *where):
        return list((await db.execute(select(model).where(model.org_id == org_id, *where))).scalars())

    def by_id(items, view) -> Dict[str, Any]:
        return {str(x.id): view(x) for x in items}

    sc = (await rows(SupplyChainSettings))
    ident = (await rows(AgentIdentitySettings))
    gw = (await rows(GatewaySettings))
    provider = (await db.execute(select(Organization.ai_provider_policy).where(Organization.id == org_id))).scalar()
    return {
        "agents": by_id(await rows(Agent), agent_view),
        "agent_policies": by_id(await rows(AgentPolicy), policy_view),
        "policy_layers": {layer_key(r.scope, r.team_id if r.scope == "team" else r.agent_id): r.document
                          for r in await rows(PolicyLayer) if r.document},
        "teams": {str(t.id): {"name": t.name, "parent_id": t.parent_id} for t in await rows(Team)},
        "tool_registry": {
            "mode": sc[0].mode if sc else supply_chain.DEFAULT_MODE,
            # pending entries allow nothing a missing entry would not
            "entries": {e.pattern: registry_view(e) for e in await rows(ToolRegistryEntry)
                        if e.status != "pending"},
        },
        "identity": {k: (getattr(ident[0], k) if ident else v) for k, v in agent_identity.DEFAULTS.items()
                     if k != "default_attestation_policy_id"},
        "provider_policy": provider or "any",
        # "unknown" entries are left out (they fill up from traffic): without one,
        # a blocked parent domain stays blocked on the signed side
        "ai_domains": {d.domain: d.policy_status for d in await rows(AIDomainCatalog)
                       if d.policy_status != "unknown"},
        "gateway": {
            "settings": {k: (getattr(gw[0], k) if gw else v) for k, v in gateway_service.DEFAULTS.items()},
            "routes": by_id(await rows(GatewayRoute), route_view),
        },
        "ai_providers": by_id(await rows(AIProvider), provider_view),
        "mcp_servers": by_id(await rows(MCPServer), mcp_server_view),
        "a2a_peers": by_id(await rows(A2APeer), a2a_peer_view),
        "http_tools": by_id(await rows(HttpTool), http_tool_view),
        "egress_routes": by_id(await rows(EgressRoute), egress_route_view),
        "egress_workloads": by_id(await rows(EgressWorkload, EgressWorkload.deleted_at.is_(None)),
                                  egress_workload_view),
    }


async def manifest_content(db: AsyncSession, org_id: int, quorum: int,
                           proxy_binaries: Optional[List[str]] = None,
                           proxy_configs: Optional[List[str]] = None) -> Dict[str, Any]:
    from app.core import webauthn
    from app.models.agent import Agent
    from app.models.egress_proxy import EgressProxy
    from app.models.egress_sensor import EgressSensor, EgressSensorSigningKey
    from app.models.signing import UserPasskey
    from app.models.user import User

    people = list((await db.execute(select(User).where(
        User.org_id == org_id, User.role.in_(SIGNER_ROLES), User.status == "active").order_by(User.id))).scalars())
    keys = list((await db.execute(select(UserPasskey).where(
        UserPasskey.org_id == org_id, UserPasskey.revoked_at.is_(None)).order_by(UserPasskey.id))).scalars())
    signers = {}
    for u in people:
        mine = {k.credential_id: {"alg": k.alg, "public_key": webauthn.spki(k.public_key),
                                  "fingerprint": webauthn.passkey_fingerprint(k.public_key)}
                for k in keys if k.user_id == u.id}
        signers[str(u.id)] = {"email": u.email, "role": u.role, "passkeys": mine}
    agents = list((await db.execute(select(Agent).where(Agent.org_id == org_id))).scalars())
    proxies = list((await db.execute(select(EgressProxy).where(EgressProxy.org_id == org_id))).scalars())
    sensors = list((await db.execute(select(EgressSensor).where(EgressSensor.org_id == org_id))).scalars())
    skey = (await db.execute(select(EgressSensorSigningKey).where(
        EgressSensorSigningKey.org_id == org_id))).scalar_one_or_none()
    out = {
        "quorum": int(quorum),
        "signers": signers,
        "agents": {str(a.id): key_fingerprint(a.public_key, a.pq_public_key) for a in agents},
        # the key each proxy signs its receipts with (generated on its host)
        "egress_proxies": {str(p.id): {"name": p.name, "key_hash": p.key_hash, "enabled": bool(p.enabled),
                                       "key_fingerprint": key_fingerprint(p.public_key) if p.public_key else None,
                                       "encryption_key_fingerprint":
                                           key_fingerprint(p.encryption_key) if p.encryption_key else None}
                           for p in proxies},
        "egress_sensors": {str(s.id): {"name": s.name, "key_hash": s.key_hash, "enabled": bool(s.enabled)}
                           for s in sensors},
        "sensor_command_key": skey.fingerprint if skey else None,
    }
    if proxy_binaries:
        # the egress proxy binaries a sensor lets out of a proxy host (docs/pvp/edge.md,
        # section 5); absent when none, so a release made before them is unchanged
        out["proxy_binaries"] = sorted(proxy_binaries)
    if proxy_configs:
        # ... and the configurations it may run with (sha256sum proxy.json)
        out["proxy_configs"] = sorted(proxy_configs)
    return out


def admins_with_passkeys(manifest: Dict[str, Any]) -> int:
    return sum(1 for s in (manifest.get("signers") or {}).values()
               if s.get("role") == QUORUM_ROLE and s.get("passkeys"))


# ---------------------------------------------------------------------- differences

NESTED = {"tool_registry": "entries", "gateway": "routes"}     # sections holding a keyed list
FLAT = ("identity", "provider_policy", "enforcement")                        # compared as one item

def _label(section: str, key: str, before, after) -> str:
    if key == section:
        return ""
    item = after if isinstance(after, dict) else before if isinstance(before, dict) else {}
    name = item.get("name") or item.get("slug") or item.get("model") or item.get("email")
    return f"{key} ({name})" if name else key


def diff(old: Optional[Dict[str, Any]], new: Dict[str, Any], sections=SECTIONS,
         limit: int = 500) -> List[Dict[str, Any]]:
    """What differs between two documents, item by item:
    [{"section", "key", "label", "change": added|removed|changed, "fields": [{"field", "before", "after"}]}]."""
    out: List[Dict[str, Any]] = []
    old = old or {}

    def item(section, key, b, a):
        if b == a:
            return
        change = "added" if b is None else "removed" if a is None else "changed"
        fields = []
        if isinstance(b, dict) and isinstance(a, dict):
            fields = [{"field": f, "before": b.get(f), "after": a.get(f)}
                      for f in sorted(set(b) | set(a)) if b.get(f) != a.get(f)]
        elif change == "changed":
            fields = [{"field": None, "before": b, "after": a}]
        out.append({"section": section, "key": key, "label": _label(section, key, b, a), "change": change,
                    "fields": fields})

    for section in sections:
        b, a = old.get(section), new.get(section)
        if section in FLAT or not isinstance(a, dict) or (b is not None and not isinstance(b, dict)):
            item(section, section, b, a)
            continue
        b = b or {}
        sub = NESTED.get(section)
        for key in sorted(set(b) | set(a), key=str):
            if key == sub:
                bb, aa = b.get(key) or {}, a.get(key) or {}
                for k in sorted(set(bb) | set(aa), key=str):
                    item(f"{section}.{key}", k, bb.get(k), aa.get(k))
            else:
                item(section, key, b.get(key), a.get(key))
        if len(out) >= limit:
            break
    return out[:limit]
