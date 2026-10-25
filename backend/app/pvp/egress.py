# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Egress actions - an agent process calling an AI provider directly, outside
Provenza's gateways (reported by the SDK's auto-instrumentation,
provenza.auto in sdk/python).

    action_type "egress", tool_name "egress.<host>",
    input {"host", "method", "path", "body_sha256", "body_bytes"}   (no content)

The organization's AI domain catalog (Shadow AI) is the right here, not the
agent's allowed_tools - listing every provider host on every agent would
make the rule unusable:

  blocked   -> denied, incident "ai_domain_blocked"
  allowed   -> allowed
  unknown   -> allowed (not classified yet: the attempt is on record for an
               admin to classify)

With the organization's "self-hosted providers only" policy
(services/provider_policy.py), every host the catalog or its built-in hints
know as an AI service is refused too, allowed or not: incident
"ai_provider_not_self_hosted".

Every other rule still applies: policies (deny_tools, deny_tool_patterns,
approval rules, ...), the behaviour baseline, the breaker. The Tool Registry
does not: provider hosts are managed in the catalog, not as tools.

The decision is the server's. The SDK only needs the catalog to know which
hosts are AI providers (GET /pvp/egress-catalog).
"""

from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from app.services import provider_policy
from app.services.agent_policy_engine import DENIED, Decision
from app.services.domain_catalog_seed import SEED_DOMAINS
from app.services.domain_catalog_service import DomainCatalogService

ACTION_TYPE = "egress"
PREFIX = "egress."
BLOCKED_INCIDENT = "ai_domain_blocked"


def signed_match(domains: Dict[str, str], host: str):
    """DomainCatalogService.match_domain over the signed catalog (domain -> status)."""
    from app.services.domain_catalog_service import DomainMatch

    if host in domains:
        return DomainMatch(domains[host], None, None, 0)
    suffix = [d for d in domains if host.endswith("." + d)]
    if suffix:
        return DomainMatch(domains[max(suffix, key=len)], None, None, 0)
    from app.services.domain_catalog_seed import lookup_seed_hint

    hint = lookup_seed_hint(host)
    return DomainMatch("unknown", hint["tool_name"] if hint else None, hint["category"] if hint else None, None)


def classify_signed(signed, tool_name: Optional[str], input_data: Dict[str, Any]) -> Tuple[str, Optional[Decision]]:
    """classify() by the signed catalog and provider policy alone - no database."""
    host = str((input_data or {}).get("host") or "").strip().lower()
    if not host or tool_name != PREFIX + host:
        return "invalid", Decision(DENIED, "an egress action names its host in tool_name (egress.<host>) and input.host",
                                   None)
    match = signed_match(signed.ai_domains(), host)
    return match.policy_status, _verdict(host, match, signed.provider_policy() == "self_hosted")


def _verdict(host: str, match, self_hosted: bool) -> Optional[Decision]:
    if match.policy_status == "blocked":
        what = f" ({match.tool_name})" if match.tool_name else ""
        return Decision(DENIED, f"{host}{what} is blocked in the organization's AI domain catalog", BLOCKED_INCIDENT)
    known = match.matched_catalog_id is not None or match.tool_name is not None
    if known and self_hosted:
        what = f" ({match.tool_name})" if match.tool_name else ""
        return Decision(DENIED, f"{host}{what} is a cloud AI service; the organization allows only self-hosted "
                                "providers", provider_policy.INCIDENT)
    return None


async def classify(db: AsyncSession, org_id: int, tool_name: Optional[str],
                   input_data: Dict[str, Any], signed=None) -> Tuple[str, Optional[Decision]]:
    """(catalog status, a refusal or None) for one egress action - by the
    working copy of the catalog, or by the signed one (app/pvp/signed_policy.py)."""
    if signed is not None:
        return classify_signed(signed, tool_name, input_data)
    host = str((input_data or {}).get("host") or "").strip().lower()
    if not host or tool_name != PREFIX + host:
        return "invalid", Decision(DENIED, "an egress action names its host in tool_name (egress.<host>) and input.host",
                                   None)
    match = await DomainCatalogService(db).match_domain(org_id, host)
    return match.policy_status, _verdict(host, match, await provider_policy.self_hosted_required(db, org_id))


async def catalog(db: AsyncSession, org_id: int) -> List[Dict[str, Any]]:
    """The AI provider domains an agent process should route through
    governance: the organization's catalog, then the built-in hints it has
    not classified (as unknown). Paths ("github.com/copilot") are not hosts
    and are left out."""
    out: Dict[str, Dict[str, Any]] = {}
    for e in await DomainCatalogService(db).list_entries(org_id):
        if "/" not in e.domain:
            out[e.domain] = {"domain": e.domain, "status": e.policy_status, "tool_name": e.tool_name,
                             "category": e.category}
    for s in SEED_DOMAINS:
        if "/" not in s["domain"] and s["domain"] not in out:
            out[s["domain"]] = {"domain": s["domain"], "status": "unknown", "tool_name": s["tool_name"],
                                "category": s["category"]}
    return sorted(out.values(), key=lambda d: d["domain"])
