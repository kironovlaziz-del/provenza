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

Every other rule still applies: policies (deny_tools, deny_tool_patterns,
approval rules, ...), the behaviour baseline, the breaker. The Tool Registry
does not: provider hosts are managed in the catalog, not as tools.

The decision is the server's. The SDK only needs the catalog to know which
hosts are AI providers (GET /pvp/egress-catalog).
"""

from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.agent_policy_engine import DENIED, Decision
from app.services.domain_catalog_seed import SEED_DOMAINS
from app.services.domain_catalog_service import DomainCatalogService

ACTION_TYPE = "egress"
PREFIX = "egress."
BLOCKED_INCIDENT = "ai_domain_blocked"


async def classify(db: AsyncSession, org_id: int, tool_name: Optional[str],
                   input_data: Dict[str, Any]) -> Tuple[str, Optional[Decision]]:
    """(catalog status, a refusal or None) for one egress action."""
    host = str((input_data or {}).get("host") or "").strip().lower()
    if not host or tool_name != PREFIX + host:
        return "invalid", Decision(DENIED, "an egress action names its host in tool_name (egress.<host>) and input.host",
                                   None)
    match = await DomainCatalogService(db).match_domain(org_id, host)
    if match.policy_status == "blocked":
        what = f" ({match.tool_name})" if match.tool_name else ""
        return "blocked", Decision(DENIED, f"{host}{what} is blocked in the organization's AI domain catalog",
                                   BLOCKED_INCIDENT)
    return match.policy_status, None


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
