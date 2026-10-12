# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Egress proxy - agents reach external APIs only through a Provenza proxy that
holds the credentials (proxy/ in this repository; docs/pvp/spec.md, 5.5).

    agent ──HTTP──► proxy 127.0.0.1:8443/<route>/<path>
                      │  mediated: the proxy asks /agents/actions/check with the agent's key
                      │  SDK:      the agent already holds a check (X-Provenza-Check-Id)
                      ▼
               POST /egress-proxy/redeem    the proxy describes the request it is about to
                      │                     send; it must be exactly the checked one
                      ▼
               upstream (from the route table) + the injected credential
                      ▼
               POST /egress-proxy/complete  status and response hash -> the recorded action
                                            (executed_by "egress_proxy")

The checked action is action_type "proxy", tool "proxy.<route>", input:

    {"route", "method", "path", "query_sha256", "body_sha256", "body_bytes"}

- hashes only, never the body or the query string. The route decides what
reaches the upstream at all: its methods and path prefixes, no "." / ".."
path segments (an upstream normalizing them would escape the prefix), its
body limit. The agent needs "proxy.<route>" in its rights; everything else
(policies, argument rules on method / path, behaviour, breaker) applies as to
any action.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import unquote

from fastapi import status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_signing import content_hash
from app.core.crypto import decrypt_secret
from app.core.errors import api_error
from app.models.agent_action import ActionCheck, AgentIncident
from app.models.egress_proxy import EgressProxy, EgressRedemption, EgressRoute
from app.services.agent_audit import AgentAudit
from app.services.agent_policy_engine import ALLOWED, DENIED, Decision

ACTION_TYPE = "proxy"
PREFIX = "proxy."
EXECUTOR = "egress_proxy"
DESCRIPTOR_KEYS = ("route", "method", "path", "query_sha256", "body_sha256", "body_bytes")


def descriptor(route: str, method: str, path: str, query_sha256: Optional[str], body_sha256: Optional[str],
               body_bytes: int) -> Dict[str, Any]:
    return {"route": route, "method": method, "path": path, "query_sha256": query_sha256,
            "body_sha256": body_sha256, "body_bytes": body_bytes}


def path_problem(path: str) -> Optional[str]:
    """Why a path may not be forwarded, or None."""
    if not path.startswith("/"):
        return "the path must start with /"
    for segment in path.split("/"):
        decoded = unquote(segment)
        if decoded in (".", "..") or "/" in decoded or "\\" in decoded:
            return "the path has a '.' / '..' segment or an encoded separator"
    return None


def prefix_allows(path: str, prefixes) -> bool:
    for p in prefixes or []:
        if p == "/" or path == p or path.startswith(p.rstrip("/") + "/"):
            return True
    return False


async def route_by_slug(db: AsyncSession, org_id: int, slug: str) -> Optional[EgressRoute]:
    return (await db.execute(select(EgressRoute).where(
        EgressRoute.org_id == org_id, EgressRoute.slug == slug))).scalar_one_or_none()


async def route_refusal(db: AsyncSession, org_id: int, tool_name: Optional[str],
                        input_data: Dict[str, Any]) -> Optional[Decision]:
    """The route's own rules for a proposed "proxy" action (AgentAudit.check)."""
    inp = input_data or {}
    slug = inp.get("route")
    if set(inp) != set(DESCRIPTOR_KEYS) or not isinstance(slug, str) or tool_name != PREFIX + slug:
        return Decision(DENIED, "a proxy action names its route in tool_name (proxy.<route>) and describes the "
                                f"request with exactly {', '.join(DESCRIPTOR_KEYS)}", None)
    route = await route_by_slug(db, org_id, slug)
    if route is None or not route.enabled:
        return Decision(DENIED, f"egress route '{slug}' does not exist or is disabled", None)
    method, path, size = inp.get("method"), inp.get("path"), inp.get("body_bytes")
    if method not in (route.methods or []):
        return Decision(DENIED, f"method {method} is not allowed on route '{slug}'", None)
    problem = path_problem(path) if isinstance(path, str) else "the path is missing"
    if problem:
        return Decision(DENIED, f"route '{slug}': {problem}", None)
    if not prefix_allows(path, route.path_prefixes):
        return Decision(DENIED, f"path {path} is outside route '{slug}'", None)
    if not isinstance(size, int) or size < 0 or size > route.max_body_bytes:
        return Decision(DENIED, f"the body is larger than route '{slug}' allows ({route.max_body_bytes} bytes)", None)
    return None


def route_config(route: EgressRoute) -> Dict[str, Any]:
    """A route as a proxy needs it - with the server-held secret, decrypted."""
    secret = decrypt_secret(route.secret_encrypted) if route.credential_source == "server" and \
        route.secret_encrypted else None
    return {"slug": route.slug, "upstream_url": route.upstream_url, "methods": route.methods,
            "path_prefixes": route.path_prefixes, "credential_source": route.credential_source,
            "auth_header": route.auth_header, "secret": secret, "max_body_bytes": route.max_body_bytes}


def _decision(chk: ActionCheck) -> Decision:
    return Decision(chk.decision, chk.reason or "", chk.incident_type, matched_policy_id=chk.policy_id)


async def redeem(db: AsyncSession, proxy: EgressProxy, check_token: str, desc: Dict[str, Any]) -> Dict[str, Any]:
    """Reserve a check for the request the proxy is about to send. The request
    must be exactly the checked one; a refused check is recorded here and now."""
    org_id, proxy_id = proxy.org_id, proxy.id
    chk = (await db.execute(select(ActionCheck).where(ActionCheck.token == check_token, ActionCheck.org_id == org_id)
                            .with_for_update())).scalar_one_or_none()
    if chk is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "egress.unknown_check")
    if chk.used_at is not None:
        raise api_error(status.HTTP_409_CONFLICT, "egress.check_used")
    now = datetime.now(timezone.utc)
    if chk.expires_at <= now:
        raise api_error(status.HTTP_400_BAD_REQUEST, "egress.check_expired")
    if chk.action_type != ACTION_TYPE or chk.tool_name != PREFIX + desc["route"] \
            or chk.input_sha256 != content_hash(desc):
        # what is about to be sent is not what was checked: burn the check, raise an incident
        chk.used_at = now
        db.add(AgentIncident(org_id=org_id, agent_id=chk.agent_id, chain_id=chk.chain_id,
                             incident_type="action_mismatch", severity="critical",
                             details={"via": EXECUTOR, "proxy_id": proxy_id, "checked_tool": chk.tool_name,
                                      "checked_action_type": chk.action_type, "route": desc["route"]}))
        await db.commit()
        raise api_error(status.HTTP_400_BAD_REQUEST, "egress.request_mismatch")

    audit = AgentAudit(db)
    route = await route_by_slug(db, org_id, desc["route"])
    decision = _decision(chk)
    if decision.result == ALLOWED and (route is None or not route.enabled):
        decision = Decision(DENIED, f"egress route '{desc['route']}' was disabled after the check", None)
    if decision.result != ALLOWED:
        chk.used_at = now
        action = await audit.record(org_id=org_id, agent_id=chk.agent_id, chain_id=chk.chain_id,
                                    action_type=ACTION_TYPE, tool_name=chk.tool_name, input_data=desc,
                                    output_data=None, signature=None, duration_ms=None, decision=decision,
                                    check_id=chk.id, executed_by=EXECUTOR, check_token=check_token)
        return {"allowed": False, "decision": decision.result, "reason": decision.reason, "action_id": action.id}

    chk.used_at = now   # reserved: neither the agent nor another proxy can use it now
    redemption = EgressRedemption(org_id=org_id, check_id=chk.id, proxy_id=proxy_id, route_id=route.id,
                                  agent_id=chk.agent_id, descriptor=desc, reserved_at=now)
    db.add(redemption)
    await db.flush()
    redemption_id = redemption.id
    await db.commit()
    return {"allowed": True, "redemption_id": redemption_id}


async def complete(db: AsyncSession, proxy: EgressProxy, check_token: str, output: Dict[str, Any],
                   duration_ms: Optional[int]) -> Dict[str, Any]:
    """Record what a redeemed request did."""
    row = (await db.execute(
        select(EgressRedemption, ActionCheck).join(ActionCheck, ActionCheck.id == EgressRedemption.check_id)
        .where(ActionCheck.token == check_token, EgressRedemption.proxy_id == proxy.id)
        .with_for_update(of=EgressRedemption))).first()
    if row is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "egress.unknown_redemption")
    redemption, chk = row
    if redemption.completed_at is not None:
        raise api_error(status.HTTP_409_CONFLICT, "egress.already_completed")
    action = await AgentAudit(db).record(
        org_id=proxy.org_id, agent_id=chk.agent_id, chain_id=chk.chain_id, action_type=ACTION_TYPE,
        tool_name=chk.tool_name, input_data=redemption.descriptor, output_data=output, signature=None,
        duration_ms=duration_ms, decision=_decision(chk), check_id=chk.id, executed_by=EXECUTOR,
        check_token=check_token)
    redemption = await db.get(EgressRedemption, redemption.id)
    redemption.completed_at, redemption.action_id = datetime.now(timezone.utc), action.id
    action_id = action.id
    await db.commit()
    return {"action_id": action_id}
