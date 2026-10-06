# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
LLM gateway - an OpenAI-compatible endpoint agents call instead of the
provider. Change base_url to .../api/v1/gateway/v1 and the API key to the
agent's own key; every call then goes through:

  1. identity      only an agent key (X-Agent-Key, or "Authorization:
                   Bearer <agent key>" for stock OpenAI SDKs - see
                   gateway API); the agent must be active
  2. model         the requested model must be in the agent's
                   allowed_models (same rule as the policy engine) and have a
                   route to an active connection
  3. limits        requests per minute per agent; max_tokens capped
  4. firewall      every message through the Prompt Firewall: blocked terms
                   refuse the call, PII is masked before it leaves Provenza
  5. ASI01         instructions hidden in user / tool messages (indirect
                   injection) - refused in enforce mode, flagged in monitor
  6. provider      the call itself, with the connection's key
  7. output        ASI01 / ASI05 on the answer - in enforce mode a poisoned
                   answer is replaced (finish_reason "content_filter")
  8. record        ai_requests (raw prompt Fernet-encrypted, masked text in
                   clear, as for every other request) + ai_responses +
                   gateway_calls

Errors are returned in the OpenAI shape {"error": {"message", "type", "code"}}.
"""

import asyncio
import fnmatch
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_secret
from app.models.agent import Agent
from app.models.ai_provider import AIProvider
from app.models.ai_request import AIRequest
from app.models.ai_response import AIResponse
from app.models.gateway import GatewayCall, GatewayRoute, GatewaySettings
from app.models.user import User
from app.services import gateway_adapters, prompt_firewall
from app.services.provider_adapters import ProviderCallError

DEFAULTS = {"enabled": True, "rpm_per_agent": 60, "max_tokens_cap": 4096, "scan_output": True}
SCANNED_ROLES = ("user", "tool", "function")


class GatewayError(Exception):
    def __init__(self, http_status: int, code: str, message: str, err_type: str = "invalid_request_error"):
        super().__init__(message)
        self.http_status, self.code, self.message, self.err_type = http_status, code, message, err_type

    def body(self) -> dict:
        return {"error": {"message": self.message, "type": self.err_type, "code": self.code}}


def provider_api_key(provider: AIProvider) -> Optional[str]:
    """The connection's key in clear - the single place the gateway decrypts it."""
    if not provider.api_key_encrypted:
        return None
    from app.core.crypto import decrypt_secret
    return decrypt_secret(provider.api_key_encrypted)


def _text(content: Any) -> str:
    return gateway_adapters._text(content)


class GatewayService:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------ settings / routes
    async def _settings_row(self, org_id: int) -> Optional[GatewaySettings]:
        return (await self.db.execute(
            select(GatewaySettings).where(GatewaySettings.org_id == org_id)
        )).scalar_one_or_none()

    async def settings(self, org_id: int) -> dict:
        row = await self._settings_row(org_id)
        if not row:
            return {**DEFAULTS, "source": "default"}
        return {k: getattr(row, k) for k in DEFAULTS} | {"source": "org"}

    async def save_settings(self, org_id: int, values: dict, user_id: int) -> tuple:
        row = await self._settings_row(org_id)
        before = None if row is None else {k: getattr(row, k) for k in DEFAULTS}
        if row is None:
            row = GatewaySettings(org_id=org_id, blocked_terms=[])  # terms: services/blocked_terms.py
            self.db.add(row)
        for k in DEFAULTS:
            setattr(row, k, values[k])
        row.updated_by = user_id
        await self.db.commit()
        return before, {k: values[k] for k in DEFAULTS}

    async def add_route(self, org_id: int, data: dict, user_id: int) -> dict:
        provider = (await self.db.execute(
            select(AIProvider).where(AIProvider.id == data["provider_id"], AIProvider.org_id == org_id)
        )).scalar_one_or_none()
        if not provider:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")
        dup = (await self.db.execute(
            select(GatewayRoute.id).where(GatewayRoute.org_id == org_id, GatewayRoute.enabled.is_(True),
                                          GatewayRoute.model == data["model"])
        )).scalar_one_or_none()
        if dup:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail="An enabled route for this model already exists; disable it first")
        route = GatewayRoute(org_id=org_id, model=data["model"], provider_id=provider.id,
                             upstream_model=data.get("upstream_model"), created_by=user_id)
        self.db.add(route)
        await self.db.commit()
        await self.db.refresh(route)
        return {"id": route.id, "model": route.model, "provider_id": route.provider_id,
                "upstream_model": route.upstream_model}

    async def disable_route(self, org_id: int, route_id: int) -> dict:
        route = (await self.db.execute(
            select(GatewayRoute).where(GatewayRoute.id == route_id, GatewayRoute.org_id == org_id)
        )).scalar_one_or_none()
        if not route:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Route not found")
        if not route.enabled:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Route is already disabled")
        route.enabled = False
        await self.db.commit()
        return {"id": route.id, "enabled": False}

    async def _route(self, org_id: int, model: str) -> Optional[Tuple[GatewayRoute, AIProvider]]:
        rows = (await self.db.execute(
            select(GatewayRoute, AIProvider).join(AIProvider, AIProvider.id == GatewayRoute.provider_id)
            .where(GatewayRoute.org_id == org_id, GatewayRoute.enabled.is_(True))
            .order_by(GatewayRoute.created_at)
        )).all()
        exact = [(r, p) for r, p in rows if r.model == model]
        globbed = [(r, p) for r, p in rows if r.model != model and fnmatch.fnmatchcase(model, r.model)]
        return (exact or globbed or [None])[0]

    # ------------------------------------------------------------------ models
    async def models(self, org_id: int, agent: Agent) -> dict:
        rows = (await self.db.execute(
            select(GatewayRoute.model).where(GatewayRoute.org_id == org_id, GatewayRoute.enabled.is_(True))
        )).scalars().all()
        from app.services import hier_policy

        eff = await hier_policy.for_agent(self.db, agent)
        allowed = list(agent.allowed_models or [])
        data = [m for m in allowed if any(m == r or fnmatch.fnmatchcase(m, r) for r in rows)
                and eff.refusing("models.allow", m) is None]
        return {"object": "list", "data": [{"id": m, "object": "model", "owned_by": "provenza"} for m in data]}

    # ------------------------------------------------------------------ chat
    async def _record(self, org_id: int, agent_id: int, model: str, status_: str, reason: Optional[str],
                      flags: List[str], provider_id: Optional[int] = None, ai_request_id: Optional[int] = None,
                      latency_ms: Optional[int] = None, usage: Optional[dict] = None) -> GatewayCall:
        call = GatewayCall(org_id=org_id, agent_id=agent_id, model=model[:200], status=status_,
                           reason=(reason or None) and reason[:500], flags=flags, provider_id=provider_id,
                           ai_request_id=ai_request_id, latency_ms=latency_ms,
                           prompt_tokens=(usage or {}).get("prompt_tokens"),
                           completion_tokens=(usage or {}).get("completion_tokens"))
        self.db.add(call)
        await self.db.commit()
        await self.db.refresh(call)
        return call

    async def chat(self, agent: Agent, user: User, body: dict) -> dict:
        # plain values up front: commits below must not leave us reading expired ORM state
        org_id, agent_id, agent_name = agent.org_id, agent.id, agent.name
        agent_status, allowed_models = agent.status, set(agent.allowed_models or [])
        user_id = user.id
        model = body["model"]
        cfg = await self.settings(org_id)
        # the policy hierarchy (gateway settings -> organization -> team -> agent):
        # limits, models, providers, output scanning (blocked terms: services/blocked_terms.py)
        from app.services import hier_policy

        eff = await hier_policy.for_agent(self.db, agent)
        rpm = eff.limit("limits.requests_per_minute") or cfg["rpm_per_agent"]
        max_tokens_cap = eff.limit("limits.max_tokens") or cfg["max_tokens_cap"]
        from app.services import blocked_terms as bt

        blocked_terms = await bt.for_agent(self.db, agent)
        scan_output = eff.switch("content.scan_output")
        from app.services.kill_switch import traffic_stop

        stop = await traffic_stop(self.db, org_id)
        if stop is not None:
            await self._record(org_id, agent_id, model, "denied", f"kill switch #{stop.id}: AI traffic stopped", [])
            raise GatewayError(503, "kill_switch", "The organization's AI traffic is stopped by the kill switch.",
                               "service_unavailable")
        if not cfg["enabled"]:
            raise GatewayError(403, "gateway_disabled", "The gateway is disabled for this organization.")
        if body.get("stream"):
            raise GatewayError(400, "stream_not_supported", "Streaming is not supported by the gateway yet; "
                                                            "send stream=false.")
        if agent_status != "active":
            await self._record(org_id, agent_id, model, "denied", f"agent is {agent_status}", [])
            raise GatewayError(403, "agent_not_active", f"Agent is {agent_status}.", "permission_error")
        if model not in allowed_models:
            await self._record(org_id, agent_id, model, "denied", "model not in the agent's allowed models", [])
            raise GatewayError(403, "model_not_allowed", f"Model '{model}' is not in the agent's allowed models.",
                               "permission_error")
        by = eff.refusing("models.allow", model)
        if by:
            await self._record(org_id, agent_id, model, "denied", f"model not allowed by the {by} policy", [])
            raise GatewayError(403, "model_not_allowed", f"Model '{model}' is not allowed by the {by} policy.",
                               "permission_error")
        found = await self._route(org_id, model)
        if found is None:
            await self._record(org_id, agent_id, model, "denied", "no route for this model", [])
            raise GatewayError(404, "model_not_routed", f"No gateway route serves model '{model}'.")
        route, provider = found
        provider_id, p_type, p_base, p_name, p_status = (provider.id, provider.type, provider.base_url,
                                                         provider.name, provider.status)
        p_key = provider_api_key(provider)
        upstream = route.upstream_model or model
        if p_status != "active":
            await self._record(org_id, agent_id, model, "denied", "connection disabled", [], provider_id)
            raise GatewayError(503, "connection_disabled", f"The '{p_name}' connection is disabled.",
                               "api_error")
        by = eff.refusing_any("providers.allow", [p_name, p_type])
        if by:
            await self._record(org_id, agent_id, model, "denied", f"provider not allowed by the {by} policy", [],
                               provider_id)
            raise GatewayError(403, "provider_not_allowed", f"The '{p_name}' connection is not allowed by the {by} "
                                                            f"policy.", "permission_error")

        since = datetime.now(timezone.utc) - timedelta(minutes=1)
        recent = (await self.db.execute(
            select(func.count()).select_from(GatewayCall)
            .where(GatewayCall.agent_id == agent_id, GatewayCall.created_at >= since)
        )).scalar_one()
        if recent >= rpm:
            by = eff.source("limits.requests_per_minute") or hier_policy.GATEWAY_SOURCE
            await self._record(org_id, agent_id, model, "rate_limited", f"over {rpm} requests/min ({by})", [],
                               provider_id)
            raise GatewayError(429, "rate_limited", f"Rate limit of {rpm} requests per minute "
                                                    f"for this agent reached.", "rate_limit_error")

        # ---- firewall + ASI01 on every message
        from app.services.injection_detector import scan_text
        from app.services.injection_guard import InjectionGuard
        inj_cfg = await InjectionGuard(self.db).settings(org_id)
        flags: List[str] = []
        outgoing: List[Dict[str, Any]] = []
        injection_hits: List[str] = []
        from app.services import pii_rules

        pii_cfg = await pii_rules.config(self.db, org_id, request_budget=1.0)  # all messages together
        term_hits: List[Any] = []  # counted once per request, after every message is checked
        for i, m in enumerate(body["messages"]):
            text = _text(m.get("content"))
            # in a thread: custom PII rules may run up to their time limit
            fw = await asyncio.to_thread(prompt_firewall.scan, text, blocked_terms, "en", pii_cfg) if text else None
            if fw is not None and fw.timed_out:
                await pii_rules.note_timeouts(self.db, org_id, fw.timed_out)
            if fw is not None:
                term_hits += fw.term_hits
            if fw is not None and fw.blocked:
                await bt.record_hits(self.db, org_id, term_hits)
                await self._record(org_id, agent_id, model, "blocked", fw.blocked_reason, list(fw.flags), provider_id)
                raise GatewayError(403, "blocked_by_firewall", fw.blocked_reason or "Blocked by the Prompt Firewall.",
                                   "permission_error")
            if fw is not None:
                flags += [f for f in fw.flags if f not in flags]
            if text and m["role"] in SCANNED_ROLES and inj_cfg["mode"] != "off":
                r = scan_text(text, inj_cfg["threshold"])
                if r["verdict"] == "injection":
                    injection_hits.append(f"messages[{i}] ({m['role']}): "
                                          + ", ".join(f["label"] for f in r["findings"][:3]))
            outgoing.append({**{k: v for k, v in m.items() if k != "content"},
                             "content": fw.masked_text if fw is not None else m.get("content")})
        await bt.record_hits(self.db, org_id, term_hits)  # committed with the request just below
        if injection_hits:
            flags.append("asi01:injection")
            if inj_cfg["mode"] == "enforce":
                await self._record(org_id, agent_id, model, "blocked", "prompt injection: " + "; ".join(injection_hits),
                                   flags, provider_id)
                raise GatewayError(403, "prompt_injection", "Prompt-injection pattern in "
                                   + "; ".join(injection_hits) + " (ASI01)", "permission_error")

        params = {k: body.get(k) for k in ("temperature", "top_p", "stop")}
        requested = body.get("max_tokens") or body.get("max_completion_tokens")
        params["max_tokens"] = min(requested or max_tokens_cap, max_tokens_cap)

        masked_transcript = "\n".join(f"[{m['role']}] {_text(m.get('content'))}" for m in outgoing)[:20000]
        ai_req = AIRequest(
            org_id=org_id, user_id=user_id, provider_id=provider_id,
            input_text_encrypted=encrypt_secret(json.dumps(body["messages"], ensure_ascii=False, default=str), org_id=org_id),
            masked_input_text=masked_transcript, purpose=f"gateway:{agent_name}"[:255], risk_level="low",
            status="pending", firewall_flags=flags,
        )
        self.db.add(ai_req)
        await self.db.commit()
        await self.db.refresh(ai_req)
        ai_req_id = ai_req.id

        started = time.monotonic()
        try:
            text, finish, raw, usage = await gateway_adapters.chat(p_type, p_key, p_base, upstream, outgoing, params)
        except ProviderCallError as exc:
            ai_req.status = "failed"
            ai_req.error_message = str(exc)[:2000]
            await self.db.commit()
            await self._record(org_id, agent_id, model, "failed", str(exc), flags, provider_id, ai_req_id,
                               int((time.monotonic() - started) * 1000))
            raise GatewayError(502, "provider_error", str(exc), "api_error")
        latency = int((time.monotonic() - started) * 1000)

        # ---- output: ASI01 / ASI05
        filtered_reason = None
        if scan_output and text:
            from app.services.code_exec_detector import scan_value
            from app.services.code_exec_guard import CodeExecGuard
            ce_cfg = await CodeExecGuard(self.db).settings(org_id)
            out_inj = scan_text(text, inj_cfg["threshold"]) if inj_cfg["mode"] != "off" else {"verdict": "clean"}
            crit = [f for f in scan_value(text, "$") if f["severity"] == "critical"] if ce_cfg["mode"] != "off" else []
            if out_inj["verdict"] == "injection":
                flags.append("output:asi01")
                if inj_cfg["mode"] == "enforce":
                    filtered_reason = "answer carries a prompt injection (ASI01)"
            if crit:
                flags.append("output:asi05")
                if ce_cfg["mode"] == "enforce":
                    filtered_reason = "answer carries critical code: " + ", ".join(f["label"] for f in crit[:3]) + " (ASI05)"
        if filtered_reason:
            text, finish = "", "content_filter"

        ai_req.status = "completed"
        ai_req.firewall_flags = flags
        self.db.add(AIResponse(request_id=ai_req_id, provider_response_json=raw if isinstance(raw, dict) else {"raw": str(raw)},
                               response_text=text))
        await self.db.commit()
        call = await self._record(org_id, agent_id, model, "filtered" if filtered_reason else "completed",
                                  filtered_reason, flags, provider_id, ai_req_id, latency, usage)
        return {
            "id": f"chatcmpl-pvz-{call.id}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": finish}],
            "usage": {"prompt_tokens": usage.get("prompt_tokens"), "completion_tokens": usage.get("completion_tokens"),
                      "total_tokens": (usage.get("prompt_tokens") or 0) + (usage.get("completion_tokens") or 0)
                      if usage.get("prompt_tokens") is not None else None},
            "provenza": {"call_id": call.id, "request_id": ai_req_id, "flags": flags,
                         "filtered": filtered_reason},
        }

    # ------------------------------------------------------------------ overview
    async def overview(self, org_id: int) -> dict:
        calls = (await self.db.execute(
            select(GatewayCall, Agent.name).outerjoin(Agent, Agent.id == GatewayCall.agent_id)
            .where(GatewayCall.org_id == org_id).order_by(GatewayCall.created_at.desc()).limit(100)
        )).all()
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        counts = dict((await self.db.execute(
            select(GatewayCall.status, func.count())
            .where(GatewayCall.org_id == org_id, GatewayCall.created_at >= since).group_by(GatewayCall.status)
        )).all())
        tokens = (await self.db.execute(
            select(func.coalesce(func.sum(GatewayCall.prompt_tokens), 0),
                   func.coalesce(func.sum(GatewayCall.completion_tokens), 0))
            .where(GatewayCall.org_id == org_id, GatewayCall.created_at >= since)
        )).one()
        providers = (await self.db.execute(
            select(AIProvider).where(AIProvider.org_id == org_id).order_by(AIProvider.name)
        )).scalars().all()
        pname = {p.id: p.name for p in providers}
        routes = (await self.db.execute(
            select(GatewayRoute).where(GatewayRoute.org_id == org_id)
            .order_by(GatewayRoute.enabled.desc(), GatewayRoute.model)
        )).scalars().all()
        return {
            "settings": await self.settings(org_id),
            "counts_24h": counts,
            "tokens_24h": {"prompt": int(tokens[0]), "completion": int(tokens[1])},
            "providers": [{"id": p.id, "name": p.name, "type": p.type, "status": p.status,
                           "default_model": p.default_model, "has_key": bool(p.api_key_encrypted)} for p in providers],
            "routes": [{"id": r.id, "model": r.model, "provider_id": r.provider_id, "provider": pname.get(r.provider_id),
                        "upstream_model": r.upstream_model, "enabled": r.enabled, "created_at": r.created_at}
                       for r in routes],
            "calls": [{"id": c.id, "created_at": c.created_at, "agent_id": c.agent_id, "agent_name": name,
                       "model": c.model, "provider": pname.get(c.provider_id), "status": c.status, "reason": c.reason,
                       "flags": c.flags, "latency_ms": c.latency_ms, "prompt_tokens": c.prompt_tokens,
                       "completion_tokens": c.completion_tokens, "ai_request_id": c.ai_request_id}
                      for c, name in calls],
        }
