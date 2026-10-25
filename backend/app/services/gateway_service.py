# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
LLM gateway - an OpenAI-compatible endpoint agents call instead of the
provider. Change base_url to .../api/v1/gateway/v1 and the API key to the
agent's own key; every call then goes through:

  1. identity      only an agent key (X-Agent-Key, or "Authorization:
                   Bearer <agent key>" for stock OpenAI SDKs - see
                   gateway API)
  2. decision      a PVP action "model_call" on the tool "llm.<model>"
                   through the orchestrator (docs/pvp/spec.md, 5.7): the
                   model must be in the agent's allowed_models and every
                   level's models.allow; agent policies, quarantine, the
                   circuit breaker and the delegation chain
                   (X-Provenza-Chain-Id) apply as to any action (model
                   calls are not counted in the behaviour baseline)
  3. executor      a route to an active connection, the providers allowed by
                   the policy hierarchy, self-hosted only, requests per
                   minute; max_tokens capped
  4. provider      the call itself - here only for a connection that takes no
                   key (self-hosted); one with a key is called by an egress
                   proxy, which holds it (/_llm, app/pvp/proxy_actions.py)
  5. record        the action (executed_by "llm_gateway"; its input is the
                   model, a hash of the messages and their count) and
                   gateway_calls: agent, model, connection, verdict, tokens,
                   latency. What was sent and answered is not kept.

Errors are returned in the OpenAI shape {"error": {"message", "type", "code"}}.
"""

import fnmatch
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.pvp import enforcement
from app.core.agent_signing import content_hash
from app.models.agent import Agent
from app.models.ai_provider import AIProvider
from app.models.gateway import GatewayCall, GatewayRoute, GatewaySettings
from app.models.user import User
from app.pvp.model import ALLOWED, PENDING_APPROVAL, PVPActionRequest
from app.pvp.orchestrator import PVPOrchestrator
from app.services import gateway_adapters, provider_policy
from app.services.provider_adapters import ProviderCallError

DEFAULTS = {"enabled": True, "rpm_per_agent": 60, "max_tokens_cap": 4096}

EXECUTOR = "llm_gateway"
MODEL_ACTION = "model_call"
MODEL_TOOL_PREFIX = "llm."
MAX_TOOL_NAME = 100    # PVP tool names (app/pvp/model.py)


def _as_sent(messages: List[dict]) -> List[dict]:
    """The messages as the client wrote them (fields it left out are not
    null): what an agent hashes to match the action's messages_sha256."""
    return [{k: v for k, v in m.items() if v is not None} for m in messages]


class GatewayError(Exception):
    def __init__(self, http_status: int, code: str, message: str, err_type: str = "invalid_request_error"):
        super().__init__(message)
        self.http_status, self.code, self.message, self.err_type = http_status, code, message, err_type

    def body(self) -> dict:
        return {"error": {"message": self.message, "type": self.err_type, "code": self.code}}


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

    async def enforced_settings(self, org_id: int) -> dict:
        """The settings that apply: the stricter of the working copy and the
        signed policy in force (app/pvp/signed_policy.py)."""
        cfg = await self.settings(org_id)
        from app.pvp import signed_policy

        signed = await signed_policy.in_force(self.db, org_id)
        if signed is not None:
            held = signed.gateway_settings()
            cfg = dict(cfg, enabled=bool(cfg["enabled"]) and bool(held.get("enabled")),
                       rpm_per_agent=min(cfg["rpm_per_agent"], held.get("rpm_per_agent", cfg["rpm_per_agent"])),
                       max_tokens_cap=min(cfg["max_tokens_cap"], held.get("max_tokens_cap", cfg["max_tokens_cap"])))
        return cfg

    async def save_settings(self, org_id: int, values: dict, user_id: int) -> tuple:
        row = await self._settings_row(org_id)
        before = None if row is None else {k: getattr(row, k) for k in DEFAULTS}
        if row is None:
            row = GatewaySettings(org_id=org_id)
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
                      flags: List[str], provider_id: Optional[int] = None,
                      latency_ms: Optional[int] = None, usage: Optional[dict] = None,
                      action_id: Optional[int] = None, chain_id: Optional[int] = None) -> GatewayCall:
        call = GatewayCall(org_id=org_id, agent_id=agent_id, model=model[:200], status=status_,
                           reason=(reason or None) and reason[:500], flags=flags, provider_id=provider_id,
                           latency_ms=latency_ms,
                           prompt_tokens=(usage or {}).get("prompt_tokens"),
                           completion_tokens=(usage or {}).get("completion_tokens"),
                           action_id=action_id, chain_id=chain_id)
        self.db.add(call)
        await self.db.commit()
        await self.db.refresh(call)
        return call

    async def _judge(self, agent: Agent, model: str, messages: int, messages_sha256: str,
                     requested_max_tokens: Optional[int], stream: bool, chain_id: Optional[int], executor: str):
        """Everything the gateway decides before calling the provider - for a
        call it makes itself, or one an egress proxy makes (it holds the
        connection's key; app/pvp/proxy_actions.py). A refusal is recorded
        and raised as GatewayError; otherwise the context to call with."""
        # plain values up front: commits below must not leave us reading expired ORM state
        org_id, agent_id = agent.org_id, agent.id
        agent_status, allowed_models = agent.status, set(agent.allowed_models or [])
        tool = f"{MODEL_TOOL_PREFIX}{model}"
        cfg = await self.enforced_settings(org_id)
        # the policy hierarchy (gateway settings -> organization -> team -> agent):
        # limits and providers here; models and tools in the orchestrator
        from app.services import hier_policy

        eff = await hier_policy.for_agent(self.db, agent)
        rpm = eff.limit("limits.requests_per_minute") or cfg["rpm_per_agent"]
        max_tokens_cap = eff.limit("limits.max_tokens") or cfg["max_tokens_cap"]
        from app.services.kill_switch import traffic_stop

        stop = await traffic_stop(self.db, org_id)
        if stop is not None:
            await self._record(org_id, agent_id, model, "denied", f"kill switch #{stop.id}: AI traffic stopped", [])
            raise GatewayError(503, "kill_switch", "The organization's AI traffic is stopped by the kill switch.",
                               "service_unavailable")
        if not cfg["enabled"]:
            raise GatewayError(403, "gateway_disabled", "The gateway is disabled for this organization.")
        if stream:
            raise GatewayError(400, "stream_not_supported", "Streaming is not supported by the gateway yet; "
                                                            "send stream=false.")
        if len(tool) > MAX_TOOL_NAME:
            raise GatewayError(400, "model_name_too_long", f"Model names longer than "
                                                           f"{MAX_TOOL_NAME - len(MODEL_TOOL_PREFIX)} characters "
                                                           f"are not supported.")

        found = await self._route(org_id, model)
        provider = found[1] if found else None
        provider_id, p_type, p_base, p_name, p_status = (
            (provider.id, provider.type, provider.base_url, provider.name, provider.status) if provider
            else (None, None, None, None, None))
        p_source = (provider.credential_source or "none") if provider else "none"
        upstream = (found[0].upstream_model or model) if found else model
        max_tokens = min(requested_max_tokens or max_tokens_cap, max_tokens_cap)
        # what the decision and the record are about: metadata and a hash, never the text
        input_data = {"model": model, "provider": p_name, "messages": messages,
                      "messages_sha256": messages_sha256, "max_tokens": max_tokens}

        orc = PVPOrchestrator(self.db)
        try:
            check = await orc.check(org_id, PVPActionRequest(
                agent_id=agent_id, chain_id=chain_id, action_type=MODEL_ACTION, tool_name=tool, input=input_data))
        except HTTPException as exc:
            # refused before any check existed (agent key policy, attestation, unknown chain, ...)
            detail = exc.detail if isinstance(exc.detail, str) else "refused"
            await self._record(org_id, agent_id, model, "denied", detail, [], provider_id)   # the chain is unverified
            raise GatewayError(exc.status_code, detail, f"Refused by Provenza: {detail}", "permission_error")

        async def refuse(status_: str, reason: str, err: GatewayError, *, decided: bool = False):
            action = await orc.record_executed(org_id, check, input_data=input_data, output=None, duration_ms=None,
                                               executed_by=executor, refusal=None if decided else reason)
            await self._record(org_id, agent_id, model, status_, reason, [], provider_id,
                               action_id=action.id, chain_id=chain_id)
            err.message = f"{err.message} (action #{action.id})"
            raise err

        if check.decision != ALLOWED:
            if check.decision == PENDING_APPROVAL:
                await refuse("pending_approval", check.reason or "needs approval",
                             GatewayError(403, "approval_required", "This call needs a human approval and was "
                                                                    "not executed.", "permission_error"),
                             decided=True)
            if agent_status != "active":
                err = GatewayError(403, "agent_not_active", f"Agent is {agent_status}.", "permission_error")
            elif model not in allowed_models or eff.refusing("models.allow", model):
                err = GatewayError(403, "model_not_allowed", f"Model '{model}' is not allowed: {check.reason}",
                                   "permission_error")
            else:
                err = GatewayError(403, "policy_denied", f"Refused by policy: {check.reason}", "permission_error")
            await refuse("denied", check.reason or "denied", err, decided=True)

        if provider is None:
            await refuse("denied", "no route for this model",
                         GatewayError(404, "model_not_routed", f"No gateway route serves model '{model}'."))
        if p_status != "active":
            await refuse("denied", "connection disabled",
                         GatewayError(503, "connection_disabled", f"The '{p_name}' connection is disabled.",
                                      "api_error"))
        if executor == EXECUTOR and await enforcement.enforced(self.db, org_id):
            await refuse("denied", enforcement.REFUSAL,
                         GatewayError(403, "enforce_mode", "LLM gateway: " + enforcement.REFUSAL, "permission_error"))
        if executor == EXECUTOR and p_source != "none":
            # this server holds no provider key (app/pvp/sealed.py): an egress proxy opens it
            await refuse("denied", "the connection's key is sealed to the egress proxies",
                         GatewayError(409, "credential_at_proxy", f"The key of AI connection '{p_name}' is sealed "
                                                                  f"to the egress proxies: call the model through an "
                                                                  f"egress proxy.", "permission_error"))
        by = eff.refusing_any("providers.allow", [p_name, p_type])
        if by:
            await refuse("denied", f"provider not allowed by the {by} policy",
                         GatewayError(403, "provider_not_allowed", f"The '{p_name}' connection is not allowed by "
                                                                   f"the {by} policy.", "permission_error"))
        self_hosted = await provider_policy.self_hosted_required(self.db, org_id)
        cloud = provider_policy.cloud_reason(p_type, p_base) if self_hosted else None
        if cloud:
            await refuse("denied", f"self-hosted providers only: {cloud}",
                         GatewayError(403, "provider_not_self_hosted", f"The organization allows only self-hosted "
                                                                       f"AI providers: {cloud}.", "permission_error"))
        since = datetime.now(timezone.utc) - timedelta(minutes=1)
        recent = (await self.db.execute(
            select(func.count()).select_from(GatewayCall)
            .where(GatewayCall.agent_id == agent_id, GatewayCall.created_at >= since)
        )).scalar_one()
        if recent >= rpm:
            by = eff.source("limits.requests_per_minute") or hier_policy.GATEWAY_SOURCE
            await refuse("rate_limited", f"over {rpm} requests/min ({by})",
                         GatewayError(429, "rate_limited", f"Rate limit of {rpm} requests per minute "
                                                           f"for this agent reached.", "rate_limit_error"))
        return {"orc": orc, "check": check, "input_data": input_data, "provider_id": provider_id, "p_type": p_type,
                "p_base": p_base, "p_name": p_name, "p_source": p_source, "upstream": upstream,
                "max_tokens": max_tokens, "self_hosted": self_hosted}

    async def plan(self, agent: Agent, meta: dict, chain_id: Optional[int], proxy) -> dict:
        """A chat completion an egress proxy makes with the connection's key
        sealed to it: decided here as chat() decides; the proxy sends only the
        metadata (the messages' count and hash) and keeps the content."""
        from app.pvp import proxy_actions

        model = meta["model"]
        j = await self._judge(agent, model, meta["messages"], meta["messages_sha256"], meta.get("max_tokens"),
                              bool(meta.get("stream")), chain_id, proxy_actions.EXECUTOR)
        await proxy_actions.reserve(self.db, proxy, j["check"].check_id, j["input_data"])
        out = await proxy_actions.allowed(self.db, proxy, j["check"], j["input_data"])
        return {**out, "input": j["input_data"], "model": model, "upstream_model": j["upstream"],
                "max_tokens": j["max_tokens"], "self_hosted_only": bool(j["self_hosted"]),
                "provider": {"id": j["provider_id"], "type": j["p_type"], "base_url": j["p_base"],
                             "name": j["p_name"]},
                "credential": {"object": "provider", "id": j["provider_id"], "source": j["p_source"],
                               "header": "api-key" if j["p_type"] == "azure_openai" else
                               "x-api-key" if j["p_type"] == "anthropic" else "Authorization"}}

    async def proxy_completed(self, chk, output: Optional[dict], duration_ms: Optional[int], action_id: int,
                              refused: Optional[str]) -> int:
        """The gateway_calls row for a call an egress proxy made (or refused)."""
        model = chk.tool_name[len(MODEL_TOOL_PREFIX):]
        out = output or {}
        status_ = "denied" if refused else "failed" if "provider_error" in out else "completed"
        reason = refused or out.get("provider_error")
        found = await self._route(chk.org_id, model)
        provider_id = found[1].id if found and found[1] else None
        call = await self._record(chk.org_id, chk.agent_id, model, status_, reason, [], provider_id, duration_ms,
                                  {"prompt_tokens": out.get("prompt_tokens"),
                                   "completion_tokens": out.get("completion_tokens")},
                                  action_id=action_id, chain_id=chk.chain_id)
        return call.id

    async def chat(self, agent: Agent, user: User, body: dict, chain_id: Optional[int] = None) -> dict:
        """One chat completion as a PVP action: action_type "model_call" on the
        tool "llm.<model>", decided by the orchestrator (rights, policies,
        quarantine, breaker, chain) and executed and
        recorded by the gateway. The action's input is metadata and hashes,
        never the messages."""
        org_id, agent_id = agent.org_id, agent.id
        model = body["model"]
        outgoing = [{**m} for m in body["messages"]]
        j = await self._judge(agent, model, len(outgoing), content_hash(_as_sent(outgoing)),
                              body.get("max_tokens") or body.get("max_completion_tokens"), bool(body.get("stream")),
                              chain_id, EXECUTOR)
        orc, check, input_data, provider_id = j["orc"], j["check"], j["input_data"], j["provider_id"]
        params = {k: body.get(k) for k in ("temperature", "top_p", "stop")}
        params["max_tokens"] = j["max_tokens"]

        started = time.monotonic()
        try:
            with provider_policy.scope(j["self_hosted"]):
                text, finish, _raw, usage = await gateway_adapters.chat(j["p_type"], None, j["p_base"],
                                                                        j["upstream"], outgoing, params)
        except ProviderCallError as exc:
            latency = int((time.monotonic() - started) * 1000)
            action = await orc.record_executed(org_id, check, input_data=input_data,
                                               output={"provider_error": str(exc)[:500]}, duration_ms=latency,
                                               executed_by=EXECUTOR)
            await self._record(org_id, agent_id, model, "failed", str(exc), [], provider_id, latency,
                               action_id=action.id, chain_id=chain_id)
            raise GatewayError(502, "provider_error", str(exc), "api_error")
        latency = int((time.monotonic() - started) * 1000)

        action = await orc.record_executed(
            org_id, check, input_data=input_data, duration_ms=latency, executed_by=EXECUTOR,
            output={"finish_reason": finish, "prompt_tokens": usage.get("prompt_tokens"),
                    "completion_tokens": usage.get("completion_tokens"),
                    "response_sha256": content_hash({"content": text})})
        call = await self._record(org_id, agent_id, model, "completed", None, [], provider_id, latency, usage,
                                  action_id=action.id, chain_id=chain_id)
        return {
            "id": f"chatcmpl-pvz-{call.id}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": finish}],
            "usage": {"prompt_tokens": usage.get("prompt_tokens"), "completion_tokens": usage.get("completion_tokens"),
                      "total_tokens": (usage.get("prompt_tokens") or 0) + (usage.get("completion_tokens") or 0)
                      if usage.get("prompt_tokens") is not None else None},
            "provenza": {"call_id": call.id, "action_id": action.id},
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
                           "default_model": p.default_model, "has_key": p.has_credentials} for p in providers],
            "routes": [{"id": r.id, "model": r.model, "provider_id": r.provider_id, "provider": pname.get(r.provider_id),
                        "upstream_model": r.upstream_model, "enabled": r.enabled, "created_at": r.created_at}
                       for r in routes],
            "calls": [{"id": c.id, "created_at": c.created_at, "agent_id": c.agent_id, "agent_name": name,
                       "model": c.model, "provider": pname.get(c.provider_id), "status": c.status, "reason": c.reason,
                       "flags": c.flags, "latency_ms": c.latency_ms, "prompt_tokens": c.prompt_tokens,
                       "completion_tokens": c.completion_tokens}
                      for c, name in calls],
        }
