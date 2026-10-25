# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
An action judged by a signed policy release alone - no database
(docs/pvp/edge.md, sections 3.1 and 4).

The server uses it for the signed side of every decision (AgentAudit.check,
after it has looked up what only it knows: the delegation chain and the
live rows that carry the call). The enforcement points evaluate the same
bundle themselves: proxy/internal/policy is the Go port of this module, and
sdk/testdata/policy-vectors.json holds the cases both must decide alike
(backend/tests/test_policy_vectors.py, proxy/internal/policy/vectors_test.go).

    evaluate(policy, agent_id=..., key_fingerprint=..., action_type=...,
             tool_name=..., input_data=...)  ->  Decision

The steps, in order: the release itself (verifies, not expired); the agent
is in the bundle and - when a key is given - its key fingerprint is the
manifest's; its rights (its own, or in a chain the caller computed); the
action type's own rules (egress: the AI domain catalog; proxy: the signed
route); the capabilities the Tool Registry requires; the policy hierarchy
and the agent policies (agent_policy_engine.check_action, argument rules
included); the Tool Registry's verdict on the tool.
"""

from types import SimpleNamespace
from typing import Any, Optional

from app.services.agent_policy_engine import (
    DENIED, MODEL_ACTION, ActionContext, AgentView, ChainView, Decision, check_action,
)

UNCHECKED = object()          # key_fingerprint: no agent key to compare (a mediated request)
NO_SUPPLY_CHAIN = ("egress", "proxy", MODEL_ACTION)


def agent_of(policy, agent_id: int) -> Optional[SimpleNamespace]:
    entry = (policy.bundle.get("agents") or {}).get(str(agent_id))
    if entry is None:
        return None
    return SimpleNamespace(id=agent_id, **entry)


def required_capabilities(policy, tool: Optional[str]):
    import fnmatch

    if not tool:
        return []
    need: set = set()
    for e in policy.registry_entries():
        if e.required_capabilities and (e.pattern == tool or fnmatch.fnmatchcase(tool, e.pattern)):
            need |= set(e.required_capabilities)
    return sorted(need)


def evaluate(policy, *, agent_id: int, action_type: Optional[str], tool_name: Optional[str], input_data: Any,
             key_fingerprint: Any = UNCHECKED, tool_version: Optional[str] = None,
             tool_digest: Optional[str] = None, now: Optional[float] = None, chain=None) -> Decision:
    """The signed policy's verdict. `chain`: (ChainView, Rights, depth limit)
    when the action runs in a delegation chain - the caller computes the
    agent's rights in it; None: the agent's own rights."""
    from app.pvp.egress import classify_signed
    from app.pvp.egress_proxy import route_rules
    from app.services.agent_rights import own_rights
    from app.services.hier_policy import engine_rules, signed_chain
    from app.services.supply_chain import verify_against

    why = policy.refusal(now)
    if why is not None:
        return Decision(DENIED, why, None)
    agent = agent_of(policy, agent_id)
    if agent is None:
        return Decision(DENIED, f"agent #{agent_id} is not in the signed policy (release #{policy.number})", None)
    if key_fingerprint is not UNCHECKED and \
            (policy.manifest.get("agents") or {}).get(str(agent_id)) != key_fingerprint:
        return Decision(DENIED, f"agent #{agent_id}'s key is not the one in the signed manifest "
                                f"(release #{policy.number})", None)
    if chain is None:
        rights = own_rights(agent)
        chain_view = ChainView(max_depth_reached=0, granted_capabilities=rights.capabilities)
        depth_limit = agent.max_delegation_depth
    else:
        chain_view, rights, depth_limit = chain
    hierarchy, policy_depth = engine_rules(signed_chain(policy, agent=agent, gateway=False))
    if policy_depth is not None:
        depth_limit = min(depth_limit, policy_depth)
    agent_view = AgentView(allowed_tools=list(rights.tools), allowed_models=list(agent.allowed_models or []),
                           max_delegation_depth=depth_limit, status=agent.status)
    inp = input_data if isinstance(input_data, dict) else {}
    if action_type == "egress":
        _, refusal = classify_signed(policy, tool_name, inp)
        if refusal is not None:
            return refusal
        agent_view.allowed_tools.append(tool_name)
    elif action_type == MODEL_ACTION:
        agent_view.allowed_tools.append(tool_name)
    elif action_type == "proxy":
        slug = inp.get("route")
        route = next((r for r in (policy.bundle.get("egress_routes") or {}).values() if r.get("slug") == slug), None)
        refusal = route_rules(route, tool_name, inp)
        if refusal is not None:
            return refusal
    required = required_capabilities(policy, tool_name)
    ctx = ActionContext(tool_name=tool_name, action_type=action_type, input_data=inp,
                        action_capabilities=required)
    decision = check_action(agent_view, chain_view, ctx, hierarchy + policy.policies(agent_id))
    decision.required_capabilities = list(required)
    if decision.result == DENIED or action_type in NO_SUPPLY_CHAIN:
        return decision
    supply = verify_against(policy.registry_mode, policy.registry_entries(), tool_name, tool_version, tool_digest,
                            "the signed Tool Registry")
    if supply is not None:
        supply.required_capabilities = list(required)
        return supply
    return decision
