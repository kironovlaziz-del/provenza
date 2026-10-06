# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Runtime policy engine for agent actions.

Given an agent, the chain it's acting in, and the action it wants to
perform, decide allowed / denied / pending_approval. This is the
gatekeeper every tool/model call passes through.

The check order (cheapest and most fundamental first):
  1. tool allowed for this agent?
  2. model allowed (for model-invoking tools)?
  3. delegation depth within the agent's limit?
  4. the capabilities the tool requires (Tool Registry) within the agent's
     rights in the chain (no escalation mid-chain)?
  5. custom agent policies (JSON rules) - evaluated last, can only
     further restrict.

Returns a Decision (dataclass) with the verdict, a human reason, and -
when denied by escalation/depth - an incident_type so the caller can
raise the right AgentIncident. Pure decision logic: it does NOT write to
the DB (the caller records the action and any incident), which keeps it
unit-testable without a database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.services.capability_validator import escalated_items


ALLOWED = "allowed"
DENIED = "denied"
PENDING_APPROVAL = "pending_approval"


@dataclass
class Decision:
    result: str
    reason: str
    incident_type: Optional[str] = None  # capability_escalation | depth_exceeded | policy_violation
    matched_policy_id: Optional[int] = None
    # what the action needed (Tool Registry), recorded with the check
    required_capabilities: List[str] = field(default_factory=list)


@dataclass
class ActionContext:
    """Everything the engine needs, passed in by the caller so the engine
    itself stays DB-free."""
    tool_name: Optional[str]
    action_type: Optional[str]
    input_data: Dict[str, Any] = field(default_factory=dict)
    # the capabilities this action requires - derived by the server from the
    # Tool Registry, never declared by the caller
    action_capabilities: List[str] = field(default_factory=list)
    violation: Optional[str] = None  # set by argument rules (ASI02)


@dataclass
class AgentView:
    """The subset of Agent fields the engine reads (again, so it can be
    tested with plain objects, not ORM rows)."""
    allowed_tools: List[str] = field(default_factory=list)
    allowed_models: List[str] = field(default_factory=list)
    max_delegation_depth: int = 3
    status: str = "active"


@dataclass
class ChainView:
    max_depth_reached: int = 0
    status: str = "active"  # chain status: active, tripped, violated, terminated, completed
    granted_capabilities: List[str] = field(default_factory=list)
    delegation_expires_at: object = None  # datetime or None; None = no time bound
    member: bool = True  # False: the agent is neither the chain's root nor reached by a hop
    root_agent_id: Optional[int] = None


# Tools that invoke a model and therefore trigger the model-allowlist
# check. Kept explicit rather than guessed from the name.
_MODEL_INVOKING_TOOLS = {"openai.chat", "anthropic.messages", "model.invoke", "llm.chat"}


def evaluate_custom_rule(rule: Dict[str, Any], ctx: ActionContext) -> str:
    """
    Evaluate one custom JSON policy rule against the action. Returns one
    of: "ok" (rule satisfied), "deny" (rule violated), or "approval"
    (rule requires human approval before the action may proceed).

    Supported rule shapes (intentionally small and explicit - not a
    turing-complete expression evaluator, which would be a security and
    maintenance hazard):

      {"deny_tools": ["stripe.charge", ...]}
          -> "deny" if the action's tool is in the list
      {"allow_only_tools": ["openai.chat", ...]}
          -> "deny" if the action's tool is NOT in the list
      {"deny_action_types": ["api_request"]}
          -> "deny" if action_type is in the list
      {"require_approval_tools": ["stripe.charge", "email.send", ...]}
          -> "approval" if the action's tool is in the list (the action
             is otherwise permitted, but a human must approve it first)

    Pattern versions (fnmatch, "kb.*"), written by the policy hierarchy
    (services/hier_policy.py), one rule set per level:
      allow_only_tool_patterns, deny_tool_patterns,
      require_approval_tool_patterns, allow_only_model_patterns (the model
      of a model-invoking tool)

    Unknown rule keys are ignored, so a typo can't silently block or gate
    everything.
    """
    from app.core.policy_doc import matches
    tool = ctx.tool_name
    ctx.violation = None
    arg_verdict = "ok"
    if "argument_rules" in rule:
        # ASI02: constraints on WHAT a tool is called with, not just which tool
        from app.services.argument_rules import evaluate_argument_rules
        arg_verdict, ctx.violation = evaluate_argument_rules(
            rule.get("argument_rules") or [], tool, ctx.input_data or {}
        )
        if arg_verdict == "deny":
            return "deny"
    if "deny_tools" in rule:
        if tool in set(rule.get("deny_tools") or []):
            return "deny"
    if "allow_only_tools" in rule:
        if tool not in set(rule.get("allow_only_tools") or []):
            return "deny"
    if "deny_tool_patterns" in rule:
        if tool and matches(tool, rule.get("deny_tool_patterns") or []):
            return "deny"
    if "allow_only_tool_patterns" in rule:
        if not tool or not matches(tool, rule.get("allow_only_tool_patterns") or []):
            return "deny"
    if "allow_only_model_patterns" in rule and tool in _MODEL_INVOKING_TOOLS:
        model = (ctx.input_data or {}).get("model")
        if model and not matches(str(model), rule.get("allow_only_model_patterns") or []):
            return "deny"
    if "deny_action_types" in rule:
        if ctx.action_type in set(rule.get("deny_action_types") or []):
            return "deny"
    if "require_approval_tools" in rule:
        if tool in set(rule.get("require_approval_tools") or []):
            return "approval"
    if "require_approval_tool_patterns" in rule:
        if tool and matches(tool, rule.get("require_approval_tool_patterns") or []):
            return "approval"
    if arg_verdict == "approval":
        return "approval"
    return "ok"


def check_action(
    agent: AgentView,
    chain: ChainView,
    ctx: ActionContext,
    custom_policies: Optional[List[Dict[str, Any]]] = None,
) -> Decision:
    # 0. agent must be active
    if agent.status != "active":
        return Decision(DENIED, f"Agent is {agent.status}, not active", "policy_violation")

    # 0b. the chain must be active. No new incident here: the chain is already
    # stopped, and an incident per refused call would only create a storm.
    if chain.status == "tripped":
        return Decision(DENIED, "Chain halted by the circuit breaker (ASI08); an admin must resume it", None)
    if chain.status != "active":
        return Decision(DENIED, f"Chain is {chain.status}; no further actions are allowed", None)
    if not chain.member:
        return Decision(DENIED, "Agent is not part of this delegation chain", "not_in_chain")

    # 1. tool allowlist
    if ctx.tool_name and ctx.tool_name not in set(agent.allowed_tools or []):
        return Decision(DENIED, f"Tool '{ctx.tool_name}' is not in the agent's allowed tools",
                        "policy_violation")

    # 2. model allowlist (only for model-invoking tools)
    if ctx.tool_name in _MODEL_INVOKING_TOOLS:
        model = ctx.input_data.get("model")
        if model and model not in set(agent.allowed_models or []):
            return Decision(DENIED, f"Model '{model}' is not in the agent's allowed models",
                            "policy_violation")

    # 3. delegation depth
    if chain.max_depth_reached > agent.max_delegation_depth:
        return Decision(DENIED, "Delegation depth exceeded", "depth_exceeded")

    # delegation expiry: an action can't run under a delegation that has
    # already expired (the temporal equivalent of capability escalation).
    if chain.delegation_expires_at is not None:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        exp = chain.delegation_expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if now >= exp:
            return Decision(DENIED, "Delegation has expired", "delegation_expired")

    # 4. capability escalation (action must stay within the chain grant)
    escalated = escalated_items(ctx.action_capabilities, chain.granted_capabilities)
    if escalated:
        return Decision(
            DENIED,
            f"Capability escalation detected: {', '.join(escalated)}",
            "capability_escalation",
        )

    # 5. custom policies (can only further restrict). A deny wins
    # outright; an approval requirement is remembered and applied only if
    # nothing denies the action - so "deny" always beats "needs approval".
    approval = None  # (policy id, reason): the first approval requirement found
    for policy in custom_policies or []:
        rules = policy.get("rules") or {}
        # rules can be a single rule dict or a list of them
        rule_list = rules if isinstance(rules, list) else [rules]
        for rule in rule_list:
            verdict = evaluate_custom_rule(rule, ctx)
            if verdict == "deny":
                return Decision(
                    DENIED,
                    f"Blocked by policy '{policy.get('name', policy.get('id'))}'"
                    + (f": {ctx.violation}" if ctx.violation else ""),
                    "policy_violation",
                    matched_policy_id=policy.get("id"),
                )
            if verdict == "approval" and approval is None:
                # policies of the hierarchy have no id: a marker, not the id, says "found"
                approval = (policy.get("id"), (
                    f"Action requires human approval per policy "
                    f"'{policy.get('name', policy.get('id'))}'"
                    + (f": {ctx.violation}" if ctx.violation else "")
                ))

    if approval is not None:
        return Decision(PENDING_APPROVAL, approval[1], None, matched_policy_id=approval[0])

    return Decision(ALLOWED, "Action permitted")
