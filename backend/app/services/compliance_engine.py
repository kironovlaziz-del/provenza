# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Compliance evaluation: runs the catalog (compliance_catalog.py) against what
Provenza knows about the organization and returns, per requirement, a status
with the evidence behind it.

  pass     the evidence supports the requirement
  partial  in place, but incomplete or only observing (monitor mode)
  fail     the evidence shows a gap
  manual   only a person can state it - no valid attestation yet
  na       does not apply (e.g. no high-risk system)

Facts are collected once per evaluation; checks are pure functions over them.
A requirement that needs a person (attest=True) takes the worst of its check
and its latest valid attestation. Scope "system" requirements are evaluated
for every applicable AI system; the requirement takes the worst of them.

Score per framework = (pass + 0.5 x partial) / applicable requirements.
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_system import AISystem
from app.models.compliance import ComplianceAttestation
from app.services.compliance_catalog import CATALOG_VERSION, FRAMEWORKS, REQUIREMENTS

RANK = {"fail": 0, "manual": 1, "partial": 2, "pass": 3}
# Kinds whose events Provenza itself records (agent actions, gateway calls).
SOURCE_KINDS = ("agent", "llm_provider")

Result = Tuple[str, str, List[dict]]  # status, detail, evidence [{label, value, link?}]


def _worst(statuses: List[str]) -> str:
    real = [s for s in statuses if s != "na"]
    if not real:
        return "na"
    return min(real, key=lambda s: RANK[s])


def ev(label: str, value: Any, link: Optional[str] = None) -> dict:
    out = {"label": label, "value": value}
    if link:
        out["link"] = link
    return out


# ====================================================================== facts
async def _safe(coro, default):
    try:
        return await coro
    except Exception:  # noqa: BLE001 - a missing module/table makes one fact unknown, not the report
        return default


async def collect_facts(db: AsyncSession, org_id: int) -> dict:
    from app.core.config import settings
    from app.models.agent import Agent, AgentPolicy
    from app.models.agent_action import AgentIncident
    from app.models.ai_policy import AIPolicy
    from app.models.audit_log import AIAuditLog
    from app.models.ai_provider import AIProvider

    now = datetime.now(timezone.utc)
    f: Dict[str, Any] = {"now": now}
    systems = (await db.execute(select(AISystem).where(AISystem.org_id == org_id))).scalars().all()
    f["systems"] = list(systems)
    f["active_systems"] = [s for s in systems if s.lifecycle_stage != "retired"]

    async def count(q):
        return (await db.execute(q)).scalar_one()

    f["audit_30d"] = await _safe(count(select(func.count()).select_from(AIAuditLog).where(
        AIAuditLog.org_id == org_id, AIAuditLog.created_at >= now - timedelta(days=30))), None)
    f["ai_policies"] = await _safe(count(select(func.count()).select_from(AIPolicy).where(AIPolicy.org_id == org_id)), 0)
    f["agents"] = await _safe(count(select(func.count()).select_from(Agent).where(
        Agent.org_id == org_id, Agent.status != "retired")), 0)
    f["agents_without_signing_key"] = await _safe(count(select(func.count()).select_from(Agent).where(
        Agent.org_id == org_id, Agent.status != "retired", Agent.public_key.is_(None))), 0)
    f["agents_without_pq_key"] = await _safe(count(select(func.count()).select_from(Agent).where(
        Agent.org_id == org_id, Agent.status != "retired", Agent.pq_public_key.is_(None))), 0)
    f["providers"] = await _safe(count(select(func.count()).select_from(AIProvider).where(AIProvider.org_id == org_id)), 0)

    rules = await _safe(db.execute(select(AgentPolicy.rules).where(
        AgentPolicy.org_id == org_id, AgentPolicy.enabled.is_(True))), None)
    rules = [r or {} for r in rules.scalars().all()] if rules is not None else []
    f["agent_policies"] = len(rules)
    f["approval_rules"] = sum(1 for r in rules if r.get("require_approval_tools"))
    f["argument_rules"] = sum(len(r.get("argument_rules") or []) for r in rules)

    inc = await _safe(db.execute(select(AgentIncident.severity, func.count()).where(
        AgentIncident.org_id == org_id, AgentIncident.resolved.is_(False)).group_by(AgentIncident.severity)), None)
    f["open_incidents"] = dict(inc.all()) if inc is not None else {}
    f["incidents_90d"] = await _safe(count(select(func.count()).select_from(AgentIncident).where(
        AgentIncident.org_id == org_id, AgentIncident.created_at >= now - timedelta(days=90))), 0)

    async def tool_counts():
        from app.models.tool_registry import ToolRegistryEntry
        rows = await db.execute(select(ToolRegistryEntry.status, func.count())
                                .where(ToolRegistryEntry.org_id == org_id).group_by(ToolRegistryEntry.status))
        return dict(rows.all())
    f["tools"] = await _safe(tool_counts(), {})

    async def breaker():
        from app.models.breaker import AgentBreakerSettings
        row = (await db.execute(select(AgentBreakerSettings.enabled)
                                .where(AgentBreakerSettings.org_id == org_id))).scalar_one_or_none()
        return True if row is None else bool(row)          # no row = defaults, which are on
    f["breaker_enabled"] = await _safe(breaker(), None)

    async def mode(module: str, cls: str):
        import importlib
        svc = getattr(importlib.import_module(module), cls)(db)
        return (await svc.settings(org_id))["mode"]
    f["modes"] = {
        "injection": await _safe(mode("app.services.injection_guard", "InjectionGuard"), None),
        "code_exec": await _safe(mode("app.services.code_exec_guard", "CodeExecGuard"), None),
        "memory": await _safe(mode("app.services.memory_guard", "MemoryGuard"), None),
        "a2a": await _safe(mode("app.services.a2a_guard", "A2AGuard"), None),
        "behavior": await _safe(mode("app.services.behavior_monitor", "BehaviorMonitor"), None),
    }

    async def identity():
        from app.services.agent_identity import org_settings
        return await org_settings(db, org_id)
    ident = await _safe(identity(), None)
    f["require_agent_key"] = ident["require_agent_key"] if ident else None
    f["require_pq_signatures"] = ident.get("require_pq_signatures") if ident else None

    async def retention():
        from app.services.queue_ttl import org_settings
        return (await org_settings(db, org_id))["raw_prompt_retention_days"]
    f["retention_days"] = await _safe(retention(), None)

    async def byok():
        from app.models.org_key import OrgKey
        return (await db.execute(select(func.count()).select_from(OrgKey).where(
            OrgKey.org_id == org_id, OrgKey.status == "active"))).scalar_one() > 0
    f["byok"] = await _safe(byok(), False)
    f["encryption_key_set"] = bool((settings.ENCRYPTION_KEY or "").strip())

    async def assessments():
        from app.models.impact_assessment import ImpactAssessment
        rows = (await db.execute(select(ImpactAssessment).where(ImpactAssessment.org_id == org_id)
                                 .order_by(ImpactAssessment.version))).scalars().all()
        approved, drafts = {}, set()
        for a in rows:                       # by version: the last approved one wins
            if a.status == "approved":
                approved[a.system_id] = a
            else:
                drafts.add(a.system_id)
        return approved, drafts
    f["assessments"], f["assessment_drafts"] = await _safe(assessments(), ({}, set()))

    async def assurance():
        from app.models.assurance import AssuranceRecord
        rows = (await db.execute(select(AssuranceRecord).where(AssuranceRecord.org_id == org_id)
                                 .order_by(AssuranceRecord.performed_on.desc(), AssuranceRecord.id.desc()))).scalars().all()
        out: Dict[int, list] = {}
        for r in rows:                       # newest first, per system
            out.setdefault(r.system_id, []).append(r)
        return out
    f["assurance"] = await _safe(assurance(), {})

    async def gateway():
        from app.models.gateway import GatewaySettings
        g = (await db.execute(select(GatewaySettings).where(GatewaySettings.org_id == org_id))).scalar_one_or_none()
        # no row: the defaults hold (models/gateway.py)
        return {"enabled": True, "rpm": 60, "max_tokens": 4096} if g is None else \
            {"enabled": bool(g.enabled), "rpm": g.rpm_per_agent, "max_tokens": g.max_tokens_cap}
    f["gateway"] = await _safe(gateway(), None)

    async def mfa():
        from app.models.organization import Organization
        return (await db.execute(select(Organization.mfa_required).where(Organization.id == org_id))).scalar() or "none"
    f["mfa_required"] = await _safe(mfa(), "none")
    return f


# ====================================================================== helpers
def _owner(s: AISystem) -> bool:
    return s.owner_user_id is not None or bool((s.business_owner or "").strip())


def _pii(s: AISystem) -> bool:
    return any(l.contains_pii for l in (s.data_links or []))


def _share(n_ok: int, n: int, what: str, link: str) -> Result:
    if n == 0:
        return "partial", f"No active AI system yet - nothing to {what}", [ev("active systems", 0, link)]
    status = "pass" if n_ok == n else "partial" if n_ok else "fail"
    return status, f"{n_ok} of {n} active systems", [ev("systems", f"{n_ok}/{n}", link)]


def _mode(m: Optional[str], name: str, link: str) -> Result:
    if m is None:
        return "fail", f"{name} is not installed", []
    return ({"enforce": "pass", "monitor": "partial", "off": "fail"}.get(m, "fail"),
            f"{name}: {m}", [ev("mode", m, link)])


def _no_agents(f) -> Optional[Result]:
    if not f["agents"]:
        return "na", "No agent registered", [ev("agents", 0, "/agents")]
    return None


# ====================================================================== org checks
def c_no_unacceptable(f) -> Result:
    bad = [s for s in f["active_systems"] if s.lifecycle_stage == "production"
           and (s.confirmed_risk_tier or s.suggested_risk_tier) == "unacceptable"]
    if bad:
        return "fail", f"{len(bad)} unacceptable-risk system(s) in production", \
            [ev(s.name, "unacceptable", f"/inventory/{s.id}") for s in bad[:10]]
    return "pass", "No unacceptable-risk system in production", [ev("checked systems", len(f["active_systems"]), "/inventory")]


def c_inventory_classified(f) -> Result:
    act = f["active_systems"]
    ok = [s for s in act if s.confirmed_risk_tier]
    st, detail, e = _share(len(ok), len(act), "classify", "/inventory")
    return st, f"Risk tier confirmed: {detail}", e


def c_ai_act_roles_stated(f) -> Result:
    act = f["active_systems"]
    st, detail, e = _share(sum(bool(s.ai_act_roles) for s in act), len(act), "describe", "/inventory")
    return st, f"Role under the AI Act stated: {detail}", e


def _tier(s: AISystem) -> Optional[str]:
    return s.confirmed_risk_tier or s.suggested_risk_tier


def c_impact_assessed(f) -> Result:
    """Every active system above minimal risk has an approved, current
    impact assessment (ISO/IEC 42001 A.5)."""
    need = [s for s in f["active_systems"] if _tier(s) in ("high", "limited", "unacceptable")]
    if not need:
        return "pass", "No active AI system above minimal risk", [ev("systems above minimal risk", 0, "/inventory")]
    ok = sum(s_impact_assessed(f, s)[0] == "pass" for s in need)
    st, detail, e = _share(ok, len(need), "assess", "/inventory")
    return st, f"Impact assessment approved and current: {detail} above minimal risk", e


def c_consumption_limits(f) -> Result:
    """Requests per agent and tokens per call are capped at the AI gateway
    (OWASP LLM10, MITRE ATLAS AML.M0004)."""
    g = f["gateway"]
    if g is None:
        return "manual", "Gateway settings could not be read", []
    e = [ev("requests per agent per minute", g["rpm"], "/gateway"), ev("max tokens per call", g["max_tokens"], "/gateway")]
    if not g["enabled"]:
        return "fail", "The AI gateway is off: nothing caps consumption", e
    if g["rpm"] and g["max_tokens"]:
        return "pass", f"At most {g['rpm']} requests per agent a minute and {g['max_tokens']} tokens a call", e
    return "partial", "Only part of the consumption is capped", e


def c_mfa(f) -> Result:
    """People who sign in use a second factor (NIS2 Art. 21(2)(j))."""
    m = f["mfa_required"]
    e = [ev("two-factor sign-in required for", m, "/users")]
    if m == "all":
        return "pass", "Two-factor sign-in is required for everyone", e
    if m == "reviewers":
        return "partial", "Two-factor sign-in is required for admins, approvers and oversight roles only", e
    return "fail", "Two-factor sign-in is not required", e


def c_injection_defenses(f) -> Result:
    """What governance can do about prompt injection (OWASP LLM01): risky
    actions need a person, and systems are tested against misuse."""
    parts = [c_asi_approvals(f), c_assurance_tested(f)]
    return _worst([p[0] for p in parts]), "; ".join(p[1] for p in parts), [x for p in parts for x in p[2]]


def c_owners_assigned(f) -> Result:
    act = f["active_systems"]
    st, detail, e = _share(sum(_owner(s) for s in act), len(act), "assign", "/inventory")
    return st, f"Named owner: {detail}", e


def c_owners_and_monitoring(f) -> Result:
    owners = c_owners_assigned(f)
    mon = c_monitoring(f)
    return _worst([owners[0], mon[0]]), f"{owners[1]}; {mon[1]}", owners[2] + mon[2]


def c_monitoring(f) -> Result:
    m = f["modes"]["behavior"]
    audit = f["audit_30d"]
    if m in ("monitor", "enforce") and audit:
        return "pass", f"Behaviour monitor {m}, {audit} audit events in 30 days", \
            [ev("behaviour monitor", m, "/agent-behavior"), ev("audit events, 30 days", audit, "/audit")]
    if m in ("monitor", "enforce") or audit:
        return "partial", "Only part of the monitoring is active", \
            [ev("behaviour monitor", m or "off", "/agent-behavior"), ev("audit events, 30 days", audit or 0, "/audit")]
    return "fail", "No monitoring evidence", [ev("behaviour monitor", m or "off", "/agent-behavior")]


def c_incidents(f) -> Result:
    open_ = f["open_incidents"]
    crit = open_.get("critical", 0) + open_.get("high", 0)
    e = [ev("open incidents (critical/high)", crit, "/agent-incidents"), ev("incidents, 90 days", f["incidents_90d"])]
    if crit:
        return "partial", f"{crit} critical/high incident(s) still open", e
    return "pass", "Incidents are recorded and none critical is open", e


def c_pii_masking(f) -> Result:
    return "pass", "Every prompt passes the Prompt Firewall: PII is masked before it reaches a model", \
        [ev("Prompt Firewall", "always on", "/requests"), ev("AI Gateway", "masks every message", "/gateway")]


def c_prompt_retention(f) -> Result:
    d = f["retention_days"]
    if d:
        return "pass", f"Encrypted raw prompts are wiped after {d} days", [ev("retention, days", d, "/queue-ttl")]
    return "fail", "Encrypted raw prompts are kept indefinitely", [ev("retention", "indefinite", "/queue-ttl")]


def c_erasure(f) -> Result:
    e = [ev("organization key (BYOK)", "active" if f["byok"] else "off", "/encryption-keys"),
         ev("raw prompt retention", f["retention_days"] or "indefinite", "/queue-ttl")]
    if f["byok"]:
        return "pass", "Crypto-shredding of the organization key makes its data unreadable on request", e
    return "partial", "Records can be removed one by one; organization-wide erasure needs BYOK", e


def c_approvals(f) -> Result:
    if f["approval_rules"]:
        return "pass", f"{f['approval_rules']} policy(ies) send actions to a human", \
            [ev("approval policies", f["approval_rules"], "/agent-policies")]
    return "fail", "No policy sends any action to a human", [ev("approval policies", 0, "/agent-policies")]


def c_human_intervention(f) -> Result:
    na = _no_agents(f)
    return na if na else c_approvals(f)


def c_privacy_by_design(f) -> Result:
    parts = [c_pii_masking(f)[0], _mode(f["modes"]["memory"], "Memory integrity", "/agent-memory")[0],
             c_prompt_retention(f)[0]]
    return _worst(parts), "PII masking, memory integrity and retention by default", \
        [ev("PII masking", "on", "/requests"), ev("memory integrity", f["modes"]["memory"] or "off", "/agent-memory"),
         ev("retention, days", f["retention_days"] or "indefinite", "/queue-ttl")]


def c_pii_systems(f) -> Result:
    pii = [s for s in f["active_systems"] if _pii(s)]
    if not pii:
        return "partial", "No system is marked as processing personal data - verify the data links", \
            [ev("systems with personal data", 0, "/inventory")]
    ok = [s for s in pii if s.review_status == "reviewed" and _owner(s)]
    st = "pass" if len(ok) == len(pii) else "partial"
    return st, f"{len(ok)} of {len(pii)} systems with personal data reviewed and owned", \
        [ev(s.name, "documented" if s in ok else "incomplete", f"/inventory/{s.id}") for s in pii[:10]]


def c_security(f) -> Result:
    e = [ev("encryption at rest", "on" if f["encryption_key_set"] else "OFF", "/encryption-keys"),
         ev("organization key (BYOK)", "active" if f["byok"] else "off", "/encryption-keys"),
         ev("agents must use their own key", "yes" if f["require_agent_key"] else "no", "/agent-identity")]
    if not f["encryption_key_set"]:
        return "fail", "Secrets are not encrypted with a configured key", e
    if f["byok"] or f["require_agent_key"]:
        return "pass", "Encryption at rest and strong agent/organization key controls", e
    return "partial", "Encryption at rest; BYOK and mandatory agent keys are off", e


def c_ai_policies(f) -> Result:
    n = (f["ai_policies"] or 0) + f["agent_policies"]
    if n:
        return "pass", f"{n} AI / agent policies in force", [ev("AI policies", f["ai_policies"], "/policies"),
                                                             ev("agent policies", f["agent_policies"], "/agent-policies")]
    return "fail", "No AI or agent policy defined", [ev("policies", 0, "/policies")]


def c_resources(f) -> Result:
    act = f["active_systems"]
    st, detail, e = _share(sum(bool(s.data_links) for s in act), len(act), "document", "/inventory")
    return st, f"Data documented: {detail}", e


def c_lifecycle(f) -> Result:
    bad = [s for s in f["active_systems"] if "in_production_without_confirmed_risk" in (s.attention or [])]
    if bad:
        return "partial", f"{len(bad)} system(s) in production without a confirmed risk tier", \
            [ev(s.name, "unconfirmed", f"/inventory/{s.id}") for s in bad[:10]]
    return "pass", "Production only after risk confirmation; retiring stops the source", \
        [ev("systems", len(f["active_systems"]), "/inventory")]


def c_audit(f) -> Result:
    n = f["audit_30d"]
    if n is None:
        return "fail", "Audit log not available", []
    return ("pass" if n else "fail"), f"{n} audit events in the last 30 days", [ev("audit events", n, "/audit")]


def c_use_cases(f) -> Result:
    act = f["active_systems"]
    st, detail, e = _share(sum(s.use_case_id is not None for s in act), len(act), "link", "/inventory")
    return st, f"Intended use linked: {detail}", e


def c_third_parties(f) -> Result:
    t = f["tools"]
    e = [ev("connections", f["providers"], "/providers")] + [ev(f"tools {k}", v, "/tool-registry") for k, v in t.items()]
    if t.get("drifted") or t.get("blocked"):
        return "partial", "Some third-party tools drifted or are blocked", e
    if t.get("pending"):
        return "partial", f"{t['pending']} tool(s) wait for approval", e
    if t.get("approved"):
        return "pass", "Third-party tools are approved and pinned", e
    return ("partial", "No tool registered in the Tool Registry", e) if f["agents"] else ("na", "No agent uses tools", e)


def c_containment(f) -> Result:
    parts = [("pass" if f["breaker_enabled"] else "fail"), c_approvals(f)[0]]
    status = "pass" if all(p == "pass" for p in parts) else "partial" if "pass" in parts else "fail"
    return status, "Circuit breaker and human approval", \
        [ev("circuit breaker", "on" if f["breaker_enabled"] else "off", "/agent-breaker"),
         ev("approval policies", f["approval_rules"], "/agent-policies")]


def c_deactivation(f) -> Result:
    return "pass", "Retiring a system stops its source; agents can be quarantined; chains can be tripped", \
        [ev("retire stops the source", "yes", "/inventory"), ev("quarantine", "yes", "/agent-behavior"),
         ev("circuit breaker", "on" if f["breaker_enabled"] else "off", "/agent-breaker")]


def c_argument_rules(f) -> Result:
    na = _no_agents(f)
    if na:
        return na
    n = f["argument_rules"]
    return ("pass" if n else "fail"), f"{n} argument constraint(s) on agent tools", \
        [ev("argument rules", n, "/agent-policies")]


def c_identity(f) -> Result:
    na = _no_agents(f)
    if na:
        return na
    e = [ev("agent key required", "yes" if f["require_agent_key"] else "no", "/agent-identity"),
         ev("agents without signing key", f["agents_without_signing_key"], "/agent-identity"),
         ev("post-quantum (Ed25519 + ML-DSA-65) signatures required",
            "yes" if f.get("require_pq_signatures") else "no", "/agent-identity"),
         ev("agents without a post-quantum key", f.get("agents_without_pq_key"), "/agent-identity")]
    if f["require_agent_key"] and not f["agents_without_signing_key"]:
        return "pass", "Agents act only as themselves, with their own keys", e
    return "partial", "Agent keys exist but are optional, or some agents cannot sign", e


def c_tool_registry(f) -> Result:
    na = _no_agents(f)
    return na if na else c_third_parties(f)


def c_breaker(f) -> Result:
    na = _no_agents(f)
    if na:
        return na
    return ("pass" if f["breaker_enabled"] else "fail"), \
        f"Circuit breaker {'on' if f['breaker_enabled'] else 'off'}", \
        [ev("circuit breaker", "on" if f["breaker_enabled"] else "off", "/agent-breaker")]


def c_asi_approvals(f) -> Result:
    na = _no_agents(f)
    return na if na else c_approvals(f)


def mode_check(key: str, name: str, link: str) -> Callable:
    def check(f) -> Result:
        na = _no_agents(f)
        return na if na else _mode(f["modes"][key], name, link)
    return check


# ====================================================================== system checks
def s_risk_confirmed(f, s: AISystem) -> Result:
    if not s.confirmed_risk_tier:
        return "fail", "Risk tier not confirmed by a person", [ev("risk tier", "unconfirmed", f"/inventory/{s.id}")]
    return "pass", f"Confirmed {s.confirmed_risk_tier}", [ev("risk tier", s.confirmed_risk_tier, f"/inventory/{s.id}")]


def s_impact_assessed(f, s: AISystem) -> Result:
    link = f"/inventory/{s.id}/assessment"
    a = f["assessments"].get(s.id)
    if a is None:
        if s.id in f["assessment_drafts"]:
            return "partial", "Impact assessment drafted, not approved", [ev("impact assessment", "draft", link)]
        return "fail", "No impact assessment", [ev("impact assessment", "none", link)]
    e = [ev("impact assessment", f"v{a.version}, approved {a.approved_at:%Y-%m-%d}", link)]
    ans = a.answers or {}
    if ans.get("decision") == "do_not_proceed" and s.lifecycle_stage == "production":
        return "fail", "The assessment concluded not to proceed, yet the system is in production", e
    due = a.review_due
    if due is not None and due < f["now"]:
        return "partial", f"Review was due {due:%Y-%m-%d}", e
    return "pass", f"Approved v{a.version}, residual risk {ans.get('residual', '?')}", e


def s_dpia(f, s: AISystem) -> Result:
    """The impact assessment, read as a DPIA: it must say the system processes
    personal data when its data links do."""
    st, detail, e = s_impact_assessed(f, s)
    a = f["assessments"].get(s.id)
    if a is not None and st == "pass" and (a.answers or {}).get("personal_data") != "yes":
        return "partial", "The assessment says no personal data, but the system's data links contain some", e
    return st, detail, e


# A test counts for this long; after it the system needs testing again.
ASSURANCE_VALID = timedelta(days=365)
ADVERSARIAL = ("red_team", "robustness")


def _recent(f, s: AISystem) -> list:
    since = (f["now"] - ASSURANCE_VALID).date()
    return [r for r in f["assurance"].get(s.id, []) if r.performed_on >= since]


def _latest(records: list, kinds) -> Optional[Any]:
    return next((r for r in records if r.kind in kinds), None)   # newest first


def s_assurance(f, s: AISystem) -> Result:
    """EU AI Act Art. 15: the system's quality is evaluated and it was tested
    against misuse (red teaming or robustness) within the last year, and the
    latest of each did not fail and is not overdue."""
    link = f"/inventory/{s.id}"
    recent = _recent(f, s)
    ev_ = _latest(recent, ("evaluation",))
    adv = _latest(recent, ADVERSARIAL)
    e = [ev("evaluation", f"{ev_.performed_on:%Y-%m-%d} {ev_.result}" if ev_ else "none", link),
         ev("red teaming / robustness", f"{adv.performed_on:%Y-%m-%d} {adv.result}" if adv else "none", link)]
    if not ev_ and not adv:
        return "fail", "No evaluation or adversarial test recorded in the last year", e
    gaps = []
    if not ev_:
        gaps.append("no quality evaluation in the last year")
    if not adv:
        gaps.append("no red teaming or robustness test in the last year")
    today = f["now"].date()
    for r in (ev_, adv):
        if r is not None and r.result == "failed":
            gaps.append(f"the latest {r.kind.replace('_', ' ')} failed")
        if r is not None and r.next_due is not None and r.next_due < today:
            gaps.append(f"{r.kind.replace('_', ' ')} due again since {r.next_due:%Y-%m-%d}")
    if gaps:
        return "partial", "; ".join(gaps).capitalize(), e
    return "pass", f"Evaluated {ev_.performed_on:%Y-%m-%d}, tested against misuse {adv.performed_on:%Y-%m-%d}", e


def s_data_and_bias(f, s: AISystem) -> Result:
    """EU AI Act Art. 10: the data is documented, and examined for bias
    (Art. 10(2)(f)) within the last year."""
    st, detail, e = s_data_documented(f, s)
    bias = _latest(_recent(f, s), ("bias",))
    e = e + [ev("bias test", f"{bias.performed_on:%Y-%m-%d} {bias.result}" if bias else "none", f"/inventory/{s.id}")]
    if st != "pass":
        return st, detail, e
    if bias is None:
        return "partial", f"{detail}; no bias test in the last year", e
    if bias.result == "failed":
        return "partial", f"{detail}; the latest bias test failed", e
    return "pass", f"{detail}; bias tested {bias.performed_on:%Y-%m-%d}", e


def c_assurance_tested(f) -> Result:
    """Every active system above minimal risk has a test on record from the
    last year (ISO/IEC 42001 A.6.2.4, NIST MEASURE 1)."""
    need = [s for s in f["active_systems"] if _tier(s) in ("high", "limited", "unacceptable")]
    if not need:
        return "pass", "No active AI system above minimal risk", [ev("systems above minimal risk", 0, "/inventory")]
    st, detail, e = _share(sum(bool(_recent(f, s)) for s in need), len(need), "test", "/inventory")
    return st, f"Tested in the last year: {detail} above minimal risk", e


def s_data_documented(f, s: AISystem) -> Result:
    n = len(s.data_links or [])
    return ("pass" if n else "fail"), f"{n} data link(s)", [ev("data links", n, f"/inventory/{s.id}")]


def s_logged(f, s: AISystem) -> Result:
    if s.kind in SOURCE_KINDS and s.source_key:
        return "pass", "Provenza records this system's events", [ev("event source", s.source_key, f"/inventory/{s.id}")]
    return "partial", "No linked source - its events are not recorded by Provenza", [ev("event source", "none", f"/inventory/{s.id}")]


def s_oversight(f, s: AISystem) -> Result:
    if s.kind == "agent":
        return c_approvals(f)
    return "manual", "Human oversight of this system must be described", []


def s_robustness(f, s: AISystem) -> Result:
    parts = [_mode(f["modes"]["injection"], "Prompt-injection guard", "/agent-injection"),
             _mode(f["modes"]["code_exec"], "Code-execution guard", "/agent-code-exec")]
    return _worst([p[0] for p in parts]), "; ".join(p[1] for p in parts), [e for p in parts for e in p[2]]


CHECKS: Dict[str, Callable] = {
    "no_unacceptable_in_production": c_no_unacceptable,
    "inventory_classified": c_inventory_classified,
    "owners_assigned": c_owners_assigned,
    "ai_act_roles_stated": c_ai_act_roles_stated,
    "impact_assessed": c_impact_assessed,
    "assurance_tested": c_assurance_tested,
    "consumption_limits": c_consumption_limits,
    "mfa_enforced": c_mfa,
    "injection_defenses": c_injection_defenses,
    "owners_and_monitoring": c_owners_and_monitoring,
    "monitoring_active": c_monitoring,
    "incidents_handled": c_incidents,
    "pii_masking": c_pii_masking,
    "prompt_retention": c_prompt_retention,
    "erasure_capability": c_erasure,
    "human_intervention": c_human_intervention,
    "privacy_by_design": c_privacy_by_design,
    "pii_systems_documented": c_pii_systems,
    "security_of_processing": c_security,
    "ai_policies": c_ai_policies,
    "resources_documented": c_resources,
    "lifecycle_managed": c_lifecycle,
    "audit_active": c_audit,
    "use_cases_linked": c_use_cases,
    "third_parties_governed": c_third_parties,
    "containment": c_containment,
    "deactivation": c_deactivation,
    "argument_rules": c_argument_rules,
    "agent_identity": c_identity,
    "tool_registry": c_tool_registry,
    "breaker": c_breaker,
    "approvals": c_asi_approvals,
    "mode:injection": mode_check("injection", "Prompt-injection guard", "/agent-injection"),
    "mode:code_exec": mode_check("code_exec", "Code-execution guard", "/agent-code-exec"),
    "mode:memory": mode_check("memory", "Memory integrity", "/agent-memory"),
    "mode:a2a": mode_check("a2a", "Agent-to-agent messages", "/agent-messages"),
    "mode:behavior": mode_check("behavior", "Behaviour monitor", "/agent-behavior"),
}
SYSTEM_CHECKS: Dict[str, Callable] = {
    "sys_risk_confirmed": s_risk_confirmed,
    "sys_impact_assessed": s_impact_assessed,
    "sys_assurance": s_assurance,
    "sys_data_and_bias": s_data_and_bias,
    "sys_dpia": s_dpia,
    "sys_data_documented": s_data_documented,
    "sys_logged": s_logged,
    "sys_human_oversight": s_oversight,
    "sys_robustness": s_robustness,
}


def _has_role(req: dict, s: AISystem) -> bool:
    """The system is one of the operators the obligation is addressed to; a
    system whose roles are not stated counts as every one of them."""
    roles = req.get("roles")
    return not roles or not s.ai_act_roles or bool(set(roles) & set(s.ai_act_roles))


def _org_role_gap(req: dict, facts: dict) -> Optional[str]:
    """For an organization-wide obligation of some roles only: why it does not
    apply - every active system states its roles and none is one of them."""
    roles = req.get("roles")
    act = facts["active_systems"]
    if not roles or not act or any(_has_role(req, s) for s in act):
        return None
    return "No AI system where the organization is " + " or ".join(roles)


def _applies(req: dict, s: AISystem) -> bool:
    if s.lifecycle_stage == "retired":
        return False
    if not _has_role(req, s):
        return False
    a = req["applies"]
    if a == "high_risk":
        return (s.confirmed_risk_tier or s.suggested_risk_tier) == "high"
    if a == "pii":
        return _pii(s)
    if a == "agents":
        return s.kind == "agent"
    return True


# ====================================================================== attestations
async def latest_attestations(db: AsyncSession, org_id: int) -> Dict[Tuple[str, Optional[int]], dict]:
    rows = (await db.execute(
        select(ComplianceAttestation).where(ComplianceAttestation.org_id == org_id)
        .order_by(ComplianceAttestation.attested_at.desc(), ComplianceAttestation.id.desc())
    )).scalars().all()
    now = datetime.now(timezone.utc)
    out: Dict[Tuple[str, Optional[int]], dict] = {}
    for a in rows:
        key = (a.requirement_id, a.system_id)
        if key in out:
            continue                        # newest wins
        valid_until = a.valid_until if a.valid_until is None or a.valid_until.tzinfo else a.valid_until.replace(tzinfo=timezone.utc)
        out[key] = {"id": a.id, "status": a.status, "note": a.note, "evidence_url": a.evidence_url,
                    "attested_by": a.attested_by, "attested_at": a.attested_at, "valid_until": a.valid_until,
                    "expired": valid_until is not None and valid_until < now}
    return out


def _combine(req: dict, check: Optional[Result], att: Optional[dict]) -> Tuple[str, str, List[dict], Optional[dict]]:
    parts, details, evidence = [], [], []
    if check is not None:
        parts.append(check[0])
        details.append(check[1])
        evidence += check[2]
    if req["attest"]:
        if att is None or att["expired"]:
            parts.append("manual")
            details.append("A person must attest this" + (" (the last attestation expired)" if att else ""))
        elif att["status"] == "not_applicable":
            return "na", "Attested as not applicable" + (f": {att['note']}" if att["note"] else ""), evidence, att
        else:
            parts.append("pass" if att["status"] == "met" else "fail")
            details.append(f"Attested {att['status'].replace('_', ' ')}")
            if att["evidence_url"]:
                evidence.append(ev("document", att["evidence_url"], att["evidence_url"]))
    if check is not None and check[0] == "na":
        return "na", check[1], evidence, att
    return _worst(parts) if parts else "manual", "; ".join(details), evidence, att


# ====================================================================== evaluation
async def evaluate(db: AsyncSession, org_id: int, frameworks: Optional[List[str]] = None) -> dict:
    frameworks = [fw for fw in (frameworks or list(FRAMEWORKS)) if fw in FRAMEWORKS]
    facts = await collect_facts(db, org_id)
    atts = await latest_attestations(db, org_id)
    out_reqs = []
    for req in REQUIREMENTS:
        if req["framework"] not in frameworks:
            continue
        item = {k: req.get(k) for k in ("id", "framework", "ref", "title", "scope", "applies", "attest", "fix", "roles")}
        gap = _org_role_gap(req, facts) if req["scope"] == "org" else None
        if gap:
            item.update(status="na", detail=gap, evidence=[], attestation=None)
        elif req["scope"] == "org":
            check = CHECKS[req["check"]](facts) if req["check"] else None
            status, detail, evidence, att = _combine(req, check, atts.get((req["id"], None)))
            item.update(status=status, detail=detail, evidence=evidence, attestation=att)
        else:
            systems = [s for s in facts["systems"] if _applies(req, s)]
            rows = []
            for s in systems:
                check = SYSTEM_CHECKS[req["check"]](facts, s) if req["check"] else None
                st, detail, evidence, att = _combine(req, check, atts.get((req["id"], s.id)))
                rows.append({"system_id": s.id, "system": s.name, "status": st, "detail": detail,
                             "evidence": evidence, "attestation": att})
            if not rows:
                who = f"; organization as {' or '.join(req['roles'])}" if req.get("roles") else ""
                item.update(status="na", detail=f"No applicable AI system ({req['applies'].replace('_', '-')}{who})",
                            evidence=[], attestation=None)
            else:
                st = _worst([r["status"] for r in rows])
                n_ok = sum(r["status"] in ("pass", "na") for r in rows)
                item.update(status=st, detail=f"{n_ok} of {len(rows)} applicable systems meet it",
                            evidence=[], attestation=None)
            item["systems"] = rows
        out_reqs.append(item)

    summary = {}
    for fw in frameworks:
        reqs = [r for r in out_reqs if r["framework"] == fw]
        counts = {k: sum(r["status"] == k for r in reqs) for k in ("pass", "partial", "fail", "manual", "na")}
        applicable = len(reqs) - counts["na"]
        score = round((counts["pass"] + 0.5 * counts["partial"]) / applicable * 100) if applicable else None
        summary[fw] = {**FRAMEWORKS[fw], "counts": counts, "applicable": applicable, "score": score}
    return {"catalog_version": CATALOG_VERSION, "generated_at": facts["now"].isoformat(), "org_id": org_id,
            "frameworks": frameworks, "summary": summary, "requirements": out_reqs}


def canonical_hash(content: dict) -> str:
    data = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()
