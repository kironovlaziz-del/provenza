# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Prompt-injection guard - OWASP Agentic Top 10, ASI01 (agent goal hijack).

Two places where hostile text reaches an agent:

  * arguments (/actions/check) - the agent is about to pass text that
    carries an instruction ("ignore previous instructions and ...") to a
    tool, usually because it already swallowed it somewhere upstream;
  * outputs (/actions/record) - a tool returned a web page, e-mail or
    document with an instruction embedded in it (indirect injection).

mode "off"      nothing is scanned;
mode "monitor"  (default) detections are recorded and appended to the
                decision reason, nothing is blocked; an injected output
                raises an indirect_prompt_injection incident;
mode "enforce"  an argument with an injection is refused; an injected
                output also *taints* the delegation chain: from then on every
                action in that chain that the policies would allow needs a
                human approval (ASI09 review) until an admin clears the taint.
"""

import dataclasses
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.agent_action import AgentIncident
from app.models.delegation import DelegationChain
from app.models.injection import InjectionDetection, InjectionSettings
from app.services.agent_policy_engine import ALLOWED, DENIED, PENDING_APPROVAL, Decision
from app.services.injection_detector import DEFAULT_THRESHOLD, SUSPICIOUS, WEIGHTS, scan_structure

MODES = ("off", "monitor", "enforce")
DEFAULTS = {"mode": "monitor", "threshold": DEFAULT_THRESHOLD}
BOUNDS = {"threshold": (SUSPICIOUS + 10, 100)}
VIOLATION = "prompt_injection"
OUTPUT_INCIDENT = "indirect_prompt_injection"


def _replace(decision: Decision, **changes) -> Decision:
    if dataclasses.is_dataclass(decision):
        return dataclasses.replace(decision, **changes)
    for k, v in changes.items():
        setattr(decision, k, v)
    return decision


def _brief(report: dict) -> str:
    labels = ", ".join(f["label"] for f in report["hits"][0]["findings"][:3]) if report["hits"] else ""
    return f"{report['verdict']} in '{report['path']}' (score {report['score']}: {labels})"


class InjectionGuard:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------ settings
    async def _settings_row(self, org_id: int) -> Optional[InjectionSettings]:
        return (await self.db.execute(
            select(InjectionSettings).where(InjectionSettings.org_id == org_id)
        )).scalar_one_or_none()

    async def settings(self, org_id: int) -> dict:
        row = await self._settings_row(org_id)
        if not row:
            return {**DEFAULTS, "source": "default"}
        return {"mode": row.mode, "threshold": row.threshold, "source": "org"}

    async def save_settings(self, org_id: int, values: dict, user_id: int) -> tuple:
        row = await self._settings_row(org_id)
        before = None if row is None else {k: getattr(row, k) for k in DEFAULTS}
        if row is None:
            row = InjectionSettings(org_id=org_id)
            self.db.add(row)
        for k in DEFAULTS:
            setattr(row, k, values[k])
        row.updated_by = user_id
        await self.db.commit()
        return before, {k: values[k] for k in DEFAULTS}

    # ------------------------------------------------------------------ helpers
    async def _chain(self, org_id: int, chain_id: Optional[int]) -> Optional[DelegationChain]:
        if chain_id is None:
            return None
        return (await self.db.execute(
            select(DelegationChain).where(DelegationChain.id == chain_id, DelegationChain.org_id == org_id)
        )).scalar_one_or_none()

    def _record(self, org_id, agent_id, chain_id, action_id, source, tool_name, report, outcome) -> None:
        top = report["hits"][0] if report["hits"] else {"findings": []}
        self.db.add(InjectionDetection(
            org_id=org_id, agent_id=agent_id, chain_id=chain_id, action_id=action_id, source=source,
            tool_name=(tool_name or None) and str(tool_name)[:100], path=(report["path"] or "")[:300],
            verdict=report["verdict"], score=report["score"], findings=top["findings"], outcome=outcome,
        ))

    # ------------------------------------------------------------------ arguments (/actions/check)
    async def apply(self, org_id: int, agent_id: int, chain_id: Optional[int], tool_name: Optional[str],
                    input_data: Any, decision: Decision) -> Decision:
        """Called by AgentAudit.check after the policy engine and the Tool Registry
        allowed (or held) the action. Never turns a denial into anything else."""
        cfg = await self.settings(org_id)
        if cfg["mode"] == "off" or decision.result == DENIED:
            return decision
        enforce = cfg["mode"] == "enforce"
        report = scan_structure(input_data or {}, cfg["threshold"])
        chain = await self._chain(org_id, chain_id)
        tainted = chain is not None and chain.tainted_at is not None

        if report["verdict"] == "injection" and enforce:
            self._record(org_id, agent_id, chain_id, None, "argument", tool_name, report, "blocked")
            await self.db.commit()
            return Decision(DENIED, f"Prompt-injection pattern: {_brief(report)} (ASI01)", VIOLATION)

        result = decision
        if report["verdict"] != "clean":
            self._record(org_id, agent_id, chain_id, None, "argument", tool_name, report, "flagged")
            result = _replace(result, reason=f"{result.reason} | ASI01 {cfg['mode']}: {_brief(report)}")
        if tainted and enforce and result.result == ALLOWED:
            result = _replace(result, result=PENDING_APPROVAL,
                              reason=f"{result.reason} | ASI01: chain #{chain.id} is tainted by an injected "
                                     f"tool output; a human must review this action")
        if report["verdict"] != "clean":
            await self.db.commit()
        return result

    # ------------------------------------------------------------------ outputs (/actions/record)
    async def scan_output(self, org_id: int, agent_id: int, chain_id: Optional[int], action_id: Optional[int],
                          tool_name: Optional[str], output: Any) -> Optional[dict]:
        cfg = await self.settings(org_id)
        if cfg["mode"] == "off" or output in (None, "", {}, []):
            return None
        report = scan_structure(output, cfg["threshold"])
        if report["verdict"] == "clean":
            return None
        enforce = cfg["mode"] == "enforce"
        chain = await self._chain(org_id, chain_id)
        taint = report["verdict"] == "injection" and enforce and chain is not None
        if taint and chain.tainted_at is None:
            now = datetime.now(timezone.utc)
            chain.tainted_at = now
            chain.taint_details = {"action_id": action_id, "agent_id": agent_id, "tool_name": tool_name,
                                   "path": report["path"], "score": report["score"],
                                   "findings": report["hits"][0]["findings"], "tainted_at": now.isoformat()}
        self._record(org_id, agent_id, chain_id, action_id, "output", tool_name, report,
                     "tainted" if taint else "flagged")
        if report["verdict"] == "injection":
            extra = {"chain_id": chain_id} if hasattr(AgentIncident, "chain_id") else {}
            self.db.add(AgentIncident(
                org_id=org_id, agent_id=agent_id, incident_type=OUTPUT_INCIDENT, severity="high", **extra,
                details={"action_id": action_id, "tool_name": tool_name, "path": report["path"],
                         "score": report["score"], "findings": report["hits"][0]["findings"],
                         "chain_tainted": taint, "mode": cfg["mode"]},
            ))
        await self.db.commit()
        return {**report, "chain_tainted": taint}

    # ------------------------------------------------------------------ operator actions
    async def clear_taint(self, org_id: int, chain_id: int, user_id: int) -> dict:
        chain = await self._chain(org_id, chain_id)
        if chain is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delegation chain not found")
        if chain.tainted_at is None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Chain is not tainted")
        details = dict(chain.taint_details or {})
        details.update({"cleared_at": datetime.now(timezone.utc).isoformat(), "cleared_by": user_id})
        chain.tainted_at = None
        chain.taint_details = details
        await self.db.commit()
        return {"chain_id": chain.id, "tainted": False}

    async def overview(self, org_id: int) -> dict:
        tainted = (await self.db.execute(
            select(DelegationChain, Agent.name)
            .outerjoin(Agent, Agent.id == DelegationChain.root_agent_id)
            .where(DelegationChain.org_id == org_id, DelegationChain.tainted_at.is_not(None))
            .order_by(DelegationChain.tainted_at.desc()).limit(100)
        )).all()
        detections = (await self.db.execute(
            select(InjectionDetection, Agent.name)
            .outerjoin(Agent, Agent.id == InjectionDetection.agent_id)
            .where(InjectionDetection.org_id == org_id)
            .order_by(InjectionDetection.detected_at.desc()).limit(100)
        )).all()
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        counts = dict((await self.db.execute(
            select(InjectionDetection.outcome, func.count())
            .where(InjectionDetection.org_id == org_id, InjectionDetection.detected_at >= since)
            .group_by(InjectionDetection.outcome)
        )).all())
        return {
            "settings": await self.settings(org_id),
            "bounds": BOUNDS,
            "weights": WEIGHTS,
            "counts_24h": counts,
            "tainted_chains": [
                {"chain_id": c.id, "root_agent": name, "status": c.status, "tainted_at": c.tainted_at,
                 "details": c.taint_details or {}}
                for c, name in tainted
            ],
            "detections": [
                {"id": d.id, "detected_at": d.detected_at, "agent_id": d.agent_id, "agent_name": name,
                 "chain_id": d.chain_id, "action_id": d.action_id, "source": d.source, "tool_name": d.tool_name,
                 "path": d.path, "verdict": d.verdict, "score": d.score, "findings": d.findings,
                 "outcome": d.outcome}
                for d, name in detections
            ],
        }
