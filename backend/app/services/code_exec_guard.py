# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Code-execution guard - OWASP Agentic Top 10, ASI05 (unexpected code execution).

Runs on every /actions/check after the policies, the Tool Registry and the
prompt-injection guard. It never turns a denial into anything else.

mode "off"      nothing is scanned;
mode "monitor"  (default) findings are recorded and appended to the decision
                reason; nothing is blocked;
mode "enforce"  critical finding                -> denied
                high finding                    -> human approval (ASI09 review)
                any call of a "code tool"       -> human approval, when
                (shell.*, python.*, ...)           approve_code_tools is on
                medium finding                  -> recorded only

"Code tools" are the tools whose job is to run code; their arguments are
scanned in command scope (";", "|", sudo, curl... count) and, in enforce
mode, each call can be sent to a human regardless of what the scan found.
"""

import dataclasses
import fnmatch
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.code_exec import CodeExecDetection, CodeExecSettings
from app.services.agent_policy_engine import ALLOWED, DENIED, PENDING_APPROVAL, Decision
from app.services.code_exec_detector import LABEL_SEVERITY, scan_arguments

MODES = ("off", "monitor", "enforce")
DEFAULT_CODE_TOOLS = ["shell.*", "bash*", "terminal.*", "python.*", "code.*", "*.exec", "*.execute_code",
                      "sandbox.*", "jupyter.*"]
DEFAULTS = {"mode": "monitor", "code_tools": DEFAULT_CODE_TOOLS, "approve_code_tools": True}
VIOLATION = "code_execution"


def _replace(decision: Decision, **changes) -> Decision:
    if dataclasses.is_dataclass(decision):
        return dataclasses.replace(decision, **changes)
    for k, v in changes.items():
        setattr(decision, k, v)
    return decision


def is_code_tool(tool_name: Optional[str], patterns: List[str]) -> bool:
    if not tool_name:
        return False
    name = tool_name.lower()
    return any(fnmatch.fnmatchcase(name, p.lower()) for p in patterns or [])


def _brief(findings: List[dict]) -> str:
    return "; ".join(f"{f['label']} ({f['severity']}) in '{f['path']}'" for f in findings[:3])


class CodeExecGuard:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------ settings
    async def _settings_row(self, org_id: int) -> Optional[CodeExecSettings]:
        return (await self.db.execute(
            select(CodeExecSettings).where(CodeExecSettings.org_id == org_id)
        )).scalar_one_or_none()

    async def settings(self, org_id: int) -> dict:
        row = await self._settings_row(org_id)
        if not row:
            return {**DEFAULTS, "code_tools": list(DEFAULT_CODE_TOOLS), "source": "default"}
        return {"mode": row.mode, "code_tools": list(row.code_tools or []),
                "approve_code_tools": row.approve_code_tools, "source": "org"}

    async def save_settings(self, org_id: int, values: dict, user_id: int) -> tuple:
        row = await self._settings_row(org_id)
        before = None if row is None else {k: getattr(row, k) for k in DEFAULTS}
        if row is None:
            row = CodeExecSettings(org_id=org_id)
            self.db.add(row)
        for k in DEFAULTS:
            setattr(row, k, values[k])
        row.updated_by = user_id
        await self.db.commit()
        return before, {k: values[k] for k in DEFAULTS}

    # ------------------------------------------------------------------ /actions/check
    async def apply(self, org_id: int, agent_id: int, chain_id: Optional[int], tool_name: Optional[str],
                    input_data: Any, decision: Decision) -> Decision:
        cfg = await self.settings(org_id)
        if cfg["mode"] == "off" or decision.result == DENIED:
            return decision
        enforce = cfg["mode"] == "enforce"
        code_tool = is_code_tool(tool_name, cfg["code_tools"])
        report = scan_arguments(input_data or {}, code_tool=code_tool)
        sev = report["severity"]
        findings = report["findings"]

        outcome, result = "flagged", decision
        if enforce and sev == "critical":
            outcome = "blocked"
            result = Decision(DENIED, f"Code execution blocked: {_brief(findings)} (ASI05)", VIOLATION)
        elif enforce and decision.result == ALLOWED and (sev == "high" or (code_tool and cfg["approve_code_tools"])):
            outcome = "held"
            why = _brief(findings) if sev == "high" else f"'{tool_name}' runs code"
            result = _replace(decision, result=PENDING_APPROVAL,
                              reason=f"{decision.reason} | ASI05: {why}; a human must review this call")
        elif sev != "none":
            result = _replace(decision, reason=f"{decision.reason} | ASI05 {cfg['mode']}: {_brief(findings)}")

        if sev != "none" or outcome == "held":
            self.db.add(CodeExecDetection(
                org_id=org_id, agent_id=agent_id, chain_id=chain_id,
                tool_name=(str(tool_name)[:100] if tool_name else None), code_tool=code_tool,
                severity=sev, findings=findings, outcome=outcome,
            ))
            await self.db.commit()
        return result

    # ------------------------------------------------------------------ UI
    async def scan(self, org_id: int, tool_name: Optional[str], arguments: Any) -> dict:
        cfg = await self.settings(org_id)
        code_tool = is_code_tool(tool_name, cfg["code_tools"])
        report = scan_arguments(arguments if arguments is not None else {}, code_tool=code_tool)
        sev = report["severity"]
        if cfg["mode"] == "off":
            would = "allowed"
        elif sev == "critical":
            would = "denied" if cfg["mode"] == "enforce" else "flagged"
        elif sev == "high" or (code_tool and cfg["approve_code_tools"]):
            would = "pending_approval" if cfg["mode"] == "enforce" else ("flagged" if sev != "none" else "allowed")
        else:
            would = "flagged" if sev != "none" else "allowed"
        return {**report, "code_tool": code_tool, "would": would, "mode": cfg["mode"]}

    async def overview(self, org_id: int) -> dict:
        rows = (await self.db.execute(
            select(CodeExecDetection, Agent.name)
            .outerjoin(Agent, Agent.id == CodeExecDetection.agent_id)
            .where(CodeExecDetection.org_id == org_id)
            .order_by(CodeExecDetection.detected_at.desc()).limit(100)
        )).all()
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        counts = dict((await self.db.execute(
            select(CodeExecDetection.outcome, func.count())
            .where(CodeExecDetection.org_id == org_id, CodeExecDetection.detected_at >= since)
            .group_by(CodeExecDetection.outcome)
        )).all())
        return {
            "settings": await self.settings(org_id),
            "default_code_tools": DEFAULT_CODE_TOOLS,
            "labels": LABEL_SEVERITY,
            "counts_24h": counts,
            "detections": [
                {"id": d.id, "detected_at": d.detected_at, "agent_id": d.agent_id, "agent_name": name,
                 "chain_id": d.chain_id, "tool_name": d.tool_name, "code_tool": d.code_tool,
                 "severity": d.severity, "findings": d.findings, "outcome": d.outcome}
                for d, name in rows
            ],
        }
