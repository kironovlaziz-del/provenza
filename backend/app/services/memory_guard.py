# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Memory-integrity guard - OWASP Agentic Top 10, ASI06 (memory & context poisoning).

Whatever lands in an agent's long-term memory is fed back into prompts
later, to this agent or to others - one poisoned entry keeps acting long
after the attacker left.

Provenza keeps an attestation of agent memory, not the content: before
writing, the agent calls /memory/write and gets a status; before putting
retrieved memory into a prompt it calls /memory/verify with the hashes and
uses only what comes back "trusted". The content is scanned with the ASI01
(prompt injection) and ASI05 (code execution) detectors, and a changed
entry (hash mismatch) is refused and raises an incident. Isolation: an
agent writes and reads its private namespace "agent.<id>[.<anything>]" and
the shared namespaces from the settings.

   hash = sha256(utf-8 text) for a string,
          sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=False).encode()) otherwise.

mode "off"      nothing is checked, everything is trusted;
mode "monitor"  (default) findings are recorded, nothing is quarantined or
                rejected;
mode "enforce"  poisoned content is quarantined, a write into a foreign
                namespace or by a non-active agent is rejected, a write that
                comes from a chain tainted by ASI01 is quarantined.
"""

import fnmatch
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.agent_action import AgentIncident
from app.models.delegation import DelegationChain
from app.models.memory import MemoryEntry, MemorySettings
from app.services.code_exec_detector import scan_arguments, scan_value
from app.services.injection_detector import scan_structure, scan_text

MODES = ("off", "monitor", "enforce")
DEFAULT_SHARED = ["shared.*"]
DEFAULTS = {"mode": "monitor", "shared_namespaces": DEFAULT_SHARED, "default_ttl_days": 30}
TAMPER_INCIDENT = "memory_integrity_violation"


def memory_hash(content: Any) -> str:
    if isinstance(content, str):
        data = content.encode("utf-8")
    else:
        data = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def scan_content(content: Any, threshold: int) -> dict:
    """ASI01 + ASI05 detectors over one text or JSON value."""
    if isinstance(content, str):
        inj = scan_text(content, threshold)
        inj_findings = inj["findings"]
        code = scan_value(content, "$")
        code_sev = max((f["severity"] for f in code), key=["medium", "high", "critical"].index, default="none")
    else:
        inj = scan_structure(content, threshold)
        inj_findings = inj["hits"][0]["findings"] if inj["hits"] else []
        rep = scan_arguments(content)
        code, code_sev = rep["findings"], rep["severity"]
    findings = [{"check": "ASI01", "label": f["label"], "snippet": f["snippet"]} for f in inj_findings[:5]]
    findings += [{"check": "ASI05", "label": f["label"], "severity": f["severity"], "snippet": f["snippet"]}
                 for f in code[:5]]
    poisoned = inj["verdict"] == "injection" or code_sev == "critical"
    suspicious = not poisoned and (inj["verdict"] == "suspicious" or code_sev == "high")
    return {"poisoned": poisoned, "suspicious": suspicious, "injection": inj["verdict"],
            "injection_score": inj["score"], "code_severity": code_sev, "findings": findings}


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class MemoryGuard:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------ settings
    async def _settings_row(self, org_id: int) -> Optional[MemorySettings]:
        return (await self.db.execute(
            select(MemorySettings).where(MemorySettings.org_id == org_id)
        )).scalar_one_or_none()

    async def settings(self, org_id: int) -> dict:
        row = await self._settings_row(org_id)
        if not row:
            return {**DEFAULTS, "shared_namespaces": list(DEFAULT_SHARED), "source": "default"}
        return {"mode": row.mode, "shared_namespaces": list(row.shared_namespaces or []),
                "default_ttl_days": row.default_ttl_days, "source": "org"}

    async def save_settings(self, org_id: int, values: dict, user_id: int) -> tuple:
        row = await self._settings_row(org_id)
        before = None if row is None else {k: getattr(row, k) for k in DEFAULTS}
        if row is None:
            row = MemorySettings(org_id=org_id)
            self.db.add(row)
        for k in DEFAULTS:
            setattr(row, k, values[k])
        row.updated_by = user_id
        await self.db.commit()
        return before, {k: values[k] for k in DEFAULTS}

    async def _threshold(self, org_id: int) -> int:
        from app.services.injection_guard import InjectionGuard
        return (await InjectionGuard(self.db).settings(org_id))["threshold"]

    # ================================================================== agent memory
    def _may_access(self, agent_id: int, namespace: str, shared: List[str]) -> bool:
        own = f"agent.{agent_id}"
        if namespace == own or namespace.startswith(own + "."):
            return True
        return any(fnmatch.fnmatchcase(namespace, g) for g in shared)

    async def _agent(self, org_id: int, agent_id: int) -> Agent:
        agent = (await self.db.execute(
            select(Agent).where(Agent.id == agent_id, Agent.org_id == org_id)
        )).scalar_one_or_none()
        if not agent:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        return agent

    async def write(self, org_id: int, data: dict) -> dict:
        cfg = await self.settings(org_id)
        agent = await self._agent(org_id, data["agent_id"])
        content = data["content"]
        sha = memory_hash(content)
        size = len(content.encode("utf-8")) if isinstance(content, str) else len(json.dumps(content, default=str))
        now = datetime.now(timezone.utc)
        ttl = data.get("ttl_days") or cfg["default_ttl_days"]
        enforce = cfg["mode"] == "enforce"

        chain = None
        if data.get("chain_id") is not None:
            chain = (await self.db.execute(
                select(DelegationChain).where(DelegationChain.id == data["chain_id"], DelegationChain.org_id == org_id)
            )).scalar_one_or_none()
            if not chain:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delegation chain not found")

        reasons: List[str] = []
        findings: List[dict] = []
        new_status = "trusted"
        if cfg["mode"] != "off":
            if not self._may_access(agent.id, data["namespace"], cfg["shared_namespaces"]):
                reasons.append(f"namespace '{data['namespace']}' is neither the agent's own (agent.{agent.id}) "
                               f"nor shared")
                if enforce:
                    new_status = "rejected"
            if agent.status != "active":
                reasons.append(f"agent is {agent.status}")
                if enforce:
                    new_status = "rejected"
            if new_status != "rejected":
                r = scan_content(content, await self._threshold(org_id))
                findings = r["findings"]
                if r["poisoned"]:
                    reasons.append(f"poisoned content (injection {r['injection']}, code {r['code_severity']})")
                    if enforce:
                        new_status = "quarantined"
                elif r["suspicious"]:
                    reasons.append(f"suspicious content (injection {r['injection']}, code {r['code_severity']})")
                tainted = chain is not None and getattr(chain, "tainted_at", None) is not None
                if tainted and data["source"] in ("tool_output", "document"):
                    reasons.append(f"chain #{chain.id} is tainted by an injected tool output (ASI01)")
                    if enforce:
                        new_status = "quarantined"

        entry = MemoryEntry(
            org_id=org_id, agent_id=agent.id, chain_id=chain.id if chain else None,
            namespace=data["namespace"], key=data.get("key"), sha256=sha, size_bytes=size,
            source=data["source"], source_ref=data.get("source_ref"), status=new_status,
            reasons=reasons, findings=findings, expires_at=now + timedelta(days=ttl),
        )
        self.db.add(entry)
        await self.db.commit()
        await self.db.refresh(entry)
        return {"entry_id": entry.id, "sha256": sha, "status": new_status, "use": new_status == "trusted",
                "store": new_status != "rejected", "reasons": reasons, "findings": findings,
                "expires_at": entry.expires_at, "mode": cfg["mode"]}

    async def verify(self, org_id: int, agent_id: int, items: List[dict]) -> dict:
        cfg = await self.settings(org_id)
        agent = await self._agent(org_id, agent_id)
        now = datetime.now(timezone.utc)
        results = []
        tampered = []
        for it in items:
            sha = it["sha256"].lower()
            if it.get("entry_id") is not None:
                entry = (await self.db.execute(
                    select(MemoryEntry).where(MemoryEntry.id == it["entry_id"], MemoryEntry.org_id == org_id)
                )).scalar_one_or_none()
            else:
                entry = (await self.db.execute(
                    select(MemoryEntry).where(MemoryEntry.org_id == org_id, MemoryEntry.sha256 == sha)
                    .order_by(MemoryEntry.created_at.desc()).limit(1)
                )).scalar_one_or_none()
            if entry is None:
                verdict = "unknown"
            elif cfg["mode"] != "off" and not self._may_access(agent.id, entry.namespace, cfg["shared_namespaces"]):
                verdict = "forbidden"
            elif entry.sha256 != sha:
                verdict = "mismatch"
                tampered.append({"entry_id": entry.id, "namespace": entry.namespace})
            elif entry.expires_at is not None and _aware(entry.expires_at) <= now:
                verdict = "expired"
            else:
                verdict = entry.status
            use = verdict == "trusted" or (cfg["mode"] != "enforce" and verdict in ("unknown", "quarantined"))
            results.append({"entry_id": entry.id if entry else it.get("entry_id"), "sha256": sha,
                            "verdict": verdict, "use": use})
        if tampered and cfg["mode"] != "off":
            self.db.add(AgentIncident(
                org_id=org_id, agent_id=agent.id, incident_type=TAMPER_INCIDENT, severity="high",
                details={"entries": tampered, "note": "retrieved memory does not match its attested hash"},
            ))
            await self.db.commit()
        summary: Dict[str, int] = {}
        for r in results:
            summary[r["verdict"]] = summary.get(r["verdict"], 0) + 1
        return {"results": results, "summary": summary, "mode": cfg["mode"]}

    async def set_entry_status(self, org_id: int, entry_id: int, trusted: bool, user_id: int) -> dict:
        entry = (await self.db.execute(
            select(MemoryEntry).where(MemoryEntry.id == entry_id, MemoryEntry.org_id == org_id)
        )).scalar_one_or_none()
        if not entry:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Memory entry not found")
        if entry.status == "rejected":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail="A rejected write was never stored; the agent must write it again")
        before = entry.status
        entry.status = "trusted" if trusted else "revoked"
        entry.decided_by = user_id
        entry.decided_at = datetime.now(timezone.utc)
        await self.db.commit()
        return {"entry_id": entry.id, "before": before, "status": entry.status}

    # ================================================================== overview
    async def overview(self, org_id: int, entry_status: Optional[str] = None) -> dict:
        q = (select(MemoryEntry, Agent.name).join(Agent, Agent.id == MemoryEntry.agent_id)
             .where(MemoryEntry.org_id == org_id))
        if entry_status:
            q = q.where(MemoryEntry.status == entry_status)
        entries = (await self.db.execute(q.order_by(MemoryEntry.created_at.desc()).limit(100))).all()
        counts = dict((await self.db.execute(
            select(MemoryEntry.status, func.count()).where(MemoryEntry.org_id == org_id).group_by(MemoryEntry.status)
        )).all())
        return {
            "settings": await self.settings(org_id),
            "entry_counts": counts,
            "entries": [
                {"id": e.id, "agent_id": e.agent_id, "agent_name": name, "chain_id": e.chain_id,
                 "namespace": e.namespace, "key": e.key, "sha256": e.sha256, "size_bytes": e.size_bytes,
                 "source": e.source, "source_ref": e.source_ref, "status": e.status, "reasons": e.reasons,
                 "findings": e.findings, "expires_at": e.expires_at, "created_at": e.created_at,
                 "decided": e.decided_by is not None}
                for e, name in entries
            ],
        }
