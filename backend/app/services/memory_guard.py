# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Memory-integrity guard - OWASP Agentic Top 10, ASI06 (memory & context poisoning).

Whatever lands in an agent's long-term memory or in a RAG collection is fed
back into prompts later, to this agent or to others - one poisoned entry
keeps acting long after the attacker left. Two stores are covered:

1. RAG collections (Provenza's own). Every uploaded document is scanned
   chunk by chunk with the ASI01 (prompt injection) and ASI05 (code
   execution) detectors. In enforce mode a poisoned chunk is quarantined;
   retrieval (RAGService.query) only ever returns trusted chunks, so it
   cannot reach a prompt. An admin trusts or revokes a document; nothing is
   deleted - revoking only takes its chunks out of retrieval.

2. Agent memory (the agent's own store). Provenza keeps an attestation, not
   the content: before writing, the agent calls /memory/write and gets a
   status; before putting retrieved memory into a prompt it calls
   /memory/verify with the hashes and uses only what comes back "trusted".
   A changed entry (hash mismatch) is refused and raises an incident.
   Isolation: an agent writes and reads its private namespace
   "agent.<id>[.<anything>]" and the shared namespaces from the settings.

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
from app.models.document_chunk import DocumentChunk
from app.models.document_collection import DocumentCollection
from app.models.memory import MemoryEntry, MemorySettings
from app.models.rag_document import Document
from app.services.code_exec_detector import scan_arguments, scan_value
from app.services.injection_detector import scan_structure, scan_text

MODES = ("off", "monitor", "enforce")
DEFAULT_SHARED = ["shared.*"]
DEFAULTS = {"mode": "monitor", "shared_namespaces": DEFAULT_SHARED, "default_ttl_days": 30}
TAMPER_INCIDENT = "memory_integrity_violation"
MAX_DOC_FINDINGS = 20


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

    # ================================================================== RAG
    async def scan_document(self, org_id: int, document: Document, mode: Optional[str] = None) -> dict:
        """Scan the chunks of one document and set their trust status.

        Called from RAGService._ingest_saved_file after the chunks were added
        and before the ingestion commit; it flushes but never commits, so a
        failure is rolled back together with the ingestion.
        """
        mode = mode or (await self.settings(org_id))["mode"]
        await self.db.flush()
        chunks = (await self.db.execute(
            select(DocumentChunk).where(DocumentChunk.document_id == document.id).order_by(DocumentChunk.chunk_index)
        )).scalars().all()
        if mode == "off":
            for c in chunks:
                c.trust_status = "trusted"
            document.trust_status = "trusted"
            document.trust_details = {"mode": "off", "scanned_at": datetime.now(timezone.utc).isoformat()}
            return document.trust_details

        threshold = await self._threshold(org_id)
        quarantined: List[int] = []
        flagged: List[int] = []
        findings: List[dict] = []
        for c in chunks:
            r = scan_content(c.text or "", threshold)
            if r["poisoned"] and mode == "enforce":
                c.trust_status = "quarantined"
                quarantined.append(c.chunk_index)
            else:
                c.trust_status = "trusted"
                if r["poisoned"] or r["suspicious"]:
                    flagged.append(c.chunk_index)
            if (r["poisoned"] or r["suspicious"]) and len(findings) < MAX_DOC_FINDINGS:
                findings.extend({"chunk_index": c.chunk_index, "poisoned": r["poisoned"], **f}
                                for f in r["findings"][:3])
        document.trust_status = "quarantined" if quarantined else "trusted"
        document.trust_details = {
            "mode": mode, "chunks_scanned": len(chunks), "quarantined_chunks": quarantined,
            "flagged_chunks": flagged, "findings": findings[:MAX_DOC_FINDINGS],
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }
        return document.trust_details

    async def _document(self, org_id: int, document_id: int) -> Document:
        doc = (await self.db.execute(
            select(Document).where(Document.id == document_id, Document.org_id == org_id)
        )).scalar_one_or_none()
        if not doc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
        return doc

    async def set_document_trust(self, org_id: int, document_id: int, trusted: bool, user_id: int) -> dict:
        doc = await self._document(org_id, document_id)
        new = "trusted" if trusted else "revoked"
        chunks = (await self.db.execute(
            select(DocumentChunk).where(DocumentChunk.document_id == doc.id)
        )).scalars().all()
        for c in chunks:
            c.trust_status = new
        before = doc.trust_status
        doc.trust_status = new
        doc.trust_changed_by = user_id
        doc.trust_changed_at = datetime.now(timezone.utc)
        await self.db.commit()
        return {"document_id": doc.id, "before": before, "trust_status": new, "chunks": len(chunks)}

    async def rescan_collection(self, org_id: int, collection_id: int) -> dict:
        coll = (await self.db.execute(
            select(DocumentCollection).where(DocumentCollection.id == collection_id,
                                             DocumentCollection.org_id == org_id)
        )).scalar_one_or_none()
        if not coll:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Collection not found")
        docs = (await self.db.execute(
            select(Document).where(Document.collection_id == coll.id, Document.org_id == org_id,
                                   Document.status == "ready")
        )).scalars().all()
        mode = (await self.settings(org_id))["mode"]
        scanned = skipped = quarantined = 0
        for d in docs:
            if d.trust_changed_by is not None:   # an admin already decided - keep the decision
                skipped += 1
                continue
            details = await self.scan_document(org_id, d, mode)
            scanned += 1
            quarantined += 1 if details.get("quarantined_chunks") else 0
        await self.db.commit()
        return {"collection_id": coll.id, "scanned": scanned, "skipped_decided": skipped,
                "quarantined_documents": quarantined}

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
        docs = (await self.db.execute(
            select(Document, DocumentCollection.name)
            .join(DocumentCollection, DocumentCollection.id == Document.collection_id)
            .where(Document.org_id == org_id, Document.trust_details.is_not(None))
            .order_by(Document.created_at.desc()).limit(300)
        )).all()
        attention = []
        for d, coll in docs:
            det = d.trust_details or {}
            if d.trust_status != "trusted" or det.get("flagged_chunks") or det.get("quarantined_chunks"):
                attention.append({
                    "document_id": d.id, "collection_id": d.collection_id, "collection": coll,
                    "filename": d.filename, "created_at": d.created_at, "trust_status": d.trust_status,
                    "decided": d.trust_changed_by is not None, "details": det,
                })
        q = (select(MemoryEntry, Agent.name).join(Agent, Agent.id == MemoryEntry.agent_id)
             .where(MemoryEntry.org_id == org_id))
        if entry_status:
            q = q.where(MemoryEntry.status == entry_status)
        entries = (await self.db.execute(q.order_by(MemoryEntry.created_at.desc()).limit(100))).all()
        counts = dict((await self.db.execute(
            select(MemoryEntry.status, func.count()).where(MemoryEntry.org_id == org_id).group_by(MemoryEntry.status)
        )).all())
        collections = (await self.db.execute(
            select(DocumentCollection.id, DocumentCollection.name)
            .where(DocumentCollection.org_id == org_id).order_by(DocumentCollection.name)
        )).all()
        return {
            "settings": await self.settings(org_id),
            "entry_counts": counts,
            "documents": attention[:100],
            "entries": [
                {"id": e.id, "agent_id": e.agent_id, "agent_name": name, "chain_id": e.chain_id,
                 "namespace": e.namespace, "key": e.key, "sha256": e.sha256, "size_bytes": e.size_bytes,
                 "source": e.source, "source_ref": e.source_ref, "status": e.status, "reasons": e.reasons,
                 "findings": e.findings, "expires_at": e.expires_at, "created_at": e.created_at,
                 "decided": e.decided_by is not None}
                for e, name in entries
            ],
            "collections": [{"id": cid, "name": n} for cid, n in collections],
        }
