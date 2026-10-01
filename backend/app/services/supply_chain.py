# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Tool Registry - OWASP Agentic Top 10, ASI04 (agentic supply chain).

Every tool an agent calls is matched against the organization's registry:

  mode "off"      - registry ignored
  mode "monitor"  - (default) nothing is blocked except explicitly blocked
                    tools; unknown tools are added as "pending" so the
                    registry fills itself from real traffic
  mode "enforce"  - only approved tools may run; pinned tools must report a
                    matching version / manifest digest

Drift: when an approved, pinned tool reports a different version or
manifest digest, the entry becomes "drifted" and a supply_chain_drift
incident is raised once. In enforce mode the tool is refused until an
admin re-approves it - this is what catches a tool (e.g. an MCP server)
that silently changed after it was approved.

Limitation (documented): version and digest are reported by the agent's
runtime. Independent verification needs Provenza in the call path
(gateway mode).
"""

import fnmatch
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent_action import AgentIncident
from app.models.tool_registry import SupplyChainSettings, ToolRegistryEntry
from app.services.agent_policy_engine import DENIED, Decision

MODES = ("off", "monitor", "enforce")
DEFAULT_MODE = "monitor"
DRIFT_INCIDENT = "supply_chain_drift"
VIOLATION = "supply_chain_violation"
_GLOB_CHARS = set("*?[")


def normalize_digest(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    value = value.strip().lower()
    return value[7:] if value.startswith("sha256:") else value


def manifest_digest(manifest: Any) -> str:
    """Canonical sha256 of a tool manifest: key order and whitespace do not
    matter, so the admin, the SDK and the server all get the same value."""
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def match_entry(entries: List[ToolRegistryEntry], tool: str) -> Optional[ToolRegistryEntry]:
    """Exact name first, else the most specific (longest) matching glob."""
    for entry in entries:
        if entry.pattern == tool:
            return entry
    globs = [e for e in entries if _GLOB_CHARS & set(e.pattern) and fnmatch.fnmatchcase(tool, e.pattern)]
    return max(globs, key=lambda e: len(e.pattern)) if globs else None


class SupplyChain:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------ settings
    async def _settings_row(self, org_id: int) -> Optional[SupplyChainSettings]:
        return (await self.db.execute(
            select(SupplyChainSettings).where(SupplyChainSettings.org_id == org_id)
        )).scalar_one_or_none()

    async def mode(self, org_id: int) -> str:
        row = await self._settings_row(org_id)
        return row.mode if row else DEFAULT_MODE

    async def set_mode(self, org_id: int, mode: str, user_id: int) -> tuple:
        row = await self._settings_row(org_id)
        before = row.mode if row else DEFAULT_MODE
        if row is None:
            row = SupplyChainSettings(org_id=org_id)
            self.db.add(row)
        row.mode = mode
        row.updated_by = user_id
        await self.db.commit()
        return before, mode

    # ------------------------------------------------------------------ registry CRUD
    async def entries(self, org_id: int, status_filter: Optional[str] = None) -> List[ToolRegistryEntry]:
        q = select(ToolRegistryEntry).where(ToolRegistryEntry.org_id == org_id)
        if status_filter:
            q = q.where(ToolRegistryEntry.status == status_filter)
        rows = list((await self.db.execute(q)).scalars().all())
        order = {"drifted": 0, "pending": 1, "blocked": 2, "approved": 3}
        rows.sort(key=lambda e: (order.get(e.status, 9), e.pattern))
        return rows

    async def get(self, org_id: int, entry_id: int) -> ToolRegistryEntry:
        entry = (await self.db.execute(
            select(ToolRegistryEntry)
            .where(ToolRegistryEntry.id == entry_id, ToolRegistryEntry.org_id == org_id)
            .execution_options(populate_existing=True)
        )).scalar_one_or_none()
        if not entry:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Registry entry not found")
        return entry

    async def create(self, org_id: int, user_id: int, values: dict) -> int:
        entry = ToolRegistryEntry(org_id=org_id, discovered=False, seen_count=0, **values)
        entry.pinned_digest = normalize_digest(entry.pinned_digest)
        if entry.status == "approved":
            entry.approved_by = user_id
            entry.approved_at = datetime.now(timezone.utc)
        self.db.add(entry)
        try:
            await self.db.flush()
        except IntegrityError:
            await self.db.rollback()
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail="An entry with this pattern already exists")
        entry_id = entry.id
        await self.db.commit()
        return entry_id

    async def update(self, org_id: int, entry_id: int, changes: dict) -> None:
        entry = await self.get(org_id, entry_id)
        if "pinned_digest" in changes:
            changes["pinned_digest"] = normalize_digest(changes["pinned_digest"])
        for key, value in changes.items():
            setattr(entry, key, value)
        await self.db.commit()

    async def set_status(self, org_id: int, entry_id: int, new_status: str, user_id: int) -> str:
        entry = await self.get(org_id, entry_id)
        previous = entry.status
        entry.status = new_status
        if new_status == "approved":
            entry.approved_by = user_id
            entry.approved_at = datetime.now(timezone.utc)
            entry.drift_details = None
        await self.db.commit()
        return previous

    async def delete(self, org_id: int, entry_id: int) -> dict:
        entry = await self.get(org_id, entry_id)
        snapshot = {"pattern": entry.pattern, "status": entry.status}
        await self.db.delete(entry)
        await self.db.commit()
        return snapshot

    # ------------------------------------------------------------------ enforcement
    @staticmethod
    def _drift(entry: ToolRegistryEntry, version: Optional[str], digest: Optional[str]) -> List[str]:
        problems = []
        if entry.pinned_version and version and version != entry.pinned_version:
            problems.append(f"version {version!r} != pinned {entry.pinned_version!r}")
        reported = normalize_digest(digest)
        if entry.pinned_digest and reported and reported != entry.pinned_digest:
            problems.append("manifest digest differs from the pinned one")
        return problems

    @staticmethod
    def _missing(entry: ToolRegistryEntry, version: Optional[str], digest: Optional[str]) -> List[str]:
        missing = []
        if entry.pinned_version and not version:
            missing.append("version")
        if entry.pinned_digest and not digest:
            missing.append("manifest digest")
        return missing

    async def verify(self, org_id: int, agent_id: int, tool: Optional[str],
                     version: Optional[str] = None, digest: Optional[str] = None) -> Optional[Decision]:
        """Returns a DENIED Decision when the supply-chain rules refuse the
        tool, else None. Also records usage and auto-registers new tools."""
        if not tool:
            return None
        mode = await self.mode(org_id)
        if mode == "off":
            return None
        now = datetime.now(timezone.utc)
        entry = match_entry(await self.entries(org_id), tool)

        if entry is None:
            try:
                async with self.db.begin_nested():
                    self.db.add(ToolRegistryEntry(
                        org_id=org_id, pattern=tool, kind="tool", status="pending", discovered=True,
                        seen_count=1, first_seen_at=now, last_seen_at=now,
                        notes="Discovered automatically on first use",
                    ))
            except IntegrityError:
                pass  # registered concurrently by another request
            await self.db.commit()
            if mode == "enforce":
                return Decision(DENIED, f"Tool '{tool}' is not approved in the Tool Registry (ASI04); "
                                        "it was added for review", VIOLATION)
            return None

        entry.seen_count = (entry.seen_count or 0) + 1
        entry.last_seen_at = now
        denial: Optional[Decision] = None

        if entry.status == "blocked":
            denial = Decision(DENIED, f"Tool '{tool}' is blocked in the Tool Registry (ASI04)", VIOLATION)
        elif entry.status == "approved":
            drift = self._drift(entry, version, digest)
            if drift:
                entry.status = "drifted"
                entry.drift_details = {
                    "detected_at": now.isoformat(),
                    "tool": tool,
                    "problems": drift,
                    "reported_version": version,
                    "reported_digest": normalize_digest(digest),
                    "pinned_version": entry.pinned_version,
                    "pinned_digest": entry.pinned_digest,
                }
                self.db.add(AgentIncident(
                    org_id=org_id, agent_id=agent_id, incident_type=DRIFT_INCIDENT, severity="critical",
                    details={"registry_entry_id": entry.id, "pattern": entry.pattern, **entry.drift_details},
                ))
                if mode == "enforce":
                    denial = Decision(DENIED, f"Tool '{tool}' changed since it was approved "
                                              f"({'; '.join(drift)}) - re-approval required (ASI04)", VIOLATION)
            elif mode == "enforce":
                missing = self._missing(entry, version, digest)
                if missing:
                    denial = Decision(DENIED, f"Tool '{tool}' is pinned; the request must report its "
                                              f"{' and '.join(missing)} (ASI04)", VIOLATION)
        elif mode == "enforce":  # pending or drifted
            denial = Decision(DENIED, f"Tool '{tool}' is {entry.status} in the Tool Registry and needs "
                                      "admin approval (ASI04)", VIOLATION)

        await self.db.commit()
        return denial
