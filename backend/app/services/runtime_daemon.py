# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Violations reported by runtime daemons (daemon/, app/api/runtime.py).

A violation is one distinct (host, workload, action, protocol, destination,
process name): repeats only count up, so a daemon on a host where an agent
retries in a loop costs one row, not millions. The first time one is seen:

  - an agent incident ("runtime_egress_violation") if the workload is linked
    to an agent and the daemon alerted or blocked - observe mode is silent;
  - a "runtime_violation" notification, one per batch at most.
"""

import hashlib
import json
from typing import Any, Dict, List

from sqlalchemy import func, literal_column, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent_action import AgentIncident
from app.models.runtime import RuntimeViolation, RuntimeWorkload
from app.services import notification_service

INCIDENT_TYPE = "runtime_egress_violation"
_LOUD = ("alerted", "blocked")


def _one_line(text: str, limit: int) -> str:
    return "".join(c if c.isprintable() else "?" for c in text)[:limit]


def dedupe_key(workload_id: int, host: str, e: Dict[str, Any]) -> str:
    raw = json.dumps([workload_id, host, e["action"], e["protocol"], e["dst_ip"], e["dst_port"], e.get("comm")],
                     separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode()).hexdigest()


async def ingest_violations(db: AsyncSession, org_id: int, source_id: int, host: str,
                            events: List[Dict[str, Any]]) -> Dict[str, int]:
    host = _one_line(host.strip(), 255) or "unknown"
    ids = {e["workload_id"] for e in events}
    workloads = {w.id: w for w in (await db.execute(select(RuntimeWorkload).where(
        RuntimeWorkload.org_id == org_id, RuntimeWorkload.id.in_(ids)))).scalars()}
    accepted = rejected = 0
    new: List[Dict[str, Any]] = []
    for e in events:
        w = workloads.get(e["workload_id"])
        if w is None:           # another organization's, or deleted since the daemon's last config
            rejected += 1
            continue
        comm = _one_line(e["comm"], 16) if e.get("comm") else None
        cgroup = _one_line(e["cgroup"], 500) if e.get("cgroup") else None
        e = {**e, "comm": comm}
        stmt = pg_insert(RuntimeViolation).values(
            org_id=org_id, source_id=source_id, workload_id=w.id, agent_id=w.agent_id,
            dedupe_key=dedupe_key(w.id, host, e), host=host, action=e["action"], protocol=e["protocol"],
            dst_ip=e["dst_ip"], dst_port=e["dst_port"], comm=comm, cgroup=cgroup, count=e["count"])
        stmt = stmt.on_conflict_do_update(
            constraint="uq_runtime_violations_dedupe",
            set_={"count": RuntimeViolation.count + stmt.excluded.count, "last_seen_at": func.now(),
                  "cgroup": stmt.excluded.cgroup},
        ).returning(RuntimeViolation.id, literal_column("(xmax = 0)").label("inserted"))
        violation_id, inserted = (await db.execute(stmt)).one()
        accepted += 1
        if not inserted or e["action"] not in _LOUD:
            continue
        details = {"violation_id": violation_id, "workload_id": w.id, "workload": w.name, "host": host,
                   "action": e["action"], "protocol": e["protocol"], "dst_ip": e["dst_ip"],
                   "dst_port": e["dst_port"], "comm": comm}
        new.append(details)
        if w.agent_id is not None:
            db.add(AgentIncident(org_id=org_id, agent_id=w.agent_id, incident_type=INCIDENT_TYPE,
                                 severity="high" if e["action"] == "blocked" else "medium", details=details))
    await db.commit()
    if new:
        await _notify(db, org_id, new)
    return {"accepted": accepted, "rejected": rejected, "new": len(new)}


async def _notify(db: AsyncSession, org_id: int, new: List[Dict[str, Any]]) -> None:
    if len(new) == 1:
        v = new[0]
        verb = "blocked" if v["action"] == "blocked" else "made"
        subject = f"Runtime: {v['workload']} {verb} a connection outside its policy"
        message = (f"{v['protocol'].upper()} to {v['dst_ip']}:{v['dst_port']} by '{v['comm'] or '?'}' on "
                   f"{v['host']}. Review it in Runtime -> Violations.")
        await notification_service.notify(db, org_id, "runtime_violation", subject, message, v)
        return
    hosts = sorted({v["host"] for v in new})
    await notification_service.notify(
        db, org_id, "runtime_violation", f"Runtime: {len(new)} new connections outside workload policies",
        f"On {len(hosts)} host(s). Review them in Runtime -> Violations.",
        {"count": len(new), "hosts": len(hosts)})
