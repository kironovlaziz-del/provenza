# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza - https://github.com/kironovlaziz-del/provenza

"""
An agent's own network, seen by the egress sensor (docs/egress-lockdown.md,
"The agent's network").

Every new agent gets a workload of its own: observe mode, DNS through the
sensor ("any": every name resolves, and the sensor learns which name each
address came from), nothing allowed, no cgroup patterns. It governs nothing
until the agent is started on a Linux host with the sensor:

    provenza-sensor --agent <id> run -- <the agent's command>

Then every connection the agent makes is recorded - nothing is blocked - and
the agent's page lists where it went. An administrator allows those
destinations and switches the workload to enforce in one step; the kernel
then refuses everything else.

Observe by default, enforce by a person's decision: a new agent is never
blocked by a list nobody wrote.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.egress_sensor import EgressSensor, EgressSensorWorkload, EgressViolation, EgressWorkload
from app.services import egress_sensor as svc
from app.services.audit_service import AuditService

# how far back the agent's page looks for where it went
DESTINATIONS_WINDOW = timedelta(days=30)
DESTINATIONS_LIMIT = 200
# a sensor that has not reported for this long no longer counts as running the agent
RUNNING_FRESH = timedelta(minutes=5)
# Every workload of an organization goes to every sensor, which holds at most
# about 4096 (two generations in an 8192-entry kernel map, sensor.bpf.c). New
# agents stop getting one of their own past this many, leaving room for the
# ones people make; the agent's page still offers it.
AUTO_WORKLOADS_MAX = 1000


def _description(agent_id: int) -> str:
    return (f"Made with agent #{agent_id}: its network, observed. Start the agent on a Linux host "
            f"with the Provenza sensor: provenza-sensor --agent {agent_id} run -- <command>")


async def agent_workload(db: AsyncSession, org_id: int, agent_id: int) -> Optional[EgressWorkload]:
    """The agent's workload: the oldest one naming it that is not deleted."""
    return (await db.execute(
        select(EgressWorkload).where(
            EgressWorkload.org_id == org_id,
            EgressWorkload.agent_id == agent_id,
            EgressWorkload.deleted_at.is_(None),
        ).order_by(EgressWorkload.id.asc()).limit(1)
    )).scalar_one_or_none()


async def _free_name(db: AsyncSession, org_id: int, base: str) -> str:
    """base, or base-2, base-3, ...: workload names are unique in an
    organization, deleted ones included."""
    taken = set((await db.execute(
        select(EgressWorkload.name).where(
            EgressWorkload.org_id == org_id,
            EgressWorkload.name.like(f"{base}%"),
        )
    )).scalars().all())
    if base not in taken:
        return base
    n = 2
    while f"{base}-{n}" in taken:
        n += 1
    return f"{base}-{n}"


async def ensure_agent_workload(db: AsyncSession, agent, actor_user_id: Optional[int],
                                by_default: bool = False) -> Optional[EgressWorkload]:
    """The agent's workload, made in observe mode when it has none. Its audit
    record commits it (AuditService.log), so call it once the agent itself
    is stored. by_default (a new agent): none past AUTO_WORKLOADS_MAX."""
    w = await agent_workload(db, agent.org_id, agent.id)
    if w is not None:
        return w
    if by_default:
        n = await db.scalar(select(func.count(EgressWorkload.id)).where(
            EgressWorkload.org_id == agent.org_id, EgressWorkload.deleted_at.is_(None)))
        if (n or 0) >= AUTO_WORKLOADS_MAX:
            return None
    w = EgressWorkload(
        org_id=agent.org_id, agent_id=agent.id,
        name=await _free_name(db, agent.org_id, f"agent-{agent.id}"),
        description=_description(agent.id),
        cgroup_patterns=[], run_as_users=[], egress_allow=[], ingress_allow=[],
        dns="any", mode="observe", isolated=False, enabled=True, created_by=actor_user_id,
    )
    db.add(w)
    await db.flush()
    await svc.bump_revision(db, agent.org_id)
    await AuditService(db).log(
        agent.org_id, actor_user_id, "egress_workload", w.id, "created",
        {"name": w.name, "agent_id": agent.id, "mode": w.mode, "dns": w.dns, "with_agent": True},
    )
    return w


def _workload_out(w: EgressWorkload) -> Dict[str, Any]:
    return {"id": w.id, "name": w.name, "mode": w.mode, "dns": w.dns, "enabled": bool(w.enabled),
            "isolated": bool(w.isolated), "egress_allow": list(w.egress_allow or [])}


async def network_state(db: AsyncSession, agent) -> Dict[str, Any]:
    """What the agent's page shows: its workload, the hosts that run it under
    the sensor now, and where it went."""
    w = await agent_workload(db, agent.org_id, agent.id)
    out: Dict[str, Any] = {"agent_id": agent.id, "workload": None, "running": [], "destinations": []}
    if w is None:
        return out
    out["workload"] = _workload_out(w)
    now = svc.now_utc()

    rows = (await db.execute(
        select(EgressSensor.id, EgressSensor.name, EgressSensor.hostname, EgressSensorWorkload.cgroups,
               EgressSensorWorkload.processes, EgressSensor.last_seen_at)
        .join(EgressSensorWorkload, EgressSensorWorkload.sensor_id == EgressSensor.id)
        .where(EgressSensorWorkload.workload_id == w.id, EgressSensorWorkload.cgroups > 0,
               EgressSensor.org_id == agent.org_id, EgressSensor.revoked_at.is_(None),
               EgressSensor.last_seen_at >= now - RUNNING_FRESH)
        .order_by(EgressSensor.id.asc())
    )).all()
    out["running"] = [{"sensor_id": r[0], "sensor": r[1], "hostname": r[2], "cgroups": r[3], "processes": r[4],
                       "last_seen_at": r[5]} for r in rows]

    # where it went: one row per destination - the name the sensor learned
    # from the agent's own DNS, or else the address - with port and protocol
    dest = func.coalesce(EgressViolation.dst_name, EgressViolation.dst_ip)
    rows = (await db.execute(
        select(dest.label("dest"), EgressViolation.dst_port, EgressViolation.protocol,
               func.sum(EgressViolation.count), func.max(EgressViolation.created_at),
               func.max(EgressViolation.dst_ip), func.bool_or(EgressViolation.dst_name.isnot(None)),
               func.bool_or(EgressViolation.action == "blocked"))
        .where(EgressViolation.org_id == agent.org_id, EgressViolation.workload_id == w.id,
               EgressViolation.created_at >= now - DESTINATIONS_WINDOW,
               EgressViolation.kind != "ingress", EgressViolation.dst_ip.isnot(None))
        .group_by(dest, EgressViolation.dst_port, EgressViolation.protocol)
        .order_by(func.max(EgressViolation.created_at).desc())
        .limit(DESTINATIONS_LIMIT)
    )).all()
    out["destinations"] = [{"dest": r[0], "port": r[1], "protocol": r[2] or None, "count": int(r[3] or 0),
                            "last_at": r[4], "address": r[5], "named": bool(r[6]), "blocked": bool(r[7])}
                           for r in rows]
    return out


def allow_rules(destinations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The allow list for these destinations: one rule per destination and
    protocol, with every port the agent used."""
    merged: Dict[tuple, set] = {}
    for d in destinations:
        key = (d["dest"], (d.get("protocol") or "").lower())
        ports = merged.setdefault(key, set())
        if d.get("port"):
            ports.add(int(d["port"]))
    rules = []
    for (dest, proto), ports in sorted(merged.items()):
        rule: Dict[str, Any] = {"dest": dest, "ports": sorted(ports), "protocols": [proto] if proto else []}
        rules.append(rule)
    return rules


def _is_name(dest: str) -> bool:
    """A host name, not an address or a network."""
    import ipaddress

    try:
        ipaddress.ip_network(dest, strict=False)
        return False
    except ValueError:
        return True


async def enforce(db: AsyncSession, agent, w: EgressWorkload, rules: List[Dict[str, Any]],
                  actor_user_id: Optional[int]) -> EgressWorkload:
    """Allow exactly these destinations and refuse the rest. Names resolve
    through the sensor ("listed": names not allowed do not resolve)."""
    before = {"mode": w.mode, "dns": w.dns, "egress_allow": list(w.egress_allow or [])}
    w.egress_allow = rules
    w.mode = "enforce"
    if any(_is_name(r["dest"]) for r in rules):
        w.dns = "listed"
    await svc.bump_revision(db, agent.org_id)
    await db.flush()
    await AuditService(db).log(
        agent.org_id, actor_user_id, "egress_workload", w.id, "updated",
        {"changes": {k: {"from": before[k], "to": getattr(w, k)} for k in before}, "agent_id": agent.id,
         "via": "agent_network"},
    )
    return w
