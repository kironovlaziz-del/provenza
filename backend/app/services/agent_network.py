# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza - https://github.com/kironovlaziz-del/provenza

"""
An agent's own network, seen by the egress sensor (docs/egress-lockdown.md,
"The agent's network").

Every new agent gets a workload of its own: observe mode, DNS through the
sensor ("any": every name resolves, and the sensor learns which name each
address came from), nothing allowed, no cgroup patterns. It governs nothing
until the agent is attached to what it runs as on a Linux host with the
sensor - with a click, from the services and containers the host's sensor
lists (attach) - or started through the sensor:

    provenza-sensor --agent <id> run -- <the agent's command>

Then every connection the agent makes is recorded - nothing is blocked - and
the agent's page lists where it went. An administrator allows those
destinations and switches the workload to enforce in one step; the kernel
then refuses everything else.

Observe by default, enforce by a person's decision: a new agent is never
blocked by a list nobody wrote.
"""

from __future__ import annotations

import re
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
# a sensor whose list of services and containers is older than this is not offered
HOSTS_FRESH = timedelta(minutes=15)

# what a sensor may list (sensor/internal/daemon/units.go)
_UNIT_CGROUP = re.compile(r"^(system\.slice/[^/]{1,200}\.service|system\.slice/docker-[0-9a-f]{64}\.scope"
                          r"|machine\.slice/libpod-[0-9a-f]{64}\.scope)$")


# Never offered and never attached: an agent attached there and then enforced
# would cut the network of what governs it - Provenza's own services and
# containers (provenza-*, the sensor's provenzasensor*) - or of the host
# itself: the system manager, SSH, D-Bus, polkit, scheduling, logging, time,
# storage, the container runtimes, the network, the hypervisor's and the
# cloud's guest agents, package updates, the firewall.
_RESERVED_SERVICE = re.compile(
    r"^(provenza[^/]*|systemd-[^/]+|(ssh|sshd|dbus|dbus-broker|polkit|cron|crond|anacron|atd|rsyslog|syslog-ng"
    r"|auditd|containerd|docker|podman|snapd|NetworkManager|ModemManager|networkd-dispatcher|chronyd|ntp|ntpd"
    r"|multipathd|udisks2|lvm2-[^/]+|irqbalance|thermald|accounts-daemon|packagekit|fwupd|unattended-upgrades"
    r"|apparmor|firewalld|ufw|qemu-guest-agent|open-vm-tools|vmtoolsd|cloud-init[^/]*|cloud-config|cloud-final"
    r"|google-guest-agent|amazon-ssm-agent|walinuxagent|getty@[^/]+|serial-getty@[^/]+)\.service)$")
_RESERVED_CONTAINER = re.compile(r"^provenza", re.IGNORECASE)


def reserved_unit(unit: Dict[str, Any]) -> bool:
    """A service or container no agent may be attached to (above)."""
    cgroup = unit.get("cgroup") or ""
    if cgroup.endswith(".service"):
        return bool(_RESERVED_SERVICE.match(cgroup.rsplit("/", 1)[-1]))
    return bool(_RESERVED_CONTAINER.match(unit.get("name") or ""))


def clean_units(units: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """A sensor's list as it is kept: the entries that look like what a
    sensor lists, with only the known fields, bounded."""
    out = []
    for u in units[:500]:
        cg = u.get("cgroup")
        if not isinstance(cg, str) or not _UNIT_CGROUP.match(cg):
            continue
        kind = "service" if cg.endswith(".service") else "container"
        item: Dict[str, Any] = {"kind": kind, "cgroup": cg}
        for key, cap in (("name", 200), ("runtime", 10), ("id", 12)):
            v = u.get(key)
            if isinstance(v, str) and v and v.isprintable():
                item[key] = v[:cap]
        if kind == "container" and item.get("runtime") not in ("docker", "podman"):
            item.pop("runtime", None)
        out.append(item)
    return out


def literal_pattern(cgroup: str) -> str:
    """A workload pattern that matches exactly this cgroup (the sensor's
    patterns are shell wildcards per path segment)."""
    return re.sub(r"([*?\[\\])", r"\\\1", cgroup)


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
            "isolated": bool(w.isolated), "egress_allow": list(w.egress_allow or []),
            "cgroup_patterns": list(w.cgroup_patterns or [])}


async def network_state(db: AsyncSession, agent) -> Dict[str, Any]:
    """What the agent's page shows: its workload, the hosts that run it under
    the sensor now, and where it went."""
    w = await agent_workload(db, agent.org_id, agent.id)
    out: Dict[str, Any] = {"agent_id": agent.id, "workload": None, "running": [], "destinations": [], "hosts": []}
    if w is None:
        return out
    out["workload"] = _workload_out(w)
    now = svc.now_utc()

    # where it can be attached: each live sensor's services and containers,
    # marked when this workload or another one already governs them
    patterns = set(w.cgroup_patterns or [])
    others: Dict[str, str] = {}
    for name, pats in (await db.execute(
        select(EgressWorkload.name, EgressWorkload.cgroup_patterns).where(
            EgressWorkload.org_id == agent.org_id, EgressWorkload.deleted_at.is_(None),
            EgressWorkload.id != w.id)
    )).all():
        for p in pats or []:
            others.setdefault(p, name)
    sensors = (await db.execute(
        select(EgressSensor).where(
            EgressSensor.org_id == agent.org_id, EgressSensor.revoked_at.is_(None),
            EgressSensor.units.isnot(None), EgressSensor.units_at >= now - HOSTS_FRESH)
        .order_by(EgressSensor.name.asc())
    )).scalars().all()
    for s in sensors:
        units = []
        for u in s.units or []:
            if reserved_unit(u):
                continue
            pat = literal_pattern(u["cgroup"])
            units.append({**u, "pattern": pat, "attached": pat in patterns, "taken_by": others.get(pat)})
        out["hosts"].append({"sensor_id": s.id, "sensor": s.name, "hostname": s.hostname, "units": units})

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


class UnitError(Exception):
    def __init__(self, code: str, status: int):
        super().__init__(code)
        self.code, self.status = code, status


async def attach(db: AsyncSession, agent, w: EgressWorkload, sensor_id: int, cgroup: str,
                 actor_user_id: Optional[int]) -> EgressWorkload:
    """Govern the service or container the sensor listed as this agent: its
    cgroup becomes one of the workload's patterns. Only what the sensor
    listed, not what another workload governs, and never Provenza's own
    services or the host's core ones (reserved_unit)."""
    s = (await db.execute(select(EgressSensor).where(
        EgressSensor.id == sensor_id, EgressSensor.org_id == agent.org_id, EgressSensor.revoked_at.is_(None))
    )).scalar_one_or_none()
    if s is None:
        raise UnitError("agent_network.sensor_not_found", 404)
    unit = next((u for u in (s.units or []) if u.get("cgroup") == cgroup), None)
    if unit is None:
        raise UnitError("agent_network.unit_not_listed", 422)
    if reserved_unit(unit):
        raise UnitError("agent_network.unit_reserved", 422)
    pat = literal_pattern(cgroup)
    taken = (await db.execute(select(EgressWorkload.name).where(
        EgressWorkload.org_id == agent.org_id, EgressWorkload.deleted_at.is_(None), EgressWorkload.id != w.id,
        EgressWorkload.cgroup_patterns.contains([pat])))).scalars().first()
    if taken:
        raise UnitError("agent_network.unit_taken", 409)
    before = list(w.cgroup_patterns or [])
    if pat in before:
        return w
    w.cgroup_patterns = before + [pat]
    await svc.bump_revision(db, agent.org_id)
    await db.flush()
    await AuditService(db).log(
        agent.org_id, actor_user_id, "egress_workload", w.id, "updated",
        {"changes": {"cgroup_patterns": {"from": before, "to": list(w.cgroup_patterns)}}, "agent_id": agent.id,
         "sensor_id": s.id, "via": "agent_network"},
    )
    return w


async def detach(db: AsyncSession, agent, w: EgressWorkload, pattern: str,
                 actor_user_id: Optional[int]) -> EgressWorkload:
    """No longer govern what this pattern matches as the agent."""
    before = list(w.cgroup_patterns or [])
    if pattern not in before:
        return w
    w.cgroup_patterns = [p for p in before if p != pattern]
    await svc.bump_revision(db, agent.org_id)
    await db.flush()
    await AuditService(db).log(
        agent.org_id, actor_user_id, "egress_workload", w.id, "updated",
        {"changes": {"cgroup_patterns": {"from": before, "to": list(w.cgroup_patterns)}}, "agent_id": agent.id,
         "via": "agent_network"},
    )
    return w


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
