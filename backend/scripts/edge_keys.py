# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The keys of this host's edge services, made by the installer instead of by
hand (deploy/scripts/edge.sh):

    edge-keys --host web-1 --out /out --proxy --ingestion [--sensor] [--org SLUG]
              [--proxy-binary SHA256 ...] [--proxy-config SHA256 ...]

--proxy      an egress proxy key        -> /out/proxy.key     (Gateways -> External APIs -> Proxies)
--ingestion  an endpoint agent's key    -> /out/ingestion.key (Settings -> Ingestion Sources)
--sensor     an egress sensor's key     -> /out/sensor.key    (Runtime -> Sensors)

Each key is written to its file (mode 600) and nowhere else: it is never
printed. The objects are named after the host and audited as made by the
installer; they are managed and revoked in the interface like any other.

--proxy-binary / --proxy-config add SHA-256 values to the egress proxy
binaries and configurations of the next signed policy release (Policies ->
Signed policy); --drop-proxy-binary / --drop-proxy-config take out the ones
this host added before. Like any change, they take effect only when the
administrators sign that release.

The organization: --org (its slug), or the only one there is.
"""

import argparse
import asyncio
import os
import re
import sys

SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
VIA = {"via": "installer"}


def _write(out: str, name: str, key: str) -> None:
    path = os.path.join(out, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key + "\n")


async def _org(db, slug):
    from sqlalchemy import select

    from app.models.organization import Organization

    if slug:
        org = (await db.execute(select(Organization).where(Organization.slug == slug))).scalar_one_or_none()
        if org is None:
            sys.exit(f"No organization with the slug {slug!r}.")
        return org
    orgs = (await db.execute(select(Organization).order_by(Organization.id).limit(2))).scalars().all()
    if len(orgs) != 1:
        sys.exit("There is not exactly one organization here: name it with --org <slug>.")
    return orgs[0]


async def _sensor_name(db, org_id: int, host: str) -> str:
    """Sensor names are unique among the sensors not revoked."""
    from sqlalchemy import select

    from app.models.egress_sensor import EgressSensor

    taken = set((await db.execute(select(EgressSensor.name).where(
        EgressSensor.org_id == org_id, EgressSensor.revoked_at.is_(None)))).scalars())
    name, n = host, 2
    while name in taken:
        name, n = f"{host}-{n}", n + 1
    return name


async def _release_hashes(db, org_id: int, binaries, configs, drop_binaries=(), drop_configs=()) -> int:
    """Add hashes to the working copy of the next release's settings, and
    take out the ones this host had added before (an upgraded binary, an
    edited configuration). Returns how many changed."""
    from sqlalchemy import select

    from app.models.policy_release import PolicySigningSettings
    from app.services import policy_release as pr

    row = (await db.execute(select(PolicySigningSettings).where(
        PolicySigningSettings.org_id == org_id))).scalar_one_or_none()
    if row is None:
        row = PolicySigningSettings(org_id=org_id, **pr.DEFAULTS)
        db.add(row)
    changed = 0
    for field, values, drop in (("proxy_binaries", binaries, drop_binaries),
                                ("proxy_configs", configs, drop_configs)):
        have = set(getattr(row, field) or [])
        want = (have - set(drop)) | set(values)
        if want == have:
            continue
        if len(want) > pr.PROXY_BINARIES:
            print(f"  ! {field}: more than {pr.PROXY_BINARIES} - remove old ones in "
                  "Policies -> Signed policy, then run this again", file=sys.stderr)
            continue
        setattr(row, field, sorted(want) or None)
        changed += len(want ^ have)
    return changed


async def main(args) -> int:
    from app.api.egress_proxy import KEY_PREFIX
    from app.core.database import AsyncSessionLocal
    from app.core.security import generate_api_key, hash_api_key
    from app.models.egress_proxy import EgressProxy
    from app.models.egress_sensor import EgressSensor
    from app.models.ingestion_source import IngestionSource
    from app.services import egress_sensor as sensor_svc
    from app.services.audit_service import AuditService

    host = re.sub(r"[^A-Za-z0-9._-]+", "-", args.host).strip("-")[:60] or "host"
    for v in args.proxy_binary + args.proxy_config + args.drop_proxy_binary + args.drop_proxy_config:
        if not SHA256_HEX.match(v):
            sys.exit(f"Not a SHA-256 (64 lowercase hex characters): {v!r}")
    if not os.path.isdir(args.out) or not os.access(args.out, os.W_OK):
        sys.exit(f"{args.out} is not a writable directory.")

    async with AsyncSessionLocal() as db:
        org = await _org(db, args.org)
        org_id, slug = org.id, org.slug
        audit = AuditService(db)
        made = []

        if args.proxy:
            key = KEY_PREFIX + generate_api_key()
            p = EgressProxy(org_id=org_id, name=host, key_hash=hash_api_key(key), key_prefix=key[:16])
            db.add(p)
            await db.flush()
            _write(args.out, "proxy.key", key)
            made.append(("egress proxy", p.name, p.id, "egress_proxy", {"name": p.name}))

        if args.ingestion:
            key = generate_api_key()
            s = IngestionSource(org_id=org_id, name=f"{host} (endpoint agent)", source_type="endpoint",
                                api_key_hash=hash_api_key(key), enabled=True)
            db.add(s)
            await db.flush()
            _write(args.out, "ingestion.key", key)
            made.append(("ingestion source", s.name, s.id, "ingestion_source",
                         {"name": s.name, "source_type": "endpoint"}))

        if args.sensor:
            raw, h, prefix = sensor_svc.new_sensor_key()
            sn = EgressSensor(org_id=org_id, name=await _sensor_name(db, org_id, host), key_hash=h,
                              key_prefix=prefix, enabled=True)
            db.add(sn)
            await db.flush()
            _write(args.out, "sensor.key", raw)
            made.append(("egress sensor", sn.name, sn.id, "egress_sensor", {"name": sn.name, "key_prefix": prefix}))

        added = 0
        if args.proxy_binary or args.proxy_config or args.drop_proxy_binary or args.drop_proxy_config:
            added = await _release_hashes(db, org_id, args.proxy_binary, args.proxy_config,
                                          args.drop_proxy_binary, args.drop_proxy_config)
        # each record is appended to the audit chain and committed with what it records
        for _, name, oid, entity, meta in made:
            await audit.log(org_id, None, entity, oid, "created", {**meta, **VIA})
        if added:
            await audit.log(org_id, None, "policy_release", None, "settings_changed",
                            {"proxy_binaries": args.proxy_binary, "proxy_configs": args.proxy_config,
                             "removed": args.drop_proxy_binary + args.drop_proxy_config, **VIA})
        await db.commit()

    for kind, name, oid, _, _ in made:
        print(f"Created {kind} '{name}' (id {oid}) in organization '{slug}'.")
    if added:
        print("The egress proxy's hashes changed in the next signed policy release: sign it in "
              "Policies -> Signed policy.")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Keys for this host's edge services, written to files.")
    p.add_argument("--host", required=True, help="this host's name (names the objects)")
    p.add_argument("--out", required=True, help="directory the key files are written to")
    p.add_argument("--org", help="organization slug (default: the only organization)")
    p.add_argument("--proxy", action="store_true", help="an egress proxy key")
    p.add_argument("--ingestion", action="store_true", help="an endpoint agent's ingestion key")
    p.add_argument("--sensor", action="store_true", help="an egress sensor key")
    p.add_argument("--proxy-binary", action="append", default=[], help="SHA-256 for the next release")
    p.add_argument("--proxy-config", action="append", default=[], help="SHA-256 for the next release")
    p.add_argument("--drop-proxy-binary", action="append", default=[], help="SHA-256 to take out of it")
    p.add_argument("--drop-proxy-config", action="append", default=[], help="SHA-256 to take out of it")
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.exit(asyncio.run(main(p.parse_args())))
