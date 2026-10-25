# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""scripts/edge_keys.py: the installer makes this host's keys (deploy/scripts/edge.sh)."""

import argparse
import importlib.util
import os
import stat
from pathlib import Path

import pytest
from sqlalchemy import select

from app.core.security import hash_api_key
from app.models.audit_log import AIAuditLog
from app.models.egress_proxy import EgressProxy
from app.models.egress_sensor import EgressSensor
from app.models.ingestion_source import IngestionSource
from app.models.policy_release import PolicySigningSettings

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "edge_keys.py"
A, B = "a" * 64, "b" * 64


def _module():
    spec = importlib.util.spec_from_file_location("edge_keys", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Session:
    def __init__(self, s):
        self.s = s

    async def __aenter__(self):
        return self.s

    async def __aexit__(self, *exc):
        return False


def _args(out, **kw):
    base = dict(host="web 1", out=str(out), org=None, proxy=False, ingestion=False, sensor=False,
                proxy_binary=[], proxy_config=[], drop_proxy_binary=[], drop_proxy_config=[])
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.fixture
def run(db_session, monkeypatch):
    import app.core.database as database

    monkeypatch.setattr(database, "AsyncSessionLocal", lambda: _Session(db_session))
    mod = _module()

    async def go(args):
        return await mod.main(args)
    return go


async def test_keys_are_written_to_files_only(run, db_session, org_and_users, tmp_path, capsys):
    slug = org_and_users["org"].slug
    assert await run(_args(tmp_path, org=slug, proxy=True, ingestion=True, sensor=True)) == 0
    out = capsys.readouterr().out
    org_id = org_and_users["org"].id

    for name in ("proxy.key", "ingestion.key", "sensor.key"):
        f = tmp_path / name
        assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
        key = f.read_text().strip()
        assert key and key not in out          # never printed
    proxy_key = (tmp_path / "proxy.key").read_text().strip()
    assert proxy_key.startswith("pvz_proxy_")
    p = (await db_session.execute(select(EgressProxy).where(EgressProxy.org_id == org_id))).scalar_one()
    assert p.name == "web-1" and p.key_hash == hash_api_key(proxy_key) and p.enabled
    s = (await db_session.execute(select(IngestionSource).where(IngestionSource.org_id == org_id))).scalar_one()
    assert s.source_type == "endpoint" and s.api_key_hash == hash_api_key((tmp_path / "ingestion.key").read_text().strip())
    assert (tmp_path / "sensor.key").read_text().startswith("pvz_sensor_")
    logs = (await db_session.execute(select(AIAuditLog).where(AIAuditLog.org_id == org_id))).scalars().all()
    created = {(log.entity_type, log.action) for log in logs}
    assert {("egress_proxy", "created"), ("ingestion_source", "created"), ("egress_sensor", "created")} <= created


async def test_only_the_keys_asked_for(run, db_session, org_and_users, tmp_path):
    await run(_args(tmp_path, org=org_and_users["org"].slug, ingestion=True))
    assert sorted(os.listdir(tmp_path)) == ["ingestion.key"]


async def test_sensor_names_stay_unique(run, db_session, org_and_users, tmp_path):
    slug, org_id = org_and_users["org"].slug, org_and_users["org"].id
    await run(_args(tmp_path, org=slug, sensor=True))
    await run(_args(tmp_path, org=slug, sensor=True))
    names = sorted((await db_session.execute(select(EgressSensor.name).where(
        EgressSensor.org_id == org_id))).scalars())
    assert names == ["web-1", "web-1-2"]


async def test_release_hashes_go_to_the_working_copy(run, db_session, org_and_users, tmp_path):
    slug, org_id = org_and_users["org"].slug, org_and_users["org"].id
    await run(_args(tmp_path, org=slug, proxy_binary=[A], proxy_config=[B]))
    await run(_args(tmp_path, org=slug, proxy_binary=[A, B]))          # A again: kept once
    row = (await db_session.execute(select(PolicySigningSettings).where(
        PolicySigningSettings.org_id == org_id))).scalar_one()
    assert row.proxy_binaries == [A, B] and row.proxy_configs == [B]
    assert row.quorum == 1                                               # defaults for the rest
    # an upgraded binary replaces the one this host added before
    C = "c" * 64
    await run(_args(tmp_path, org=slug, proxy_binary=[C], drop_proxy_binary=[A]))
    await db_session.refresh(row)
    assert row.proxy_binaries == [B, C] and row.proxy_configs == [B]


async def test_bad_hash_and_unknown_org_are_refused(run, org_and_users, tmp_path):
    with pytest.raises(SystemExit):
        await run(_args(tmp_path, org=org_and_users["org"].slug, proxy_binary=["xyz"]))
    with pytest.raises(SystemExit):
        await run(_args(tmp_path, org="no-such-org", proxy=True))
    assert os.listdir(tmp_path) == []
