# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Rows made on first use, asked for by several at once (app/core/db_race.py).

These run real transactions side by side, each on its own connection - the
way two requests meet in production - and commit, so they clean up after
themselves. Everyone must get the same row, and nobody an error.
"""

import asyncio
import secrets

import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.db_race import insert_or_get
from app.models.agent import Agent
from app.models.ai_system import AISystem
from app.models.audit_log import AuditSigningKey
from app.models.behavior import AgentBaseline
from app.models.egress_sensor import EgressPolicyRevision, EgressPolicySettings, EgressSensorSigningKey
from app.models.organization import Organization
from tests.conftest import TEST_DATABASE_URL, auth_headers

N = 6


@pytest_asyncio.fixture
async def side_by_side():
    """(a session factory with a connection per session, the id of an organization that is really there)."""
    engine = create_async_engine(TEST_DATABASE_URL, pool_size=N + 2)
    make = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with make() as db:
        org = Organization(name="Race", slug=f"race-{secrets.token_hex(4)}")
        db.add(org)
        await db.commit()
        org_id = org.id
    try:
        yield make, org_id
    finally:
        async with make() as db:
            for model in (AgentBaseline, Agent, AISystem, EgressPolicySettings, EgressPolicyRevision,
                          EgressSensorSigningKey, AuditSigningKey):
                await db.execute(delete(model).where(model.org_id == org_id))
            await db.execute(delete(Organization).where(Organization.id == org_id))
            await db.commit()
        await engine.dispose()


async def _each(make, work):
    """`work(db)` in N transactions at once; each commits. Returns the results."""
    start = asyncio.Event()

    async def one():
        async with make() as db:
            await db.execute(select(1))      # the connection is open before the start
            await start.wait()
            out = await work(db)
            await db.commit()
            return out

    tasks = [asyncio.create_task(one()) for _ in range(N)]
    await asyncio.sleep(0.05)
    start.set()
    return await asyncio.gather(*tasks)


async def test_the_sensor_settings_of_a_new_organization(side_by_side):
    from app.services import egress_sensor as svc

    make, org_id = side_by_side
    ids = await _each(make, lambda db: _id(svc.settings_for(db, org_id)))
    assert len(set(ids)) == 1
    async with make() as db:
        assert await db.scalar(select(func.count()).select_from(EgressPolicySettings)
                               .where(EgressPolicySettings.org_id == org_id)) == 1


async def _id(coro):
    return (await coro).id


async def test_the_sensor_signing_key_is_made_once(side_by_side):
    from app.services import egress_sensor_commands as cmd

    make, org_id = side_by_side
    prints = await _each(make, lambda db: _fp(cmd.signing_key_for(db, org_id)))
    assert len(set(prints)) == 1, prints


async def _fp(coro):
    return (await coro).fingerprint


async def test_every_policy_change_gets_its_own_revision(side_by_side):
    """Two changes at once used to get the same number: a sensor that held the
    first would never fetch the second."""
    from app.services import egress_sensor as svc

    make, org_id = side_by_side
    first = await _each(make, lambda db: svc.bump_revision(db, org_id))
    again = await _each(make, lambda db: svc.bump_revision(db, org_id))
    assert sorted(first + again) == list(range(1, 2 * N + 1))


async def test_an_organization_gets_one_first_audit_key(side_by_side):
    """A first permit, manifest and checkpoint can ask at once; what one signs
    must verify under the key the others publish."""
    from app.services import audit_proofs

    make, org_id = side_by_side
    prints = await _each(make, lambda db: _fp(audit_proofs.current_key(db, org_id)))
    assert len(set(prints)) == 1, prints
    async with make() as db:
        assert await db.scalar(select(func.count()).select_from(AuditSigningKey)
                               .where(AuditSigningKey.org_id == org_id)) == 1


async def test_an_agents_baseline_under_calls_at_once(side_by_side):
    from app.services.behavior_monitor import BehaviorMonitor

    make, org_id = side_by_side
    async with make() as db:
        agent = Agent(org_id=org_id, name="racer", status="active", api_key_hash=secrets.token_hex(32),
                      allowed_tools=[])
        db.add(agent)
        await db.commit()
        agent_id = agent.id
    ids = await _each(make, lambda db: _id(BehaviorMonitor(db).baseline(org_id, agent_id)))
    assert len(set(ids)) == 1


async def test_inventory_discovery_from_two_requests(side_by_side):
    """The inventory page asks for the list and the summary at once."""
    from app.services.inventory_service import InventoryService

    make, org_id = side_by_side
    async with make() as db:
        for i in range(3):
            db.add(Agent(org_id=org_id, name=f"found-{i}", status="active", api_key_hash=secrets.token_hex(32),
                         allowed_tools=[]))
        await db.commit()
    created = await _each(make, lambda db: InventoryService(db).sync(org_id))
    # each system was created once, by one of them
    assert sorted(c["name"] for cs in created for c in cs) == ["found-0", "found-1", "found-2"]


async def test_two_syncs_of_one_mcp_server(side_by_side):
    """A second click on Sync, or an egress proxy reporting while an admin
    syncs: each tool and its registry entry are made once."""
    from app.models.mcp import MCPServer, MCPTool
    from app.models.tool_registry import ToolRegistryEntry
    from app.pvp.mcp_gateway import MCPGateway

    make, org_id = side_by_side
    async with make() as db:
        server = MCPServer(org_id=org_id, slug="wiki", name="Wiki", url="https://mcp.example.com/mcp")
        db.add(server)
        await db.commit()
        server_id = server.id
    tools = [{"name": f"tool_{i}", "description": "d", "inputSchema": {"type": "object"}} for i in range(4)]

    async def sync(db):
        return await MCPGateway(db).apply_sync(org_id, await db.get(MCPServer, server_id), tools, None)

    try:
        reports = await _each(make, sync)
        assert sorted(len(r["added"]) for r in reports) == [0] * (N - 1) + [4]
        async with make() as db:
            assert await db.scalar(select(func.count()).select_from(MCPTool).where(MCPTool.server_id == server_id)) == 4
            assert await db.scalar(select(func.count()).select_from(ToolRegistryEntry)
                                   .where(ToolRegistryEntry.org_id == org_id)) == 4
    finally:
        async with make() as db:
            await db.execute(delete(MCPTool).where(MCPTool.server_id == server_id))
            await db.execute(delete(MCPServer).where(MCPServer.id == server_id))
            await db.execute(delete(ToolRegistryEntry).where(ToolRegistryEntry.org_id == org_id))
            await db.commit()


async def test_losing_does_not_unload_what_the_request_holds(db_session, org_and_users):
    """The loser's transaction goes on: the rows it already read stay loaded
    (a rollback would unload them, and reading one would fail the request)."""
    org = org_and_users["org"]
    first, mine = await insert_or_get(
        db_session, AISystem(org_id=org.id, name="A", kind="other", domain="general", risk_flags=[],
                             review_status="unreviewed", source_key="k:1"), lambda: None)
    assert mine
    again, mine = await insert_or_get(
        db_session, AISystem(org_id=org.id, name="B", kind="other", domain="general", risk_flags=[],
                             review_status="unreviewed", source_key="k:1"),
        lambda: db_session.scalar(select(AISystem).where(AISystem.org_id == org.id, AISystem.source_key == "k:1")))
    assert not mine and again.id == first.id and again.name == "A"
    assert org.slug and org_and_users["admin"].email          # still loaded: no lazy load, no error
    # not the row raced for: the error is not swallowed
    with pytest.raises(IntegrityError):
        await insert_or_get(db_session, AISystem(org_id=org.id, name="C", kind="other", domain="general",
                                                 risk_flags=[], review_status="unreviewed", source_key="k:1"),
                            _nothing)


async def _nothing():
    return None


async def test_a_lost_race_elsewhere_is_a_conflict_not_a_fault(client, admin_token, monkeypatch):
    """A unique violation nobody caught (a second click on a first Save):
    409 "try again", not an unexplained 500. Any other integrity error stays a fault."""
    from app.services.inventory_service import InventoryService

    class Orig(Exception):
        sqlstate = "23505"

    async def clash(self, org_id):
        raise IntegrityError("insert", {}, Orig("duplicate key value violates unique constraint"))

    monkeypatch.setattr(InventoryService, "summary", clash)
    r = await client.get("/api/v1/inventory/summary", headers=auth_headers(admin_token))
    assert r.status_code == 409 and r.json()["detail"] == "conflict.try_again"

    Orig.sqlstate = "23503"          # a foreign key: a real fault
    with pytest.raises(IntegrityError):
        await client.get("/api/v1/inventory/summary", headers=auth_headers(admin_token))


@pytest.mark.parametrize("when", ["before the insert", "after it"])
async def test_a_commit_that_lands_inside_the_insert(db_session, org_and_users, when):
    """One session serving several requests in turn (the test suite itself, in
    tests that run a real proxy against this server): another request's commit
    lands inside our insert. Whatever was open went in with that commit;
    nothing is left to release, and nothing fails."""
    from unittest.mock import patch

    org = org_and_users["org"]
    row = AISystem(org_id=org.id, name="A", kind="other", domain="general", risk_flags=[],
                   review_status="unreviewed", source_key=f"k:{when}")
    if when == "after it":
        flush = db_session.flush

        async def flush_then_someone_commits(*a, **kw):
            await flush(*a, **kw)
            await db_session.commit()

        with patch.object(db_session, "flush", flush_then_someone_commits):
            row, mine = await insert_or_get(db_session, row, _nothing)
    else:
        begin_nested = db_session.begin_nested

        class Then:
            """begin_nested(), and by the time it is entered someone has committed."""
            def __init__(self):
                self.inner = begin_nested()

            def __await__(self):
                return self._go().__await__()

            async def _go(self):
                sp = await self.inner
                await db_session.commit()
                return sp

            async def __aenter__(self):
                sp = await self.inner.__aenter__()
                await db_session.commit()
                return sp

            async def __aexit__(self, *exc):
                return await self.inner.__aexit__(*exc)

        with patch.object(db_session, "begin_nested", Then):
            row, mine = await insert_or_get(db_session, row, _nothing)
    assert mine and row.id
    assert await db_session.scalar(select(func.count()).select_from(AISystem)
                                   .where(AISystem.source_key == f"k:{when}")) == 1
