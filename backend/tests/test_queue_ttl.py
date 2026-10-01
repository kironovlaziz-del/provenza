"""
Request pipeline time limits: tasks are queued with Celery `expires`, the
worker claims a request once (no double provider call on redelivery) and
refuses a stale one, the sweep expires stuck / unanswered requests and wipes
raw prompts past retention; admin API.
"""

import secrets
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.core.crypto import encrypt_secret
from app.models.agent import Agent
from app.models.ai_request import AIRequest
from app.services import queue_ttl
from tests.conftest import auth_headers

Q = "/api/v1/queue"


async def _org(client, token, db):
    r = await client.post("/api/v1/agents/register",
                          json={"name": "q-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": [],
                                "allowed_tools": [], "allowed_models": [], "max_delegation_depth": 1},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return (await db.get(Agent, r.json()["id"])).org_id


async def _settings(client, token, ttl=900, approval_h=72, retention=None):
    r = await client.put(Q + "/settings", json={"queue_ttl_seconds": ttl, "approval_ttl_hours": approval_h,
                                               "raw_prompt_retention_days": retention}, headers=auth_headers(token))
    assert r.status_code == 200, r.text


async def _req(db, org_id, status="pending", age=timedelta(0), enqueued_age=None, raw="secret prompt", retention_in=None):
    now = datetime.now(timezone.utc)
    r = AIRequest(org_id=org_id, status=status, masked_input_text="x", purpose="test",
                  input_text_encrypted=encrypt_secret(raw) if raw else None,
                  created_at=now - age,
                  enqueued_at=(now - enqueued_age) if enqueued_age is not None else None,
                  retention_expires_at=(now + retention_in) if retention_in is not None else None)
    db.add(r)
    await db.commit()
    await db.refresh(r)
    return r.id


async def _status(db, rid):
    db.expire_all()
    return (await db.execute(select(AIRequest.status, AIRequest.input_text_encrypted).where(AIRequest.id == rid))).one()


class TestEnqueueAndClaim:
    @pytest.mark.asyncio
    async def test_enqueue_passes_expires_and_stamps(self, client, admin_token, db_session, monkeypatch):
        from app.core.celery_app import celery_app
        sent = []
        monkeypatch.setattr(celery_app, "send_task", lambda name, args=None, **kw: sent.append((name, args, kw)))
        org = await _org(client, admin_token, db_session)
        await _settings(client, admin_token, ttl=120)
        rid = await _req(db_session, org)
        req = await db_session.get(AIRequest, rid)
        await queue_ttl.enqueue_request(db_session, req, org)
        assert sent == [("request.process", [rid, org], {"expires": 120})]
        db_session.expire_all()
        assert (await db_session.get(AIRequest, rid)).enqueued_at is not None
        await _settings(client, admin_token)

    @pytest.mark.asyncio
    async def test_claim_once_then_redelivery_is_a_noop(self, client, admin_token, db_session):
        org = await _org(client, admin_token, db_session)
        rid = await _req(db_session, org, enqueued_age=timedelta(seconds=5))
        assert await queue_ttl.claim_for_processing(db_session, rid, org) is True
        assert (await _status(db_session, rid))[0] == "processing"
        assert await queue_ttl.claim_for_processing(db_session, rid, org) is False   # redelivered task

    @pytest.mark.asyncio
    async def test_stale_task_does_not_run(self, client, admin_token, db_session):
        org = await _org(client, admin_token, db_session)
        await _settings(client, admin_token, ttl=60)
        rid = await _req(db_session, org, status="approved", enqueued_age=timedelta(minutes=10))
        assert await queue_ttl.claim_for_processing(db_session, rid, org) is False
        assert (await _status(db_session, rid))[0] == "expired"
        await _settings(client, admin_token)

    @pytest.mark.asyncio
    async def test_claim_ignores_other_org_and_finished(self, client, admin_token, db_session):
        org = await _org(client, admin_token, db_session)
        rid = await _req(db_session, org, status="completed")
        assert await queue_ttl.claim_for_processing(db_session, rid, org) is False
        assert await queue_ttl.claim_for_processing(db_session, rid, org + 999999) is False


class TestSweep:
    @pytest.mark.asyncio
    async def test_sweep_expires_and_purges(self, client, admin_token, db_session):
        org = await _org(client, admin_token, db_session)
        await _settings(client, admin_token, ttl=300, approval_h=24)
        stale = await _req(db_session, org, enqueued_age=timedelta(minutes=30))
        fresh = await _req(db_session, org, enqueued_age=timedelta(seconds=10))
        old_approval = await _req(db_session, org, status="pending_approval", age=timedelta(hours=30))
        new_approval = await _req(db_session, org, status="pending_approval", age=timedelta(hours=1))
        lost = await _req(db_session, org, status="processing", enqueued_age=timedelta(hours=3))
        working = await _req(db_session, org, status="processing", enqueued_age=timedelta(minutes=2))
        purge = await _req(db_session, org, status="completed", retention_in=timedelta(days=-1))
        keep = await _req(db_session, org, status="completed", retention_in=timedelta(days=5))

        counts = await queue_ttl.sweep_org(db_session, org)
        assert counts["expired_queued"] >= 1 and counts["expired_approvals"] >= 1
        assert counts["failed_stuck"] >= 1 and counts["purged_prompts"] >= 1
        assert (await _status(db_session, stale))[0] == "expired"
        assert (await _status(db_session, fresh))[0] == "pending"
        assert (await _status(db_session, old_approval))[0] == "expired"
        assert (await _status(db_session, new_approval))[0] == "pending_approval"
        assert (await _status(db_session, lost))[0] == "failed"
        assert (await _status(db_session, working))[0] == "processing"
        assert (await _status(db_session, purge))[1] is None
        assert (await _status(db_session, keep))[1] is not None
        await _settings(client, admin_token)

    @pytest.mark.asyncio
    async def test_org_retention_period(self, client, admin_token, db_session):
        org = await _org(client, admin_token, db_session)
        await _settings(client, admin_token, retention=7)
        old = await _req(db_session, org, status="completed", age=timedelta(days=10))
        recent = await _req(db_session, org, status="completed", age=timedelta(days=2))
        r = await client.post(Q + "/sweep", headers=auth_headers(admin_token))
        assert r.status_code == 200 and r.json()["purged_prompts"] >= 1
        assert (await _status(db_session, old))[1] is None
        assert (await _status(db_session, recent))[1] is not None
        ov = (await client.get(Q + "/", headers=auth_headers(admin_token))).json()
        assert ov["sweeps"][0]["trigger"] == "manual" and ov["settings"]["raw_prompt_retention_days"] == 7
        await _settings(client, admin_token)

    @pytest.mark.asyncio
    async def test_sweep_all_task_body(self, client, admin_token, db_session):
        org = await _org(client, admin_token, db_session)
        await _settings(client, admin_token, ttl=60)
        stale = await _req(db_session, org, enqueued_age=timedelta(minutes=5))
        result = await queue_ttl.sweep_all(db_session)
        assert org in result and (await _status(db_session, stale))[0] == "expired"
        await _settings(client, admin_token)


class TestApi:
    @pytest.mark.asyncio
    async def test_overview_validation_roles(self, client, admin_token, approver_token, db_session):
        org = await _org(client, admin_token, db_session)
        await _req(db_session, org, status="pending_approval", age=timedelta(minutes=5))
        ov = await client.get(Q + "/", headers=auth_headers(approver_token))
        assert ov.status_code == 200 and ov.json()["live"]["pending_approval"]["count"] >= 1
        for bad in ({"queue_ttl_seconds": 10, "approval_ttl_hours": 72}, {"queue_ttl_seconds": 900, "approval_ttl_hours": 0},
                    {"queue_ttl_seconds": 900, "approval_ttl_hours": 72, "raw_prompt_retention_days": 0}):
            assert (await client.put(Q + "/settings", json=bad, headers=auth_headers(admin_token))).status_code == 422
        ok = {"queue_ttl_seconds": 900, "approval_ttl_hours": 72, "raw_prompt_retention_days": None}
        assert (await client.put(Q + "/settings", json=ok, headers=auth_headers(approver_token))).status_code == 403
        assert (await client.post(Q + "/sweep", headers=auth_headers(approver_token))).status_code == 403
