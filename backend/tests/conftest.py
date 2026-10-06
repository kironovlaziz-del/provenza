"""
Shared pytest fixtures.

Tests run against a dedicated `ai_control_tower_test` database.

The schema is created once per session by a **synchronous** fixture that
uses its own short-lived event loop via asyncio.run(). This avoids the
pytest-asyncio scope mismatch that occurs when a session-scoped async
fixture is combined with function-scoped test loops.
"""

import asyncio
import os
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

# Override the database name before importing the app so config picks it up.
os.environ["POSTGRES_DB"] = "ai_control_tower_test"
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("SECRET_KEY", "test-secret-key-do-not-use-in-production-1234567890")
os.environ.setdefault("ENCRYPTION_KEY", "")
os.environ.setdefault("REDIS_PASSWORD", "")
# Several tests create extra organizations through the sign-up endpoint;
# tests/test_signup.py covers the default (disabled) behaviour.
os.environ.setdefault("ALLOW_PUBLIC_SIGNUP", "true")

from app.core.config import settings  # noqa: E402
from app.core.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Organization, User, UserRole  # noqa: E402
from app.core import security as _security  # noqa: E402

# bcrypt at its production cost (12 rounds, ~0.25 s a hash) dominated fixture
# setup: org_and_users hashes two passwords and every token is a real login.
# Tests check behaviour, not hashing cost, so they use the minimum, 4 rounds.
# A hash carries its own cost, so verification works exactly as in production.
_security.pwd_context.update(bcrypt__rounds=4)


TEST_DATABASE_URL = (
    f"postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
    f"@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/ai_control_tower_test"
)


# ---------------------------------------------------------------------------
# Schema setup
# ---------------------------------------------------------------------------


async def _recreate_schema() -> None:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
    finally:
        await engine.dispose()


@pytest.fixture(scope="session", autouse=True)
def _prepare_schema():
    """
    Synchronous session fixture: creates the test schema once, before any
    test runs, using its own event loop. This deliberately does not use
    pytest_asyncio so there is no scope clash with the function-scoped
    test loop.
    """
    asyncio.run(_recreate_schema())
    yield


# ---------------------------------------------------------------------------
# Per-test fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Function-scoped session bound to an outer transaction that is rolled
    back after the test. The API uses the same session thanks to the
    get_db override below.
    """
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    connection = await engine.connect()
    transaction = await connection.begin()
    session_maker = async_sessionmaker(bind=connection, expire_on_commit=False)
    session = session_maker()

    try:
        yield session
    finally:
        await session.close()
        await transaction.rollback()
        await connection.close()
        await engine.dispose()


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """
    httpx client pointing at the FastAPI app. The get_db dependency is
    overridden so the API uses the same transactional session as the test.
    """

    async def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://test", follow_redirects=True
    ) as ac:
        yield ac

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Celery isolation
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def mock_celery_send_task(monkeypatch):
    """
    Prevent any test from actually dispatching work to Redis.

    Several API endpoints (request creation, approval decisions) call
    `celery_app.send_task(...)`. Without a running worker and a
    reachable Redis, that raises during the request and masks the behaviour
    under test.
    """
    from app.core.celery_app import celery_app

    class _FakeResult:
        id = "test-task-id"

    def _fake_send_task(*args, **kwargs):
        return _FakeResult()

    monkeypatch.setattr(celery_app, "send_task", _fake_send_task)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_org_with_admin_and_approver(
    db: AsyncSession,
    *,
    org_slug: str = "test-org",
    admin_email: str = "admin@test.example.com",
    approver_email: str = "approver@test.example.com",
    password: str = "TestPass123!",
    relaxed_identity: bool = True,
) -> dict:
    from app.core.security import get_password_hash

    org = Organization(name="Test Org", slug=org_slug)
    db.add(org)
    await db.flush()

    admin = User(
        org_id=org.id,
        email=admin_email,
        name="Admin",
        hashed_password=get_password_hash(password),
        role=UserRole.admin.value,
        status="active",
    )
    approver = User(
        org_id=org.id,
        email=approver_email,
        name="Approver",
        hashed_password=get_password_hash(password),
        role=UserRole.approver.value,
        status="active",
    )
    db.add_all([admin, approver])
    if relaxed_identity:
        # Production defaults are strict (agents act only with their own key,
        # keyless agents cannot act, A2A enforced). Most tests predate that and
        # drive agents through a user session, so this fixture organization
        # keeps the old relaxed settings explicitly; tests/test_strict_identity.py
        # covers the strict defaults with relaxed_identity=False.
        from app.models.a2a import A2ASettings
        from app.models.agent_identity import AgentIdentitySettings

        db.add(AgentIdentitySettings(org_id=org.id, require_agent_key=False, allow_keyless_agents=True,
                                     allow_direct_registration=True, rotation_grace_minutes=60,
                                     require_pq_signatures=False))
        db.add(A2ASettings(org_id=org.id, mode="monitor"))
    await db.flush()
    return {
        "org": org,
        "admin": admin,
        "approver": approver,
        "password": password,
    }


@pytest_asyncio.fixture
async def org_and_users(db_session: AsyncSession) -> dict:
    return await _create_org_with_admin_and_approver(db_session)


async def _login(client: AsyncClient, org_slug: str, email: str, password: str) -> str:
    resp = await client.post(
        "/api/v1/auth/login",
        json={"org_slug": org_slug, "email": email, "password": password},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest_asyncio.fixture
async def admin_token(client: AsyncClient, org_and_users: dict) -> str:
    return await _login(
        client,
        org_and_users["org"].slug,
        org_and_users["admin"].email,
        org_and_users["password"],
    )


@pytest_asyncio.fixture
async def approver_token(client: AsyncClient, org_and_users: dict) -> str:
    return await _login(
        client,
        org_and_users["org"].slug,
        org_and_users["approver"].email,
        org_and_users["password"],
    )


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Rate limiter isolation.
# app/core/rate_limit.py talks to the Redis from .env - on a server that is
# the PRODUCTION Redis. Without this, test logins (a) accumulate counters
# across runs and hit 429, and (b) write rl:* keys into prod Redis.
# Each test gets its own in-memory store; the limiter logic itself still runs.
# ---------------------------------------------------------------------------
class _FakePipeline:
    def __init__(self, store):
        self._store, self._ops = store, []

    def incr(self, key):
        self._ops.append(("incr", key))
        return self

    def expire(self, key, seconds, nx=False):
        self._ops.append(("expire", key))
        return self

    def execute(self):
        out = []
        for op, key in self._ops:
            if op == "incr":
                self._store[key] = self._store.get(key, 0) + 1
                out.append(self._store[key])
            else:
                out.append(True)
        self._ops = []
        return out


class _FakeRedis:
    def __init__(self, store):
        self._store = store

    def pipeline(self):
        return _FakePipeline(self._store)

    def delete(self, *keys):
        for k in keys:
            self._store.pop(k, None)

    def decr(self, key):
        self._store[key] = self._store.get(key, 0) - 1
        return self._store[key]

    def close(self):
        pass


@pytest.fixture(autouse=True)
def _isolated_rate_limit(monkeypatch):
    from app.core import rate_limit
    store: dict = {}
    monkeypatch.setattr(rate_limit, "_get_redis", lambda: _FakeRedis(store))
    yield store
