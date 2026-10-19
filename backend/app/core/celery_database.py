"""
A SEPARATE async engine/sessionmaker for use inside Celery tasks only.

Celery's prefork worker processes call asyncio.run() once per task
invocation (see workers/telemetry_tasks.py, workers/retention_tasks.py),
and each call creates and tears down its own event loop. The main
`engine`/AsyncSessionLocal in database.py is a single long-lived object
shared across the whole FastAPI process, which works fine there because
uvicorn runs everything on ONE event loop for the process's entire
lifetime - but reusing that same pooled engine across many short-lived
asyncio.run() loops breaks: asyncpg connections are bound to the loop
that created them, and the default connection pool will happily hand
out a pooled connection that was established under a now-closed loop,
raising "got Future ... attached to a different loop" the moment a
second task tries to use it.

NullPool sidesteps this entirely: every checkout opens a brand new
asyncpg connection and every checkin closes it, so nothing ever survives
past the asyncio.run() call that created it. This is the pattern
SQLAlchemy's own docs recommend for exactly this situation (short-lived
event loops - the same issue shows up running async SQLAlchemy in AWS
Lambda or other serverless functions).
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool

from app.core.database import DATABASE_URL

celery_engine = create_async_engine(
    DATABASE_URL,
    poolclass=NullPool,
    future=True,
)

CelerySessionLocal = async_sessionmaker(
    celery_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)
