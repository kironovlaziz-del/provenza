# Development

Running Provenza from source, for working on it. To run it on a server,
use the installer instead: see [self-hosting](self-hosting.md).

## Try it in two minutes (Docker)

The whole stack (database, backend with automatic migrations, worker and
frontend) in one command:

```bash
git clone https://github.com/kironovlaziz-del/provenza.git
cd provenza
docker compose -f docker-compose.dev.yml up --build
```

Open **http://localhost:3000** and sign in:

| Organization | Email | Password |
|---|---|---|
| `demo` | `admin@demo.com` | `demo12345` |

## Local setup (hot reload)

Requirements: Python 3.12, Node.js 20.9+, Docker with Compose v2. Go 1.26+
only to build the endpoint agent or the egress sensor (the sensor's BPF
object also needs clang 14+ and Linux 5.15+ with cgroup v2 and BTF to run).

### 1. Environment files

```bash
git clone git@github.com:kironovlaziz-del/provenza.git
cd provenza
cp .env.example .env                  # read by docker compose
cp backend/.env.example backend/.env  # read by FastAPI and Celery
```

`.env` (root):

```env
POSTGRES_USER=ai_user
POSTGRES_PASSWORD=change_me_in_dot_env
POSTGRES_DB=ai_control_tower
REDIS_PASSWORD=change_me_in_dot_env
```

`backend/.env` needs two keys. Generate them:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"                                 # SECRET_KEY
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # ENCRYPTION_KEY
```

```env
SECRET_KEY=<the first output>
ENCRYPTION_KEY=<the second output>
POSTGRES_USER=ai_user
POSTGRES_PASSWORD=change_me_in_dot_env
POSTGRES_DB=ai_control_tower
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=change_me_in_dot_env
```

### 2. Postgres and Redis

```bash
docker compose up -d
```

Both bind to `127.0.0.1` only.

### 3. Backend

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

API: http://localhost:8000. Interactive API docs: http://localhost:8000/docs
(switched off when `ENVIRONMENT=production`).

### 4. Celery (two more terminals)

```bash
cd backend && source .venv/bin/activate
celery -A app.core.celery_app worker --loglevel=info --concurrency=1
```

```bash
cd backend && source .venv/bin/activate
celery -A app.core.celery_app beat --loglevel=info
```

### 5. Frontend

```bash
cd frontend
npm install
npm run dev
```

UI: http://localhost:3000. Create the first organization and its admin
(the password is asked for, 12 characters or more):

```bash
cd backend && source .venv/bin/activate
PYTHONPATH=. python scripts/create_admin.py --org "Dev" --email admin@dev.example.com --name "Dev Admin"
```

or set `ALLOW_PUBLIC_SIGNUP=true` and use `/register`.

### 6. Endpoint agent (optional)

See [Shadow AI collectors](shadow-ai.md#endpoint-agent).

## Tests

```bash
cd backend && source .venv/bin/activate
pytest                        # everything; uses the ai_control_tower_test database
pytest tests/test_auth.py     # one file
pytest -k login               # by name
```

```bash
cd frontend
npx tsc --noEmit              # type check
npm run build                 # production build
```

CI also runs the SDK tests (`sdk/python`, `sdk/js`, `sdk/go`), the egress
proxy and sensor tests, a dependency audit and CodeQL.

## Repository layout

```
backend/     FastAPI + SQLAlchemy 2 (async) + Alembic + Celery
  app/api/        routers, one per feature area
  app/services/   business logic (agent policy engine, policy hierarchy, gateway, ...)
  app/models/     SQLAlchemy models
  app/schemas/    Pydantic v2 schemas
  app/workers/    Celery tasks
  app/core/       config, database, security, crypto
  alembic/        database migrations
frontend/    Next.js 16 (App Router) + TypeScript, i18n en/uz
agent/       Go endpoint agent and network discovery
extension/   Chrome extension (Manifest V3)
sensor/      eBPF egress sensor: a daemon that contains governed workloads per cgroup (Go)
proxy/       egress proxy for agents (Go)
sdk/         Python, JavaScript and Go SDKs
tools/       offline verifiers (provenza_sign.py, provenza_audit.py)
deploy/      production Docker stack (Caddy, non-root containers)
docs/        documentation
```

## Tech stack

| Layer | Technology |
|-------|-----------|
| API | FastAPI, Pydantic v2, SQLAlchemy 2 (async), asyncpg |
| Migrations | Alembic |
| Tasks | Celery 5 + Redis 7 |
| Database | PostgreSQL 16 |
| Auth | JWT (PyJWT), bcrypt, OpenID Connect, SCIM 2.0 |
| Encryption | Fernet (provider keys, directory passwords), Ed25519 + ML-DSA-65 (signatures) |
| Frontend | Next.js 16, React 19, TypeScript, i18next (en/uz) |
| Endpoint agent | Go, `golang.org/x/net` |
| Egress proxy | Go, standard library only |
| Egress sensor | Go + eBPF (`cilium/ebpf`); the BPF object is built with clang ≥ 14 and embedded in the binary |
| Extension | Chrome Manifest V3 (vanilla JS) |

## Configuration

`backend/.env` (FastAPI and Celery):

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | JWT signing key. **Required.** |
| `ENCRYPTION_KEY` | Fernet key for provider keys and stored prompts. **Required.** |
| `ENCRYPTION_KEY_NEW` | a second Fernet key, for key rotation |
| `POSTGRES_*` | host, port, user, password, database |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASSWORD` | Celery broker and backend |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | session token lifetime, default 30 |
| `ENVIRONMENT` / `DEBUG` | `production` turns off `/docs` and refuses default secrets |
| `CORS_ORIGINS` | comma-separated origins allowed to call the API |
| `PUBLIC_BASE_URL` | the public address, when a reverse proxy does not pass the original host (single sign-on redirects) |
| `ALLOW_PUBLIC_SIGNUP` | default `false`. When `true`, anyone who can reach the site can create an organization and become its admin |
| `TRUSTED_PROXIES` | peers whose forwarding headers are trusted, default `127.0.0.1,::1` |
| `OUTBOUND_PRIVATE_ALLOWLIST` | internal hosts that provider, Vault, webhook, identity-provider and TSA calls may reach (host names, IPs, CIDRs). Other private and loopback targets are refused; cloud metadata (link-local) always is |
| `OUTBOUND_PROXY` | proxy for those calls, when the network requires one (`HTTP(S)_PROXY` is ignored for them) |
| `SMTP_*` | e-mail notifications; without `SMTP_HOST`, e-mail is skipped and webhooks still work |
| `EXTENSION_TEMPLATE_DIR` | the `extension/` template that the download endpoint packages |

The production stack reads its own settings, written by the installer: see
[deploy/README.md](../deploy/README.md).

`frontend/.env.local`:

| Variable | Description |
|----------|-------------|
| `NEXT_PUBLIC_API_URL` | the API base, e.g. `http://localhost:8000/api/v1` |

## Common operations

Apply migrations:

```bash
cd backend && source .venv/bin/activate && alembic upgrade head
```

Reset the local database (**deletes all local data**):

```bash
docker compose down -v && docker compose up -d
cd backend && alembic upgrade head
```

Change the local Postgres password: change it in both `.env` files, then:

```bash
docker exec -it ai_ct_db psql -U ai_user -d ai_control_tower \
  -c "ALTER USER ai_user WITH PASSWORD 'new_password';"
```

and restart the backend and Celery.

## API

Every endpoint is under `/api/v1`, grouped by feature (`/policy-layers`,
`/gateway`, `/agents`, `/shadow-ai`, `/audit-logs`, ...). The
full, current list is the interactive documentation at `/docs` while the
backend runs in development.
