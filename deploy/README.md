# Self-hosting Provenza (production)

A single `docker compose` stack: PostgreSQL 16, Redis 7, database migrations,
the API, a Celery worker and scheduler, the web UI, and Caddy as the HTTPS
reverse proxy.

```
            Internet
               │ 80 / 443
          ┌────▼────┐   web network
          │  Caddy  │──────────────┬──────────────┐
          └─────────┘              │              │
                             ┌─────▼────┐   ┌─────▼────┐
                             │ backend  │   │ frontend │
                             └─────┬────┘   └──────────┘
          data network (internal, no host access)
      ┌──────────┬───────┴──┬──────────┬──────────┐
 ┌────▼───┐ ┌────▼──┐ ┌─────▼──┐ ┌─────▼──┐ ┌─────▼───┐
 │postgres│ │ redis │ │ worker │ │  beat  │ │ migrate │
 └────────┘ └───────┘ └────────┘ └────────┘ └─────────┘
```

## Requirements

- Linux host with Docker Engine 24+ and the Compose plugin v2
- 2 vCPU / 4 GB RAM minimum (4 GB+ recommended with NER-based PII detection)
- A DNS record for your domain pointing at the host, ports 80 and 443 open

## Install

```bash
git clone https://github.com/kironovlaziz-del/provenza.git /opt/provenza
cd /opt/provenza/deploy
./scripts/init-env.sh provenza.example.com      # writes .env with generated secrets
docker compose up -d --build                 # first build takes a few minutes
docker compose run --rm -it backend create-admin --org "Provenza" --email admin@provenza.example.com --name "Jane Admin"
```

Open `https://provenza.example.com` and sign in. For a trial on your own machine
use `localhost` as the domain (the browser will warn about Caddy's local
certificate).

**Back up `deploy/.env` now.** `ENCRYPTION_KEY` protects provider API keys,
stored prompts and connection secrets; without it, a database backup cannot
be read.

## What the stack enforces

- No demo data and no default credentials: the backend refuses to start if
  `SECRET_KEY`, `ENCRYPTION_KEY`, `POSTGRES_PASSWORD` or `REDIS_PASSWORD` is
  missing or a well-known default.
- Only Caddy publishes ports. PostgreSQL and Redis sit on an internal network.
- Containers run as non-root users with a read-only root filesystem, no Linux
  capabilities and `no-new-privileges`.
- Migrations run in their own one-shot container; the API, worker and
  scheduler start only after they succeed.
- Health checks on every service, memory limits, log rotation (5 × 20 MB).
- Redis keeps queued tasks on disk (AOF) and never evicts them.
- Caddy: automatic TLS, HTTP/2 and HTTP/3, HSTS and security headers,
  unbuffered proxying for live streams (agent observability, training).

## Operate

| Task | Command |
|---|---|
| Status | `docker compose ps` |
| Logs | `docker compose logs -f backend worker` |
| Upgrade | `git pull && docker compose up -d --build` (migrations run first) |
| Stop / start | `docker compose stop` / `docker compose up -d` |
| Another admin | `docker compose run --rm -it backend create-admin --org "Provenza" --email ...` |
| Shell in the API | `docker compose exec backend sh` |

Do not paste the output of `docker compose config` anywhere: it contains the
secrets from `.env`.

### Backups

```bash
./scripts/backup.sh                     # database (pg_dump) + uploaded files
```

Schedule it with cron, for example daily at 03:15:

```
15 3 * * * cd /opt/provenza/deploy && ./scripts/backup.sh >> backups/backup.log 2>&1
```

Backups older than `BACKUP_KEEP_DAYS` (14) are removed. Copy `backups/` off
the host as well.

### Restore

```bash
./scripts/restore.sh backups/provenza-20261001-031500.dump
```

This replaces all current data, after asking for confirmation. `.env` must
contain the `ENCRYPTION_KEY` that was in use when the backup was made.

### Rotating the encryption key

Put the new key in `ENCRYPTION_KEY_NEW`, then:

```bash
docker compose run --rm backend python scripts/rotate_encryption_key.py --dry-run
docker compose run --rm backend python scripts/rotate_encryption_key.py
```

Move the new value into `ENCRYPTION_KEY`, clear `ENCRYPTION_KEY_NEW` and run
`docker compose up -d`.

## Configuration

Every setting is described in [`.env.example`](.env.example). The most common:

| Variable | Default | Purpose |
|---|---|---|
| `PROVENZA_DOMAIN` | — | Public domain; TLS is issued for it |
| `API_WORKERS` | 2 | Uvicorn worker processes |
| `CELERY_CONCURRENCY` | 2 | Parallel background tasks |
| `PROMPT_FIREWALL_NER_ENABLED` | true | NER-based PII detection |
| `SMTP_*` | empty | E-mail notifications |
| `*_MEMORY` | see file | Container memory limits |

## Notes

- Model training (MLOps) runs inside the worker. Heavy training needs more
  memory (`WORKER_MEMORY`); the optional ML extras in
  `backend/requirements-ml.txt` are not part of the image.
- `docker-compose.dev.yml` in the repository root is a development/demo stack
  that seeds a demo admin. Never use it in production.
