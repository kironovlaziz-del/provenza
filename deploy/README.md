# Self-hosting Provenza (production)

The stack runs as **rootful Podman containers managed by systemd** through
Quadlet: PostgreSQL 16, Redis 7, database migrations, the API, a Celery worker
and scheduler, the web UI, Caddy as the HTTPS reverse proxy, and Prometheus,
Grafana and Alertmanager on the loopback interface.

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

| Path | What it is |
|---|---|
| `quadlet/` | Templates of the Quadlet units: 11 `.container`, 9 `.volume`, 3 `.network` |
| `systemd/` | `provenza.target` (the whole stack), the daily backup timer, and `provenza-forward.service`, which keeps 80/443 reachable when Docker sets the FORWARD policy to DROP (`scripts/forward.sh`) |
| `scripts/units.sh` | Renders the templates with the values from `.env` into `/etc/containers/systemd` |
| `scripts/lib.sh` | Helpers shared by the scripts |
| `scripts/run.sh` | One-off backend commands (`create-admin`, key rotation, `alembic`) |
| `scripts/backup.sh`, `restore.sh` | Backups |
| `scripts/migrate-from-docker.sh` | Moves an existing Docker compose installation to Podman |

Each container is a systemd service named after it: `provenza-postgres`,
`provenza-backend`, `provenza-caddy`, and so on. They are all part of
`provenza.target`.

## Requirements

- Linux with systemd and **Podman 4.4+** (Quadlet) with `netavark` and
  `aardvark-dns`: Ubuntu 24.04+, Debian 13+, RHEL/Rocky/Alma 9.3+, Fedora.
  The installer installs them from the distribution's packages.
  Ubuntu 22.04 and Debian 12 ship an older Podman without Quadlet.
- 2 vCPU / 4 GB RAM minimum (4 GB+ recommended with NER-based PII detection)
- A DNS record for your domain pointing at the host, ports 80 and 443 open

## Install

The recommended way is the installer at the repository root: it does the steps
below, checks the host, waits for the stack and schedules backups. See
[docs/self-hosting.md](../docs/self-hosting.md).

```bash
git clone https://github.com/kironovlaziz-del/provenza.git /opt/provenza
cd /opt/provenza && sudo ./install.sh
```

By hand, as root, the same in a few commands:

```bash
apt install podman netavark aardvark-dns git openssl
git clone https://github.com/kironovlaziz-del/provenza.git /opt/provenza
cd /opt/provenza/deploy
./scripts/init-env.sh provenza.example.com            # writes .env with generated secrets
podman build -t localhost/provenza/backend:local -f backend.Dockerfile ..
podman build -t localhost/provenza/web:local -f frontend.Dockerfile ..
./scripts/units.sh install                            # units into /etc/containers/systemd
systemctl start provenza.target
./scripts/run.sh create-admin --org "Provenza" --email admin@provenza.example.com --name "Jane Admin"
systemctl enable --now provenza-backup.timer
```

Open `https://provenza.example.com` and sign in. For a trial on your own machine
use `localhost` as the domain (the browser will warn about Caddy's local
certificate).

**Back up `deploy/.env` now.** `ENCRYPTION_KEY` protects provider API keys,
stored prompts and connection secrets; without it, a database backup cannot
be read.

## Moving from Docker compose

Installations made before the switch to Podman run on Docker compose. Move
one, data included, with:

```bash
cd /opt/provenza && git pull
sudo ./deploy/scripts/migrate-from-docker.sh
```

It builds the images and installs the units while Docker keeps serving, stops
the application, takes a `pg_dump`, stops the Docker containers (restart
disabled, nothing deleted), copies every Docker volume into the Podman volume
of the same name, and starts the stack under systemd. If the new stack does not
become healthy, it goes back to Docker by itself. The Docker volumes are never
modified; the script prints the commands to delete them once you are sure.

## What the stack enforces

- No demo data and no default credentials: the backend refuses to start if
  `SECRET_KEY`, `ENCRYPTION_KEY`, `POSTGRES_PASSWORD` or `REDIS_PASSWORD` is
  missing or a well-known default, or if `SECRET_KEY` looks like a placeholder.
- No self-service sign-up: organizations and their first admin are created
  with `create-admin`; set `ALLOW_PUBLIC_SIGNUP=true` only for a public demo.
- Outbound calls to admin-supplied URLs (AI providers, Vault, webhooks) cannot
  reach private or internal addresses unless they are listed in
  `OUTBOUND_PRIVATE_ALLOWLIST`; redirects are not followed.
- Only Caddy publishes ports to the internet; Prometheus, Grafana and
  Alertmanager listen on `127.0.0.1`. PostgreSQL and Redis sit on an internal
  network.
- The application containers run as non-root users with a read-only root
  filesystem, no Linux capabilities and `no-new-privileges`. Caddy keeps only
  `NET_BIND_SERVICE` to bind 80/443.
- PostgreSQL, Redis and Grafana get only their own password
  (`deploy/.runtime/*.env`, mode 600), not the whole `.env`. The rendered units
  in `/etc/containers/systemd` contain no secrets.
- Migrations run in their own one-shot service; the API, worker and scheduler
  start only after it succeeds.
- Health checks, memory limits, logs in the systemd journal.
- Redis keeps queued tasks on disk (AOF) and never evicts them.
- Caddy: automatic TLS, HTTP/2 and HTTP/3, HSTS and security headers,
  unbuffered proxying for live streams (agent observability), and no API keys
  in the access log.

## Operate

`units.sh install` puts the `provenza` command in `/usr/local/bin` (it asks
for `sudo` by itself):

| Task | Command |
|---|---|
| Status: services, containers, health checks, next backup | `provenza status` |
| Logs of one service / all, follow | `provenza logs backend` · `provenza logs` · `provenza logs caddy -f -n 200` |
| Start / stop / restart everything | `provenza start` · `provenza stop` · `provenza restart` |
| Restart one service | `provenza restart worker` |
| Upgrade | `provenza upgrade` — new code: rebuild, backup, restart, rollback on failure (`upgrade.sh`); no new code: pull fresh PostgreSQL, Redis, Caddy and monitoring images and restart what changed |
| Backup now | `provenza backup` |
| Another admin | `provenza run create-admin --org "Provenza" --email ...` |
| After editing `.env` | `provenza units && provenza restart` |
| Shell in the API | `sudo podman exec -it backend sh` |

Services: `postgres redis migrate backend worker beat frontend caddy
prometheus grafana alertmanager`; each is the systemd unit
`provenza-<service>.service`, so `systemctl` and `journalctl -u` work as well.

Do not paste the output of `podman inspect` or `cat .runtime/*` anywhere: they
contain the secrets from `.env`.

### Backups

```bash
./scripts/backup.sh                     # database (pg_dump) + uploaded files
```

The installer schedules it daily at 03:15 with `provenza-backup.timer`:

```bash
systemctl enable --now provenza-backup.timer
systemctl list-timers provenza-backup.timer
journalctl -u provenza-backup
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
./scripts/run.sh python scripts/rotate_encryption_key.py --dry-run
./scripts/run.sh python scripts/rotate_encryption_key.py
```

Move the new value into `ENCRYPTION_KEY`, clear `ENCRYPTION_KEY_NEW` and run
`systemctl restart provenza.target`.

## Configuration

Every setting is described in [`.env.example`](.env.example). The most common:

| Variable | Default | Purpose |
|---|---|---|
| `PROVENZA_DOMAIN` | — | Public domain; TLS is issued for it |
| `HTTP_PORT`, `HTTPS_PORT` | 80, 443 | Ports Caddy publishes |
| `API_WORKERS` | 2 | Uvicorn worker processes |
| `CELERY_CONCURRENCY` | 2 | Parallel background tasks |
| `PROMPT_FIREWALL_NER_ENABLED` | true | NER-based PII detection |
| `ALLOW_PUBLIC_SIGNUP` | false | Let anyone create an organization from the sign-up page |
| `OUTBOUND_PRIVATE_ALLOWLIST` | empty | Internal hosts outbound calls may reach, e.g. an in-house Vault or local model server |
| `OUTBOUND_PROXY` | empty | Egress proxy for outbound calls, if required |
| `SMTP_*` | empty | E-mail notifications |
| `*_MEMORY` | see file | Container memory limits |

Application settings reach the containers at their next restart. The domain,
ports, memory limits and passwords are part of the units: after changing them,
run `./scripts/units.sh install` first.

To change a unit, edit its template in `deploy/quadlet/` and run
`./scripts/units.sh install`: the files in `/etc/containers/systemd` are
overwritten (the previous ones are saved to `/root/provenza-units-*.tar`).

## Notes

- `docker-compose.dev.yml` and `docker-compose.yml` in the repository root are
  development stacks (the dev one seeds a demo admin). Never use them in
  production.
