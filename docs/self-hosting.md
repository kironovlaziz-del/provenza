# Self-hosting Provenza

Provenza runs on your own server, so your prompts, policies, audit records and
keys never leave it. This guide takes you from a fresh server to a running
control plane, and covers keeping it running and up to date.

## Requirements

| | |
|---|---|
| Server | Linux (Ubuntu 22.04+ or Debian 12+ recommended), 2 vCPU, **4 GB RAM**, 20 GB disk |
| Software | Docker Engine 24+ with the Compose plugin v2, `git`, `openssl` |
| Network | A domain name whose DNS record points at the server; ports **80 and 443** open to the internet |

To install Docker on Ubuntu, follow <https://docs.docker.com/engine/install/ubuntu/>.

## Install

```bash
git clone https://github.com/kironovlaziz-del/provenza.git /opt/provenza
cd /opt/provenza
./install.sh
```

The installer asks for:

- the domain;
- the organization name;
- the first administrator's e-mail, name and password (12 characters or more).

It then does everything else, and a few minutes later prints the address to
sign in at:

```
→ Checking this server
  ✓ Docker 27.3, Compose 2.29.7
  ✓ 7951 MB RAM
  ✓ 61 GB free disk
→ Configuration
  ✓ secrets generated into deploy/.env (mode 600)
  ✓ app.company.com resolves to 203.0.113.10
→ Building and starting the stack (the first build takes a few minutes)
→ Waiting for the database migrations and the services
  ✓ migrations applied; API, workers, web UI and HTTPS proxy are up
→ Creating the administrator
  ✓ daily backup scheduled (crontab -l)

✓ Provenza is running at https://app.company.com
```

**Without cloning first.** Read the script before piping it into a shell:

```bash
curl -fsSL https://raw.githubusercontent.com/kironovlaziz-del/provenza/main/install.sh | bash
```

It clones the repository into `/opt/provenza`, or the directory given with
`--dir`, and continues from there.

**Unattended.** For example from cloud-init or Ansible:

```bash
PROVENZA_ADMIN_PASSWORD='…' ./install.sh --yes \
  --domain app.company.com --org "Company" --admin-email admin@company.com
```

| Option | |
|---|---|
| `--admin-name NAME` | The administrator's display name. |
| `--no-cron` | Do not schedule the daily backup. |
| `--force` | Go on despite host warnings: low memory or disk, ports 80/443 already in use. |
| `PROVENZA_READY_TIMEOUT` | Seconds to wait for the stack to become healthy (default 900). |

**Trying it on your own machine.** Use `localhost` as the domain. Caddy then
issues a local certificate, and the browser warns about it once.

### What the installer does

1. **Checks the host:** Docker and Compose v2, memory, disk, whether the domain resolves, and whether ports 80/443 are free.
2. **Writes `deploy/.env`** (mode 600) with freshly generated secrets:
   - `SECRET_KEY` for signing sessions;
   - `ENCRYPTION_KEY` for stored API keys and secrets;
   - the PostgreSQL and Redis passwords.

   There are no default passwords anywhere: the backend refuses to start with a missing or well-known secret.
3. **Builds and starts the stack** from `deploy/docker-compose.yml`: PostgreSQL 16, Redis 7, a migration job, the API, a worker, the scheduler, the web UI and Caddy. Migrations run before anything that needs the database.
4. **Waits** until every service reports healthy.
5. **Creates the organization and its first administrator.** The password reaches the container through the environment and never appears in a command line.
6. **Schedules a daily backup** at 03:15 in the crontab of the user who ran the installer.

Running `./install.sh` again is safe: it keeps the existing `deploy/.env` and
leaves existing users alone.

### First steps after installing

1. **Back up `deploy/.env`** to somewhere off the server, such as a password manager. Without its `ENCRYPTION_KEY`, no backup can be read.
2. Sign in and follow the **setup checklist** on the dashboard:
   - connect an AI provider;
   - activate a policy;
   - register the first agent;
   - set up notifications;
   - require two-factor sign-in.
3. Under **My profile**, turn on two-factor sign-in for yourself. Then, under **Settings → Users**, require it for admins and approvers.
4. Connect an agent:
   - **Agents** → create an enrollment token;
   - on the agent's host, install the SDK: `pip install provenza` (or the JS or Go SDK).

## HTTPS

Caddy obtains and renews a Let's Encrypt certificate for the domain by itself.
It needs two things:

- the domain's DNS record pointing at the server;
- ports 80 and 443 reachable from the internet. Let's Encrypt validates over port 80.

No e-mail address is required. Let's Encrypt no longer sends expiry
reminders, and Caddy renews certificates well before they expire.

Caddy also sets HSTS and the other security headers, and the application sends
its own as well.

**Another web server already on 80/443.** The installer warns about this.
Either stop the other server, or put Provenza behind it:

1. Set `HTTP_PORT` and `HTTPS_PORT` in `deploy/.env` to free ports.
2. Proxy your domain to Caddy's HTTPS port.

## Backups

The installer schedules `deploy/scripts/backup.sh` daily. Each backup is a
`pg_dump` of the database plus the uploaded files, stored in `deploy/backups/`
and kept for 14 days (`BACKUP_KEEP_DAYS`).

To run one by hand:

```bash
cd /opt/provenza/deploy && ./scripts/backup.sh
```

Copy `deploy/backups/` off the server regularly. A backup that stays on the
same disk does not survive the loss of that disk.

To restore (this replaces all current data, after asking you to confirm):

```bash
cd /opt/provenza/deploy
./scripts/restore.sh backups/provenza-20261012-031500.dump
```

`deploy/.env` must hold the `ENCRYPTION_KEY` that was in use when the backup
was made.

## Upgrade

```bash
cd /opt/provenza
./upgrade.sh                    # the latest version of the branch you installed
./upgrade.sh --version v1.4.0   # or a specific release
```

The script:

1. **Shows what is new and asks for confirmation.**
2. **Builds the new images** while the current version keeps serving.
3. **Stops outside access, then makes a backup.** Nothing can change data during the backup. This is the only downtime, usually under a minute.
4. **Starts the new version.** Its database migrations run first.
5. **Rolls back if anything is not healthy:** it restores the previous code and images, and, if the migrations had already changed the database, the database from the backup taken in step 3.

The previous images are kept as `:rollback` until the next upgrade.

Options:

- `--yes` skips the question;
- `--force` upgrades over local changes to tracked files. Without it, the script stops and lists them, so a local fix is never silently overwritten.

## Operating

All commands run in `/opt/provenza/deploy`.

| Task | Command |
|---|---|
| Status | `docker compose ps` |
| Logs | `docker compose logs -f backend worker` |
| Restart | `docker compose restart` |
| Stop / start | `docker compose stop` / `docker compose up -d` |
| Another administrator | `docker compose run --rm -it backend create-admin --org "Company" --email someone@company.com` |
| Health from the UI | **Settings → System status** |

Do not share the output of `docker compose config`: it contains the secrets
from `deploy/.env`.

Every setting is documented in `deploy/.env.example`. The most common:

- `API_WORKERS`, `CELERY_CONCURRENCY`: capacity;
- `SMTP_*`: e-mail notifications;
- `OUTBOUND_PRIVATE_ALLOWLIST`: internal hosts Provenza may call, such as an in-house Vault or model server;
- `*_MEMORY`: container memory limits.

After editing `deploy/.env`, run `docker compose up -d`.

## Troubleshooting

| Symptom | What to do |
|---|---|
| The browser warns about the certificate | The DNS record does not point at the server yet, or port 80 is blocked. `docker compose logs caddy` shows the reason; Caddy retries by itself. |
| The installer says a port is in use | Another web server is running. Stop it, or see "Another web server already on 80/443" above. |
| `the database migrations failed` | `docker compose logs migrate`. After an upgrade, `upgrade.sh` has already rolled back. |
| A service stays unhealthy | `docker compose ps`, then `docker compose logs <service>`. Low memory is the usual cause: check `free -m` and the `*_MEMORY` limits. |
| `FATAL: … uses a well-known default value` | A secret in `deploy/.env` was edited to a weak value. Generate a new one with `openssl rand -base64 48`. Do not change `ENCRYPTION_KEY`: rotate it with `scripts/rotate_encryption_key.py` (see `deploy/README.md`). |
| An administrator forgot their password | Create another administrator with `create-admin` (see Operating). |
| An administrator lost their two-factor device | Another administrator: **Settings → Users → Reset 2FA**. |

## Security checklist

- [ ] `deploy/.env` is backed up off the server, and only root can read it on the server.
- [ ] Backups are copied off the server.
- [ ] Two-factor sign-in is required, at least for admins and approvers.
- [ ] SSH accepts keys only (`PasswordAuthentication no`), and the firewall allows only 22, 80 and 443.
- [ ] `ALLOW_PUBLIC_SIGNUP` is left `false`.
- [ ] You upgrade regularly: `./upgrade.sh`.

See also [SECURITY.md](../SECURITY.md) and [deploy/README.md](../deploy/README.md)
for the details of the stack.
