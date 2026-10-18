#!/usr/bin/env bash
# Provenza hybrid development setup: data + observability (Postgres, Redis,
# Prometheus, Grafana, Alertmanager) in docker via the root
# docker-compose.yml, and the env files the backend, worker and beat need
# when they run on the host (it restarts them if systemd units ai-ct-* of an
# older hybrid install exist). docs/development.md describes the simpler
# docker-compose.dev.yml route.
#
# To run Provenza on a server, use ./install.sh instead: one command,
# Podman Quadlet units under systemd, everything behind Caddy
# (docs/self-hosting.md).
#
# Usage:
#   ./scripts/init-dev-env.sh                          # interactive
#   ./scripts/init-dev-env.sh --yes --domain X \
#       --org "Example" --admin-email a@b.c            # unattended
#   ./scripts/init-dev-env.sh --migrate                # add missing keys only
#   ./scripts/init-dev-env.sh --no-start               # skip docker + systemctl
#
# Idempotent: existing .env files and their values are never overwritten
# unless a required key is missing. No data is ever deleted.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="$ROOT/backend"
SECRET_FILE="$ROOT/deploy/observability/alertmanager-secret"

DOMAIN="" ORG="" ADMIN_EMAIL="" ADMIN_NAME=""
ASSUME_YES=0 MIGRATE=0 NO_START=0 NO_ADMIN=0

# ---------------------------------------------------------------- output
if [ -t 1 ]; then B=$'\033[1m' G=$'\033[32m' Y=$'\033[33m' R=$'\033[31m' N=$'\033[0m'
else B="" G="" Y="" R="" N=""; fi
step() { printf '%s→ %s%s\n' "$B" "$*" "$N"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s✗ %s%s\n' "$R" "$*" "$N" >&2; exit 1; }

# ---------------------------------------------------------------- prompts
tty_in() { if [ -r /dev/tty ]; then cat /dev/tty; else cat; fi; }
ask() {  # ask VAR "Question" [default]
  local __var=$1 __q=$2 __def=${3:-} __ans
  if [ "$ASSUME_YES" = 1 ] && [ -n "$__def" ]; then printf -v "$__var" '%s' "$__def"; return; fi
  [ "$ASSUME_YES" = 1 ] && die "--yes needs a value for: $__q"
  if [ -n "$__def" ]; then printf '%s? %s%s [%s]: ' "$B" "$__q" "$N" "$__def" >/dev/tty
  else printf '%s? %s%s: ' "$B" "$__q" "$N" >/dev/tty; fi
  IFS= read -r __ans </dev/tty || true
  printf -v "$__var" '%s' "${__ans:-$__def}"
}

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --domain)      DOMAIN=${2:?}; shift 2 ;;
    --org)         ORG=${2:?}; shift 2 ;;
    --admin-email) ADMIN_EMAIL=${2:?}; shift 2 ;;
    --admin-name)  ADMIN_NAME=${2:?}; shift 2 ;;
    --yes|-y)      ASSUME_YES=1; shift ;;
    --migrate)     MIGRATE=1; shift ;;
    --no-start)    NO_START=1; shift ;;
    --no-admin)    NO_ADMIN=1; shift ;;
    -h|--help)     usage ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

# ---------------------------------------------------------------- helpers
gen() {  # gen <length> <hex|b64|b64url>
  case "$2" in
    hex)     openssl rand -hex "$1" ;;
    b64)     openssl rand -base64 "$1" | tr -d '\n' ;;
    b64url)  openssl rand -base64 "$1" | tr '+/' '-_' | tr -d '\n' ;;
  esac
}

get_env() {  # get_env <file> <key>
  local file=$1 key=$2
  [ -f "$file" ] || { echo ""; return 0; }
  # pipefail + grep exit=1 on no match would abort the caller under set -e;
  # || true is the local fix, and the trailing `echo` returns 0.
  grep -E "^${key}=" "$file" 2>/dev/null | tail -1 | cut -d= -f2- || true
}

set_env() {  # set_env <file> <key> <value>  — replaces or appends
  local file=$1 key=$2 value=$3 tmp
  touch "$file"
  tmp=$(mktemp)
  awk -v k="$key" -v v="$value" '
    BEGIN { done = 0 }
    {
      if (index($0, k"=") == 1) { print k"="v; done = 1; next }
      print
    }
    END { if (!done) print k"="v }
  ' "$file" > "$tmp"
  mv "$tmp" "$file"
}

ensure_env() {  # ensure_env <file> <key> <value-if-empty> — set if missing or placeholder
  local file=$1 key=$2 value=$3 current
  current=$(get_env "$file" "$key")
  # Known placeholders from .env.example that must be replaced by a real
  # generated value on the first run.
  case "$current" in
    ""|ai_password|change_me_in_dot_env|your_key|CHANGEME|placeholder)
      set_env "$file" "$key" "$value"
      echo "set"
      ;;
    *)
      echo "kept"
      ;;
  esac
}

# ---------------------------------------------------------------- preflight
step "Checking prerequisites"
command -v openssl >/dev/null || die "openssl is required (apt install openssl)"
command -v docker  >/dev/null || die "docker is required"
docker compose version >/dev/null 2>&1 || die "docker compose plugin is required"
[ -x "$BACKEND/.venv/bin/alembic" ] || die "backend virtualenv missing: cd $BACKEND && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
[ -f "$ROOT/docker-compose.yml" ] || die "root docker-compose.yml missing"
ok "all tools present"

# ---------------------------------------------------------------- migrate
if [ "$MIGRATE" = 1 ]; then
  step "Migrating existing .env files (only missing keys are added)"
  [ -f "$ROOT/.env" ]         || die "$ROOT/.env does not exist; run without --migrate for a fresh install"
  [ -f "$BACKEND/.env" ]      || die "$BACKEND/.env does not exist; run without --migrate"

  # Sync shared secrets between the two env files. Four cases per key:
  #   both equal        -> keep
  #   only root has it  -> copy to backend
  #   only backend has  -> copy to root
  #   neither has it    -> generate fresh, write to both
  for key in ALERTMANAGER_SECRET REDIS_PASSWORD; do
    v_root=$(get_env "$ROOT/.env" "$key")
    v_back=$(get_env "$BACKEND/.env" "$key")
    if [ -n "$v_root" ] && [ -n "$v_back" ] && [ "$v_root" = "$v_back" ]; then
      ok "$key: already in sync"
      continue
    fi
    if [ -n "$v_root" ]; then
      set_env "$BACKEND/.env" "$key" "$v_root"
      ok "$key: propagated root -> backend"
    elif [ -n "$v_back" ]; then
      set_env "$ROOT/.env" "$key" "$v_back"
      ok "$key: propagated backend -> root"
    else
      case "$key" in
        ALERTMANAGER_SECRET) fresh=$(gen 32 hex) ;;
        REDIS_PASSWORD)      fresh=$(gen 24 hex) ;;
        *)                   fresh=$(gen 24 hex) ;;
      esac
      set_env "$ROOT/.env"    "$key" "$fresh"
      set_env "$BACKEND/.env" "$key" "$fresh"
      ok "$key: generated fresh (was missing in both)"
    fi
  done

  # alertmanager-secret must match ALERTMANAGER_SECRET.
  v=$(get_env "$ROOT/.env" ALERTMANAGER_SECRET)
  if [ -n "$v" ]; then
    if [ "$(cat "$SECRET_FILE" 2>/dev/null)" != "$v" ]; then
      printf '%s' "$v" > "$SECRET_FILE"
      chmod 600 "$SECRET_FILE"
      ok "alertmanager-secret synced"
    else
      ok "alertmanager-secret already in sync"
    fi
  fi

  if [ "$NO_START" = 0 ]; then
    step "Restarting containers and services"
    ( cd "$ROOT" && docker compose up -d ) || die "docker compose up failed"
    if command -v systemctl >/dev/null && systemctl list-unit-files ai-ct-backend.service >/dev/null 2>&1; then
      sudo systemctl restart ai-ct-backend ai-ct-celery ai-ct-celery-beat 2>/dev/null || true
      ok "systemd services restarted"
    fi
  fi

  ok "migration complete"
  exit 0
fi

# ---------------------------------------------------------------- prompts
step "Configuration"
[ -n "$DOMAIN" ]      || ask DOMAIN      "Public domain for the UI" "localhost"
[ -n "$ORG" ]         || ask ORG         "Organization name" "Provenza"
[ -n "$ADMIN_EMAIL" ] || ask ADMIN_EMAIL "First administrator e-mail" "admin@${DOMAIN}"
[ -n "$ADMIN_NAME" ]  || ask ADMIN_NAME  "First administrator name" "Admin"

# ---------------------------------------------------------------- secrets
step "Generating secrets (existing values are kept)"
SECRET_KEY=$(gen 48 b64)
ENCRYPTION_KEY=$(gen 32 b64url)
PG_PASS=$(gen 24 hex)
REDIS_PASS=$(gen 24 hex)
ALERT_SECRET=$(gen 32 hex)
GRAFANA_PASS=$(gen 24 b64url)

# ---------------------------------------------------------------- backend/.env
step "Writing $BACKEND/.env"
[ -f "$BACKEND/.env" ] || cp "$BACKEND/.env.example" "$BACKEND/.env"
chmod 600 "$BACKEND/.env"

# Production mode by default; the backend refuses weak secrets in prod.
set_env "$BACKEND/.env" ENVIRONMENT production
set_env "$BACKEND/.env" CORS_ORIGINS "http://${DOMAIN}:3000,http://${DOMAIN}:8000"

ensure_env "$BACKEND/.env" SECRET_KEY      "$SECRET_KEY"  >/dev/null
ensure_env "$BACKEND/.env" ENCRYPTION_KEY  "$ENCRYPTION_KEY" >/dev/null
ensure_env "$BACKEND/.env" POSTGRES_PASSWORD "$PG_PASS"    >/dev/null
ensure_env "$BACKEND/.env" REDIS_PASSWORD  "$REDIS_PASS"   >/dev/null
ensure_env "$BACKEND/.env" ALERTMANAGER_SECRET "$ALERT_SECRET" >/dev/null
# defaults that the app needs but the example already has
ensure_env "$BACKEND/.env" POSTGRES_USER   "ai_user"       >/dev/null
ensure_env "$BACKEND/.env" POSTGRES_DB     "ai_control_tower" >/dev/null
ensure_env "$BACKEND/.env" POSTGRES_HOST   "localhost"     >/dev/null
ensure_env "$BACKEND/.env" POSTGRES_PORT   "5432"          >/dev/null
ensure_env "$BACKEND/.env" REDIS_HOST      "localhost"     >/dev/null
ensure_env "$BACKEND/.env" REDIS_PORT      "6379"          >/dev/null
ensure_env "$BACKEND/.env" ACCESS_TOKEN_EXPIRE_MINUTES "30" >/dev/null
ok "backend/.env written"

# ---------------------------------------------------------------- root .env
step "Writing $ROOT/.env"
[ -f "$ROOT/.env" ] || cp "$ROOT/.env.example" "$ROOT/.env"
chmod 600 "$ROOT/.env"

# Read back what backend/.env has (fresh values, or pre-existing ones).
set_env "$ROOT/.env" POSTGRES_USER          "$(get_env "$BACKEND/.env" POSTGRES_USER)"
set_env "$ROOT/.env" POSTGRES_PASSWORD      "$(get_env "$BACKEND/.env" POSTGRES_PASSWORD)"
set_env "$ROOT/.env" POSTGRES_DB            "$(get_env "$BACKEND/.env" POSTGRES_DB)"
set_env "$ROOT/.env" REDIS_PASSWORD         "$(get_env "$BACKEND/.env" REDIS_PASSWORD)"
set_env "$ROOT/.env" ALERTMANAGER_SECRET    "$(get_env "$BACKEND/.env" ALERTMANAGER_SECRET)"
ensure_env "$ROOT/.env" GRAFANA_PASSWORD    "$GRAFANA_PASS" >/dev/null
# Domain-dependent keys: overwrite with the operator's actual domain.
# A re-run with a different domain should also pick it up; keeping the
# old domain would silently send the UI to the wrong place.
set_env "$ROOT/.env" CORS_ORIGINS        "http://${DOMAIN}:3000,http://localhost:3000"
set_env "$ROOT/.env" NEXT_PUBLIC_API_URL "http://${DOMAIN}:8000/api/v1"
ok "root .env written"

# ---------------------------------------------------------------- secret file
step "Writing Alertmanager secret file"
mkdir -p "$(dirname "$SECRET_FILE")"
printf '%s' "$(get_env "$ROOT/.env" ALERTMANAGER_SECRET)" > "$SECRET_FILE"
chmod 600 "$SECRET_FILE"
ok "alertmanager-secret written (mode 600)"

# ---------------------------------------------------------------- start
if [ "$NO_START" = 1 ]; then
  warn "--no-start: skipping docker compose up and systemctl restart"
  exit 0
fi

step "Starting containers (postgres, redis, prometheus, grafana, alertmanager)"
( cd "$ROOT" && docker compose up -d ) || die "docker compose up failed: docker compose logs"

step "Waiting for Postgres"
ready=0
for _ in $(seq 1 60); do
  if docker exec ai_ct_db pg_isready -U "$(get_env "$ROOT/.env" POSTGRES_USER)" >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done
[ "$ready" = 1 ] || die "Postgres did not become ready in 60s"
ok "Postgres ready"

step "Running database migrations"
( cd "$BACKEND" && .venv/bin/alembic upgrade head ) || die "alembic upgrade failed"
ok "migrations applied"

# ---------------------------------------------------------------- admin
if [ "$NO_ADMIN" = 0 ]; then
  step "Creating the first administrator (idempotent)"
  if [ -z "${PROVENZA_ADMIN_PASSWORD:-}" ]; then
    if [ -r /dev/tty ]; then
      printf '%s? Admin password (min 12 chars, hidden): %s' "$B" "$N" >/dev/tty
      IFS= read -r -s PROVENZA_ADMIN_PASSWORD </dev/tty || true
      printf '\n' >/dev/tty
    fi
    [ -n "${PROVENZA_ADMIN_PASSWORD:-}" ] || die "PROVENZA_ADMIN_PASSWORD is empty"
  fi
  export PROVENZA_ADMIN_PASSWORD
  ( cd "$BACKEND" && .venv/bin/python scripts/create_admin.py \
      --org "$ORG" --email "$ADMIN_EMAIL" --name "$ADMIN_NAME" ) || \
    warn "create_admin reported an issue (an admin with this e-mail may already exist)"
  unset PROVENZA_ADMIN_PASSWORD
fi

# ---------------------------------------------------------------- services
if command -v systemctl >/dev/null && systemctl list-unit-files ai-ct-backend.service >/dev/null 2>&1; then
  step "Restarting systemd services"
  sudo systemctl restart ai-ct-backend ai-ct-celery ai-ct-celery-beat 2>/dev/null || \
    warn "systemctl restart failed; check: sudo systemctl status ai-ct-backend"
  ok "systemd services restarted"
else
  warn "systemd units ai-ct-*.service not found — start the backend manually"
fi

# ---------------------------------------------------------------- summary
step "Done"
cat <<SUMMARY

  UI:          http://${DOMAIN}:3000
  API:         http://${DOMAIN}:8000/api/v1
  Prometheus:  http://127.0.0.1:9090
  Grafana:     http://127.0.0.1:3001  (admin / see GRAFANA_PASSWORD in $ROOT/.env)
  Alertmanager:http://127.0.0.1:9093

  Admin:       ${ADMIN_EMAIL} (${ORG})
  Secrets:     backend/.env, .env, deploy/observability/alertmanager-secret
               Back these up; ENCRYPTION_KEY cannot be recovered.

  Next:
    - open the UI and confirm the sensor / workloads load
    - point a sensor at http://${DOMAIN}:8000 with its pvz_sensor_ key
    - re-run this script with --migrate after a git pull to fill new keys

SUMMARY
