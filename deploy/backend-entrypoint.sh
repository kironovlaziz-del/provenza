#!/bin/sh
# Provenza backend entrypoint. One image, several roles:
#   api | worker | beat | migrate | create-admin [args] | <any command>
# Refuses to start with missing or well-known default secrets.
set -eu

log() { echo "[provenza] $*"; }
die() { echo "[provenza] FATAL: $*" >&2; exit 64; }

check_secrets() {
  for v in SECRET_KEY ENCRYPTION_KEY POSTGRES_PASSWORD REDIS_PASSWORD; do
    eval "val=\${$v:-}"
    [ -n "$val" ] || die "$v is not set - see deploy/.env.example (or run deploy/scripts/init-env.sh)"
    case "$val" in
      ai_password|changeme|change-me|password|your-secret-key-change-in-production|dev-secret-change-me*)
        die "$v uses a well-known default value - generate a real one" ;;
    esac
  done
  [ "${#SECRET_KEY}" -ge 32 ] || die "SECRET_KEY must be at least 32 characters"
  python - <<'PY' || die "ENCRYPTION_KEY is not a valid Fernet key (32 url-safe base64-encoded bytes)"
import os
from cryptography.fernet import Fernet
Fernet(os.environ["ENCRYPTION_KEY"].encode())
PY
  # The application's own production checks (placeholder-looking keys,
  # default passwords, ...) - one source of truth, see app/core/config.py.
  python - <<'PY' || die "configuration rejected - see the reasons above"
from app.core.config import secret_key_problems
import os, sys
problems = secret_key_problems(os.environ.get("SECRET_KEY", ""))
for p in problems:
    print("[provenza]   - " + p, file=sys.stderr)
sys.exit(1 if problems else 0)
PY
}

wait_for() {  # host port name
  python - "$1" "$2" "$3" <<'PY' || die "$3 at $1:$2 is not reachable"
import socket, sys, time
host, port, name = sys.argv[1], int(sys.argv[2]), sys.argv[3]
deadline = time.time() + 120
while True:
    try:
        socket.create_connection((host, port), timeout=3).close()
        break
    except OSError:
        if time.time() > deadline:
            sys.exit(1)
        time.sleep(2)
PY
}

role="${1:-api}"
[ "$#" -gt 0 ] && shift

case "$role" in
  api|worker|beat|migrate|create-admin)
    check_secrets
    wait_for "${POSTGRES_HOST:-postgres}" "${POSTGRES_PORT:-5432}" postgres
    ;;
esac
case "$role" in
  api|worker|beat) wait_for "${REDIS_HOST:-redis}" "${REDIS_PORT:-6379}" redis ;;
esac

case "$role" in
  migrate)
    log "applying database migrations"
    exec alembic upgrade head
    ;;
  api)
    log "starting API (${API_WORKERS:-2} workers)"
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000 \
      --workers "${API_WORKERS:-2}" --proxy-headers --forwarded-allow-ips '*' \
      --timeout-keep-alive 75 --no-server-header
    ;;
  worker)
    log "starting Celery worker (concurrency ${CELERY_CONCURRENCY:-2})"
    exec celery -A app.core.celery_app worker --loglevel "${LOG_LEVEL:-info}" \
      --concurrency "${CELERY_CONCURRENCY:-2}" --max-tasks-per-child 200
    ;;
  beat)
    log "starting Celery beat"
    exec celery -A app.core.celery_app beat --loglevel "${LOG_LEVEL:-info}" \
      --schedule /app/run/celerybeat-schedule
    ;;
  create-admin)
    exec python scripts/create_admin.py "$@"
    ;;
  *)
    exec "$role" "$@"
    ;;
esac
