#!/usr/bin/env bash
# Restore a backup made by backup.sh. DESTROYS the current data (run as root).
#   sudo ./scripts/restore.sh backups/provenza-20261001-031500.dump
# The matching .data.tar.gz (same timestamp) is restored when present.
# deploy/.env must hold the ENCRYPTION_KEY that was in use at backup time.
set -euo pipefail
# shellcheck source=deploy/scripts/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_root
dump="${1:?usage: restore.sh <path/to/provenza-TIMESTAMP.dump>}"
[ -f "$dump" ] || die "no such file: $dump"
dump=$(cd "$(dirname "$dump")" && pwd)/$(basename "$dump")
files="${dump%.dump}.data.tar.gz"
cd "$DEPLOY_DIR"
pg_user=$(env_get POSTGRES_USER); pg_user=${pg_user:-provenza}
pg_db=$(env_get POSTGRES_DB); pg_db=${pg_db:-provenza}

# PROVENZA_RESTORE_CONFIRM=restore answers the question (upgrade.sh rolling back)
answer="${PROVENZA_RESTORE_CONFIRM:-}"
if [ -z "$answer" ]; then
  printf "This replaces ALL current Provenza data with %s. Type 'restore' to continue: " "$dump"
  read -r answer
fi
[ "$answer" = "restore" ] || { echo "aborted"; exit 1; }

systemctl stop provenza-caddy.service provenza-frontend.service provenza-backend.service \
  provenza-worker.service provenza-beat.service
systemctl start provenza-postgres.service provenza-redis.service
until podman exec postgres pg_isready -U "$pg_user" -d "$pg_db" >/dev/null 2>&1; do sleep 1; done

echo "[restore] database"
podman exec -i postgres pg_restore -U "$pg_user" -d "$pg_db" \
  --clean --if-exists --no-owner --single-transaction < "$dump"

if [ -f "$files" ]; then
  echo "[restore] files"
  podman run --rm -i --network none -v provenza_app-data:/app/data --entrypoint sh \
    "$(image_ref backend)" -c 'rm -rf /app/data/* && tar xzf - -C /app' < "$files"
fi

# Migrations run again (the backup may be older than the code), then the rest
systemctl restart provenza-migrate.service
systemctl start provenza.target
echo "[restore] done"
