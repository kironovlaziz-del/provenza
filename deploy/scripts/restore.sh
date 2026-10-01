#!/bin/sh
# Restore a backup made by backup.sh. DESTROYS the current data.
#   ./scripts/restore.sh backups/provenza-20261001-031500.dump
# The matching .data.tar.gz (same timestamp) is restored when present.
# deploy/.env must hold the ENCRYPTION_KEY that was in use at backup time.
set -eu
cd "$(dirname "$0")/.."
dump="${1:?usage: restore.sh <path/to/provenza-TIMESTAMP.dump>}"
[ -f "$dump" ] || { echo "no such file: $dump" >&2; exit 1; }
files="${dump%.dump}.data.tar.gz"
set -a; . ./.env; set +a

printf "This replaces ALL current Provenza data with %s. Type 'restore' to continue: " "$dump"
read -r answer
[ "$answer" = "restore" ] || { echo "aborted"; exit 1; }

docker compose stop caddy frontend backend worker beat
docker compose up -d postgres redis
docker compose exec -T postgres sh -c 'until pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"; do sleep 1; done'

echo "[restore] database"
docker compose exec -T postgres pg_restore -U "${POSTGRES_USER:-provenza}" -d "${POSTGRES_DB:-provenza}" \
  --clean --if-exists --no-owner --single-transaction < "$dump"

if [ -f "$files" ]; then
  echo "[restore] files"
  docker compose run --rm --no-deps -T --entrypoint sh backend -c 'rm -rf /app/data/* && tar xzf - -C /app' < "$files"
fi

docker compose up -d
echo "[restore] done - migrations run automatically if the backup is older than the code"
