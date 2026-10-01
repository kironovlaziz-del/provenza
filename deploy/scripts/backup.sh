#!/bin/sh
# Back up the Provenza database and uploaded files.
#   ./scripts/backup.sh            -> $BACKUP_DIR/provenza-<timestamp>.{dump,data.tar.gz}
# Run it from cron, e.g.: 15 3 * * * cd /opt/provenza/deploy && ./scripts/backup.sh
# deploy/.env (ENCRYPTION_KEY!) is NOT included - back it up separately.
set -eu
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
dir="${BACKUP_DIR:-./backups}"
keep="${BACKUP_KEEP_DAYS:-14}"
stamp=$(date -u +%Y%m%d-%H%M%S)
mkdir -p "$dir"
umask 077

echo "[backup] database -> $dir/provenza-$stamp.dump"
docker compose exec -T postgres pg_dump -U "${POSTGRES_USER:-provenza}" -d "${POSTGRES_DB:-provenza}" \
  --format=custom --no-owner > "$dir/provenza-$stamp.dump.partial"
mv "$dir/provenza-$stamp.dump.partial" "$dir/provenza-$stamp.dump"

echo "[backup] files -> $dir/provenza-$stamp.data.tar.gz"
docker compose run --rm --no-deps -T --entrypoint tar backend czf - -C /app data \
  > "$dir/provenza-$stamp.data.tar.gz.partial"
mv "$dir/provenza-$stamp.data.tar.gz.partial" "$dir/provenza-$stamp.data.tar.gz"

find "$dir" -name 'provenza-*' -type f -mtime +"$keep" -print -delete | sed 's/^/[backup] removed old /'
echo "[backup] done"
