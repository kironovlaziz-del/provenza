#!/usr/bin/env bash
# Back up the Provenza database and uploaded files (run as root).
#   sudo ./scripts/backup.sh       -> $BACKUP_DIR/provenza-<timestamp>.{dump,data.tar.gz}
# install.sh schedules it daily with provenza-backup.timer (03:15):
#   systemctl list-timers provenza-backup.timer; journalctl -u provenza-backup
# deploy/.env (ENCRYPTION_KEY!) is NOT included - back it up separately.
set -euo pipefail
# shellcheck source=deploy/scripts/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_root
cd "$DEPLOY_DIR"
dir=$(env_get BACKUP_DIR); dir=${dir:-./backups}
keep=$(env_get BACKUP_KEEP_DAYS); keep=${keep:-14}
pg_user=$(env_get POSTGRES_USER); pg_db=$(env_get POSTGRES_DB)
stamp=$(date -u +%Y%m%d-%H%M%S)
mkdir -p "$dir"
umask 077

container_running postgres || die "the postgres container is not running (systemctl start provenza-postgres)"

echo "[backup] database -> $dir/provenza-$stamp.dump"
podman exec postgres pg_dump -U "${pg_user:-provenza}" -d "${pg_db:-provenza}" \
  --format=custom --no-owner > "$dir/provenza-$stamp.dump.partial"
mv "$dir/provenza-$stamp.dump.partial" "$dir/provenza-$stamp.dump"

echo "[backup] files -> $dir/provenza-$stamp.data.tar.gz"
podman run --rm --network none -v provenza_app-data:/app/data:ro --entrypoint tar \
  "$(image_ref backend)" czf - -C /app data > "$dir/provenza-$stamp.data.tar.gz.partial"
mv "$dir/provenza-$stamp.data.tar.gz.partial" "$dir/provenza-$stamp.data.tar.gz"

find "$dir" -name 'provenza-*' -type f -mtime +"$keep" -print -delete | sed 's/^/[backup] removed old /'
echo "[backup] done"
