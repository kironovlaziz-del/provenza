#!/usr/bin/env bash
# Run a one-off command in a backend container with the services' settings
# (the Podman counterpart of `docker compose run --rm backend ...`). As root:
#   sudo ./scripts/run.sh create-admin --org "Company" --email admin@company.com --name "Jane Admin"
#   sudo ./scripts/run.sh python scripts/rotate_encryption_key.py --dry-run
#   sudo ./scripts/run.sh alembic current
set -euo pipefail
# shellcheck source=deploy/scripts/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_root
[ $# -gt 0 ] || { sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
[ -f "$DEPLOY_DIR/.env" ] || die "deploy/.env not found"
container_running postgres || die "the stack is not running (systemctl start provenza.target)"
tty=()
[ -t 0 ] && [ -t 1 ] && tty=(-it)
exec_args=("${tty[@]}")
[ -n "${PROVENZA_ADMIN_PASSWORD:-}" ] && exec_args+=(-e PROVENZA_ADMIN_PASSWORD)
backend_run "${exec_args[@]}" -- "$@"
