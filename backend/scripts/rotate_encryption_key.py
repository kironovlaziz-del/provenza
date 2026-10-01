"""
Rotate the server master key (ENCRYPTION_KEY).

The master key encrypts, directly:
  - ai_providers.api_key_encrypted          connection API keys
  - ai_requests.input_text_encrypted        raw prompts
  - service_connections.bind_password_encrypted   directory passwords
  - org_keys.config_secret_encrypted        BYOK: Vault token / AWS secret
  - org_keys.wrapped_dek  (provider=local)  BYOK: the organizations' data keys
Values in the "pvz2:<key>:..." format belong to an organization key (BYOK)
and are not touched - rotating the master key re-wraps that key instead.

Forgetting org_keys here would make every BYOK organization on the "local"
provider unreadable the moment ENCRYPTION_KEY changes.

Usage (from backend/, venv active):
    1. Generate a new key:
         python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    2. Put it in backend/.env as ENCRYPTION_KEY_NEW, keep ENCRYPTION_KEY as is.
    3. Stop everything that encrypts:
         sudo systemctl stop ai-ct-backend ai-ct-celery ai-ct-celery-beat
    4. python3 scripts/rotate_encryption_key.py --dry-run     # report only
       python3 scripts/rotate_encryption_key.py               # rotate
    5. Move the new value into ENCRYPTION_KEY, remove ENCRYPTION_KEY_NEW.
    6. sudo systemctl start ai-ct-backend ai-ct-celery ai-ct-celery-beat

Idempotent: values already under the new key are skipped, so an interrupted
run can simply be started again (before step 5).
"""

import argparse
import sys
from pathlib import Path

# Allow "python scripts/rotate_encryption_key.py" from backend/
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.fernet import Fernet, InvalidToken  # noqa: E402
from sqlalchemy import inspect, select, update  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.core.sync_database import SyncSessionLocal, sync_engine  # noqa: E402

ORG_KEY_PREFIX = "pvz2:"
BATCH = 500


def rotate_value(old: Fernet, new: Fernet, value: str):
    """-> (status, new_value): rotated | already_new | org_key | failed"""
    if value.startswith(ORG_KEY_PREFIX):
        return "org_key", None
    try:
        plain = old.decrypt(value.encode())
    except InvalidToken:
        try:
            new.decrypt(value.encode())
            return "already_new", None
        except InvalidToken:
            return "failed", None
    return "rotated", new.encrypt(plain).decode()


def targets():
    """(model, column, extra where-clause or None) for every column under the master key."""
    from app.models.ai_provider import AIProvider
    from app.models.ai_request import AIRequest

    out = [(AIProvider, "api_key_encrypted", None), (AIRequest, "input_text_encrypted", None)]
    tables = set(inspect(sync_engine).get_table_names())
    if "service_connections" in tables:
        from app.models.service_connection import ServiceConnection
        out.append((ServiceConnection, "bind_password_encrypted", None))
    if "org_keys" in tables:
        from app.models.org_key import OrgKey
        out.append((OrgKey, "config_secret_encrypted", None))
        out.append((OrgKey, "wrapped_dek", OrgKey.provider == "local"))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dry-run", action="store_true", help="report what would change, write nothing")
    args = parser.parse_args()

    old_key = settings.ENCRYPTION_KEY.strip()
    new_key = settings.ENCRYPTION_KEY_NEW.strip()
    if not old_key:
        print("ERROR: ENCRYPTION_KEY is empty.", file=sys.stderr)
        return 1
    if not new_key:
        print("ERROR: ENCRYPTION_KEY_NEW is empty. Set it in backend/.env first.", file=sys.stderr)
        return 1
    if old_key == new_key:
        print("ERROR: new key equals old key, nothing to do.", file=sys.stderr)
        return 1
    try:
        old_f, new_f = Fernet(old_key.encode()), Fernet(new_key.encode())
    except ValueError as exc:
        print(f"ERROR: invalid Fernet key: {exc}", file=sys.stderr)
        return 1

    totals = {"rotated": 0, "already_new": 0, "org_key": 0, "failed": 0}
    failures = []
    db = SyncSessionLocal()
    try:
        for model, col, extra in targets():
            column = getattr(model, col)
            counts = {k: 0 for k in totals}
            last_id = 0
            while True:
                q = select(model.id, column).where(column.is_not(None), model.id > last_id)
                if extra is not None:
                    q = q.where(extra)
                rows = db.execute(q.order_by(model.id).limit(BATCH)).all()
                if not rows:
                    break
                for row_id, value in rows:
                    last_id = row_id
                    status, new_value = rotate_value(old_f, new_f, value)
                    counts[status] += 1
                    if status == "failed":
                        failures.append(f"{model.__tablename__}.{col} id={row_id}")
                    elif status == "rotated" and not args.dry_run:
                        db.execute(update(model).where(model.id == row_id).values({col: new_value}))
                if args.dry_run:
                    db.rollback()
                else:
                    db.commit()
            label = f"{model.__tablename__}.{col}" + (" (local)" if extra is not None else "")
            print(f"{label:55} rotated={counts['rotated']:6} already_new={counts['already_new']:6} "
                  f"org_key={counts['org_key']:6} failed={counts['failed']:4}")
            for k in totals:
                totals[k] += counts[k]
    finally:
        db.close()

    print()
    print(("DRY RUN - nothing written. " if args.dry_run else "") +
          f"rotated={totals['rotated']} already_new={totals['already_new']} "
          f"left on organization keys={totals['org_key']} failed={totals['failed']}")
    if failures:
        print("Values no key could decrypt (left unchanged):")
        for f in failures[:50]:
            print("  -", f)
        if len(failures) > 50:
            print(f"  ... and {len(failures) - 50} more")
    if not args.dry_run:
        print()
        print("Next: move ENCRYPTION_KEY_NEW into ENCRYPTION_KEY, remove ENCRYPTION_KEY_NEW,")
        print("then: sudo systemctl start ai-ct-backend ai-ct-celery ai-ct-celery-beat")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
