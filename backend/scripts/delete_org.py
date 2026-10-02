# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Delete one organization and everything that belongs to it.

    python scripts/delete_org.py --org-id 14                # dry run: what would go
    python scripts/delete_org.py --org-id 14 --execute      # delete, one transaction

Meant for organizations created by mistake (a demo stack started against the
production database). Real customers are offboarded through the product,
which keeps the audit trail; this removes it.

How it finds the data - from the live database schema, not a hand-kept list:
  1. every table with an org_id column: rows of this organization;
  2. every table with a foreign key to a table already in the set: rows that
     point at those rows (e.g. ai_responses -> ai_requests); repeated until
     nothing new is found;
  3. it refuses if rows of OTHER organizations point at rows it would delete,
     or if the organization is still active (use --allow-active to override);
  4. rows are deleted children first, in one transaction: all or nothing.

Files on disk (uploaded datasets, models) and Redis keys are not touched;
the dry run lists the data directories to check by hand.
"""

import argparse
import asyncio
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _plan(meta, org_id: int):
    """{table: predicate SQL} for rows owned by the organization, and the order to delete them.

    organizations.id = X is the root; a table is in the set if it has an
    org_id column or a foreign key to a table in the set. Predicates are
    built parents first; a foreign-key cycle between two tables is skipped
    on the second visit (reported), self-references are ignored."""
    tables = {t.name: t for t in meta.sorted_tables}
    if "organizations" not in tables:
        sys.exit("no organizations table")
    names = {"organizations"}
    changed = True
    while changed:
        changed = False
        for name, t in tables.items():
            if name in names:
                continue
            if "org_id" in t.c or any(fk.column.table.name in names for fk in t.foreign_keys
                                      if fk.column.table.name != name):
                names.add(name)
                changed = True

    memo, visiting, skipped = {"organizations": f"{_q('organizations')}.id = {int(org_id)}"}, set(), []

    def pred(name):
        if name in memo:
            return memo[name]
        visiting.add(name)
        t = tables[name]
        parts = [f"{_q(name)}.org_id = {int(org_id)}"] if "org_id" in t.c else []
        for fk in t.foreign_keys:
            parent = fk.column.table.name
            if parent == name or parent not in names:
                continue
            if parent in visiting:
                skipped.append(f"{name}.{fk.parent.name} -> {parent}")
                continue
            parts.append(f"{_q(name)}.{_q(fk.parent.name)} IN "
                         f"(SELECT {_q(fk.column.name)} FROM {_q(parent)} WHERE {pred(parent)})")
        visiting.discard(name)
        memo[name] = " OR ".join(f"({x})" for x in parts) if parts else "FALSE"
        return memo[name]

    owned = {n: pred(n) for n in names}
    order = [t.name for t in reversed(meta.sorted_tables) if t.name in names and t.name != "organizations"]
    if skipped:
        print("note: foreign-key cycles not followed: " + ", ".join(skipped))
    return owned, order


def _blockers(meta, owned):
    """Foreign keys from rows NOT being deleted to rows that are."""
    checks = []
    for t in meta.sorted_tables:
        for fk in t.foreign_keys:
            parent = fk.column.table.name
            if parent not in owned or t.name == parent:
                continue
            outside = f"NOT ({owned[t.name]})" if t.name in owned else "TRUE"
            checks.append((t.name, fk.parent.name, parent,
                           f"SELECT count(*) FROM {_q(t.name)} WHERE {_q(fk.parent.name)} IN "
                           f"(SELECT {_q(fk.column.name)} FROM {_q(parent)} WHERE {owned[parent]}) AND {outside}"))
    return checks


async def main(args) -> int:
    from sqlalchemy import MetaData, text

    from app.core.config import settings
    from app.core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        conn = await db.connection()
        meta = MetaData()
        await conn.run_sync(lambda c: meta.reflect(bind=c))

        org = (await db.execute(text("SELECT * FROM organizations WHERE id = :id"), {"id": args.org_id})).mappings().first()
        if not org:
            print(f"organization {args.org_id} does not exist")
            return 1
        status = org.get("status")
        active_users = (await db.execute(text(
            "SELECT count(*) FROM users WHERE org_id = :id AND status = 'active'"), {"id": args.org_id})).scalar_one()
        inactive = status in ("disabled", "deleted", "suspended") or (status is None and active_users == 0)
        print(f"organization {org['id']}: {org.get('name')!r} (slug {org.get('slug')!r}, "
              f"status {status!r}, active users {active_users})")
        if not inactive and not args.allow_active:
            print("refusing: the organization is not disabled. Disable it first, or pass --allow-active.")
            return 1

        owned, order = _plan(meta, args.org_id)
        counts = {}
        for name in order:
            counts[name] = (await db.execute(text(f"SELECT count(*) FROM {_q(name)} WHERE {owned[name]}"))).scalar_one()
        total = sum(counts.values())
        print(f"\nrows that belong to it ({total} in {sum(1 for v in counts.values() if v)} tables):")
        for name in order:
            if counts[name]:
                print(f"  {name:<40} {counts[name]:>8}")

        bad = []
        for child, col, parent, sql in _blockers(meta, owned):
            n = (await db.execute(text(sql))).scalar_one()
            if n:
                bad.append(f"  {child}.{col} -> {parent}: {n} row(s) of other organizations")
        if bad:
            print("\nrefusing: rows outside this organization refer to it:\n" + "\n".join(bad))
            return 1

        dirs = [getattr(settings, k, None) for k in ("DATASETS_DIR", "MODELS_DIR", "RAG_DOCUMENTS_DIR", "RAG_VECTORIZERS_DIR")]
        print("\nnot touched (check by hand if this organization uploaded files): " + ", ".join(d for d in dirs if d))

        if not args.execute:
            print("\ndry run - nothing deleted. Run again with --execute to delete.")
            await db.rollback()
            return 0

        if args.yes is not True:
            answer = input(f"\nDelete organization {org['id']} {org.get('name')!r} and {total} rows? Type its id to confirm: ")
            if answer.strip() != str(org["id"]):
                print("aborted")
                return 1
        deleted = defaultdict(int)
        for name in order:
            if counts[name]:
                r = await db.execute(text(f"DELETE FROM {_q(name)} WHERE {owned[name]}"))
                deleted[name] = r.rowcount or 0
        await db.execute(text("DELETE FROM organizations WHERE id = :id"), {"id": org["id"]})  # last: everything points at it
        await db.commit()
        print(f"deleted organization {org['id']} and {sum(deleted.values())} rows")
        return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Delete one organization and all of its data (dry run by default).")
    p.add_argument("--org-id", type=int, required=True)
    p.add_argument("--execute", action="store_true", help="really delete (otherwise only report)")
    p.add_argument("--allow-active", action="store_true", help="allow an organization that is not disabled")
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    sys.exit(asyncio.run(main(p.parse_args())))
