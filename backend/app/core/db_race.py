# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Rows that are made on first use, by whoever needs them first.

Two requests can need the same row at the same moment - a page that asks
for two things at once, two sensors polling, two calls of one agent. Both
look, both find nothing, both insert; the unique constraint lets one in.
The loser must not fail (the row it wanted exists now), and must not roll
its whole transaction back either: a rollback unloads every row the
request holds, and the next attribute read of one of them fails the
request (that was "Could not load the inventory" until a reload).

insert_or_get() inserts inside a SAVEPOINT, so losing undoes only the
insert, and then returns the row that won.
"""

from typing import Any, Awaitable, Callable, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession


async def insert_or_get(db: AsyncSession, row: Any, existing: Callable[[], Awaitable[Any]]) -> Tuple[Any, bool]:
    """Insert `row` (flushed, not committed), or - when another transaction
    inserted its like first - return what `existing()` now finds.
    Returns (the row, whether this call created it)."""
    try:
        async with db.begin_nested():
            db.add(row)
            await db.flush()
        return row, True
    except IntegrityError:
        found = await existing()
        if found is None:       # not the row we raced for: another constraint, a real error
            raise
        return found, False
