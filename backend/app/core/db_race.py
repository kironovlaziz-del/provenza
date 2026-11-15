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

from sqlalchemy.exc import IntegrityError, InvalidRequestError
from sqlalchemy.ext.asyncio import AsyncSession


async def insert_or_get(db: AsyncSession, row: Any, existing: Callable[[], Awaitable[Any]]) -> Tuple[Any, bool]:
    """Insert `row` (flushed, not committed), or - when another transaction
    inserted its like first - return what `existing()` now finds.
    Returns (the row, whether this call created it)."""
    # A SAVEPOINT held by hand, not `async with`: where one session serves
    # several requests in turn (the test suite does this), another request's
    # commit can land between our insert and the end of the block. The
    # savepoint is then already released with that commit - our row went in
    # with it - and there is nothing left to release or undo.
    savepoint = await db.begin_nested()
    try:
        db.add(row)
        await db.flush()
    except IntegrityError:
        try:
            await savepoint.rollback()      # undoes the insert only
        except InvalidRequestError:
            pass                            # already closed (see above)
        found = await existing()
        if found is None:       # not the row we raced for: another constraint, a real error
            raise
        return found, False
    if savepoint.is_active:
        await savepoint.commit()
    return row, True
