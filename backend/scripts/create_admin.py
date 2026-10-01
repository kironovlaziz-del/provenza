# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Create the first organization and its administrator on a fresh install.

    docker compose run --rm -it backend create-admin \
        --org "Provenza" --email admin@provenza.example.com --name "Jane Admin"

The password is read from PROVENZA_ADMIN_PASSWORD when set, otherwise asked
for interactively (twice). It is never printed and has no default.
Idempotent: an existing e-mail is left untouched.
"""

import argparse
import asyncio
import getpass
import os
import re
import sys

MIN_PASSWORD = 12


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s[:50] or "org"


def _password() -> str:
    pw = os.environ.get("PROVENZA_ADMIN_PASSWORD")
    if pw is None:
        if not sys.stdin.isatty():
            sys.exit("No terminal: set PROVENZA_ADMIN_PASSWORD or run with `docker compose run --rm -it`.")
        pw = getpass.getpass("Admin password: ")
        if getpass.getpass("Repeat password: ") != pw:
            sys.exit("Passwords do not match.")
    if len(pw) < MIN_PASSWORD:
        sys.exit(f"Password must be at least {MIN_PASSWORD} characters.")
    return pw


async def main(args) -> int:
    from sqlalchemy import func, select

    from app.core.database import AsyncSessionLocal
    from app.core.security import get_password_hash
    from app.models.organization import Organization
    from app.models.user import User, UserRole

    email = args.email.strip().lower()
    async with AsyncSessionLocal() as db:
        if (await db.execute(select(User).where(func.lower(User.email) == email))).scalar_one_or_none():
            print(f"A user with e-mail {email} already exists - nothing changed.")
            return 0
        password = _password()
        slug = args.slug or _slug(args.org)
        org = (await db.execute(select(Organization).where(Organization.slug == slug))).scalar_one_or_none()
        if org is None:
            org = Organization(name=args.org, slug=slug)
            db.add(org)
            await db.flush()
            print(f"Created organization '{args.org}' (slug {slug}, id {org.id}).")
        else:
            print(f"Using existing organization '{org.name}' (id {org.id}).")
        db.add(User(org_id=org.id, email=email, name=args.name, hashed_password=get_password_hash(password),
                    role=UserRole.admin.value, status="active"))
        await db.commit()
        print(f"Created administrator {email}. Sign in at your Provenza URL.")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Create the first organization and administrator.")
    p.add_argument("--org", required=True, help="organization name")
    p.add_argument("--slug", help="organization slug (default: derived from the name)")
    p.add_argument("--email", required=True, help="administrator e-mail")
    p.add_argument("--name", default="Administrator", help="administrator display name")
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.exit(asyncio.run(main(p.parse_args())))
