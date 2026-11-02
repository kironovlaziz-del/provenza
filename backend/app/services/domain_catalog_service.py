from dataclasses import dataclass
from typing import List, Optional

from fastapi import HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_domain_catalog import AIDomainCatalog
from app.schemas.domain_catalog import DomainCatalogCreate, DomainCatalogUpdate
from app.services.domain_catalog_seed import lookup_seed_hint


@dataclass
class DomainMatch:
    policy_status: str  # allowed, blocked, unknown
    tool_name: Optional[str]
    category: Optional[str]
    matched_catalog_id: Optional[int]


class DomainCatalogService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def import_seed(self, org_id: int) -> dict:
        """Add every known AI domain from the seed catalog that the org
        doesn't already have, as 'unknown' (needs review) - the org
        decides allow/block per domain. Existing domains are skipped."""
        from app.services.domain_catalog_seed import SEED_DOMAINS
        from app.models.ai_domain_catalog import AIDomainCatalog
        existing_res = await self.db.execute(
            select(AIDomainCatalog.domain).where(AIDomainCatalog.org_id == org_id)
        )
        existing = {row[0] for row in existing_res.all()}
        added = 0
        for seed in SEED_DOMAINS:
            if seed["domain"] in existing:
                continue
            self.db.add(AIDomainCatalog(
                org_id=org_id,
                domain=seed["domain"],
                tool_name=seed.get("tool_name"),
                category=seed.get("category"),
                policy_status="unknown",
                source="seed_import",
            ))
            added += 1
        await self.db.commit()
        return {"added": added, "skipped": len(SEED_DOMAINS) - added, "total_seed": len(SEED_DOMAINS)}

    async def create_entry(self, org_id: int, data: DomainCatalogCreate) -> AIDomainCatalog:
        entry = AIDomainCatalog(
            org_id=org_id,
            domain=data.domain,
            tool_name=data.tool_name,
            category=data.category,
            policy_status=data.policy_status,
            source="manual",
        )
        self.db.add(entry)
        try:
            await self.db.commit()
        except IntegrityError:
            await self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"'{data.domain}' is already in this organization's catalog.",
            )
        await self.db.refresh(entry)
        return entry

    async def list_entries(self, org_id: int) -> List[AIDomainCatalog]:
        """Unpaged - used internally by match_domain(), which needs the
        full catalog to check suffix matches, not a page of it."""
        result = await self.db.execute(
            select(AIDomainCatalog)
            .where(AIDomainCatalog.org_id == org_id)
            .order_by(AIDomainCatalog.domain)
        )
        return list(result.scalars().all())

    async def list_entries_page(
        self, org_id: int, skip: int = 0, limit: int = 50
    ) -> tuple[List[AIDomainCatalog], int]:
        base = select(AIDomainCatalog).where(AIDomainCatalog.org_id == org_id)
        total = await self.db.scalar(select(func.count()).select_from(base.subquery()))
        result = await self.db.execute(
            base.order_by(AIDomainCatalog.domain).offset(skip).limit(limit)
        )
        return list(result.scalars().all()), int(total or 0)

    async def _get(self, entry_id: int, org_id: int) -> AIDomainCatalog:
        result = await self.db.execute(
            select(AIDomainCatalog).where(
                AIDomainCatalog.id == entry_id, AIDomainCatalog.org_id == org_id
            )
        )
        entry = result.scalar_one_or_none()
        if not entry:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Domain catalog entry not found"
            )
        return entry

    async def update_entry(
        self, entry_id: int, org_id: int, data: DomainCatalogUpdate
    ) -> AIDomainCatalog:
        entry = await self._get(entry_id, org_id)
        for field, value in data.model_dump(exclude_unset=True).items():
            setattr(entry, field, value)
        await self.db.commit()
        await self.db.refresh(entry)
        return entry

    async def delete_entry(self, entry_id: int, org_id: int) -> None:
        entry = await self._get(entry_id, org_id)
        await self.db.delete(entry)
        await self.db.commit()

    async def match_domain(self, org_id: int, domain: str) -> DomainMatch:
        """
        Classify a domain against this org's catalog.

        Exact match wins over suffix match, and a more specific suffix
        (more labels) wins over a shorter one, so a catalog entry for
        "chat.openai.com" takes precedence over one for "openai.com" if
        both happen to exist.
        """
        domain = domain.strip().lower()
        entries = await self.list_entries(org_id)

        exact = next((e for e in entries if e.domain == domain), None)
        if exact:
            return DomainMatch(exact.policy_status, exact.tool_name, exact.category, exact.id)

        suffix_matches = [e for e in entries if domain.endswith("." + e.domain)]
        if suffix_matches:
            best = max(suffix_matches, key=lambda e: len(e.domain))
            return DomainMatch(best.policy_status, best.tool_name, best.category, best.id)

        seed_hint = lookup_seed_hint(domain)
        if seed_hint:
            return DomainMatch("unknown", seed_hint["tool_name"], seed_hint["category"], None)

        return DomainMatch("unknown", None, None, None)

    async def browser_catalog(self, org_id: int) -> dict:
        """What the organization's browser extension watches: every domain of
        the organization's catalog with its decision (allowed, blocked,
        unknown), and the built-in AI services it has not classified yet, as
        unknown. Blocked domains are closed in the browser; the allowed ones
        are offered instead. `version` changes whenever the list does."""
        import hashlib
        import json

        from app.services.domain_catalog_seed import browser_seed

        entries = [e for e in await self.list_entries(org_id) if "/" not in e.domain]
        own = {e.domain for e in entries}
        domains = [
            {"domain": e.domain, "name": e.tool_name or e.domain, "category": e.category or "",
             "status": e.policy_status}
            for e in entries
        ] + [
            {"domain": h["domain"], "name": h["tool_name"], "category": h["category"], "status": "unknown"}
            for h in browser_seed() if h["domain"] not in own
        ]
        domains.sort(key=lambda d: d["domain"])
        version = hashlib.sha256(json.dumps(domains, sort_keys=True).encode()).hexdigest()[:16]
        return {"version": version, "domains": domains}


    async def ai_domains(self, org_id: int) -> "AIDomainSet":
        """Every domain this organization's catalog or the built-in list knows
        as an AI service: what a DNS or proxy log is filtered by
        (app/services/log_import.py). API hosts count too - a program that
        calls an AI API is an AI use."""
        from app.services.domain_catalog_seed import SEED_DOMAINS

        own = {e.domain for e in await self.list_entries(org_id) if "/" not in e.domain}
        seed = {h["domain"] for h in SEED_DOMAINS if "/" not in h["domain"]}
        return AIDomainSet(own | seed)


class AIDomainSet:
    """A set of domains matched by host name or any parent domain:
    "chat.openai.com" is in a set that holds "openai.com"."""

    def __init__(self, domains):
        self.domains = {d.strip().lower().rstrip(".") for d in domains if d}

    def __call__(self, host: str) -> bool:
        labels = host.lower().rstrip(".").split(".")
        return any(".".join(labels[i:]) in self.domains for i in range(len(labels) - 1))
