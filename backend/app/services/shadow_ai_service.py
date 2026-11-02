from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from fastapi import HTTPException, status
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone
from app.models.shadow_ai_sighting import ShadowAISighting
from app.models.ai_provider import AIProvider
from app.schemas.shadow_ai import (
    ShadowSightingCreate,
    ShadowSightingUpdate,
    ShadowSightingRegister,
)


class ShadowAIService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_sighting(
        self, org_id: int, reported_by: int, data: ShadowSightingCreate
    ) -> ShadowAISighting:
        now = datetime.now(timezone.utc)
        sighting = ShadowAISighting(
            org_id=org_id,
            tool_name=data.tool_name,
            domain=data.domain,
            detected_via=data.detected_via,
            user_hint=data.user_hint,
            notes=data.notes,
            display_meta=data.display_meta,
            status="new",
            reported_by=reported_by,
            seen_count=1,
            last_seen_at=now,
        )
        self.db.add(sighting)
        await self.db.commit()
        await self.db.refresh(sighting)
        return sighting

    async def record_repeat_sighting(self, sighting: ShadowAISighting) -> ShadowAISighting:
        """
        Called by the telemetry pipeline when a re-observation matches an
        already-open sighting: instead of creating a duplicate (or doing
        nothing and losing the signal), bump the counter and timestamp so
        the UI can distinguish "seen once, days ago" from "seen 200 times,
        still happening now". Deliberately does NOT commit - the caller
        (TelemetryService) owns the transaction and commits the whole
        batch at once.
        """
        sighting.seen_count = (sighting.seen_count or 1) + 1
        sighting.last_seen_at = datetime.now(timezone.utc)
        self.db.add(sighting)
        return sighting

    async def list_sightings(
        self,
        org_id: int,
        status_filter: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> "tuple[List[ShadowAISighting], int]":
        from sqlalchemy import func

        base = select(ShadowAISighting).where(ShadowAISighting.org_id == org_id)
        if status_filter:
            base = base.where(ShadowAISighting.status == status_filter)
        total = await self.db.scalar(
            select(func.count()).select_from(base.subquery())
        )
        result = await self.db.execute(
            base.order_by(ShadowAISighting.created_at.desc()).offset(skip).limit(limit)
        )
        return list(result.scalars().all()), int(total or 0)

    async def _get(self, sighting_id: int, org_id: int) -> ShadowAISighting:
        result = await self.db.execute(
            select(ShadowAISighting).where(
                ShadowAISighting.id == sighting_id,
                ShadowAISighting.org_id == org_id,
            )
        )
        sighting = result.scalar_one_or_none()
        if not sighting:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Shadow AI sighting not found",
            )
        return sighting

    async def update_status(
        self, sighting_id: int, org_id: int, data: ShadowSightingUpdate
    ) -> ShadowAISighting:
        sighting = await self._get(sighting_id, org_id)
        if data.status is not None:
            sighting.status = data.status
            if data.status in ("dismissed", "confirmed_shadow"):
                sighting.resolved_at = datetime.now(timezone.utc)
        if data.notes is not None:
            sighting.notes = data.notes
        await self.db.commit()
        await self.db.refresh(sighting)
        return sighting

    async def register_as_provider(
        self, sighting_id: int, org_id: int, data: ShadowSightingRegister
    ) -> ShadowAISighting:
        sighting = await self._get(sighting_id, org_id)
        if sighting.status == "registered":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This sighting has already been registered as a provider.",
            )

        provider = AIProvider(
            org_id=org_id,
            name=sighting.tool_name,
            type=data.provider_type,
            status="active",
            sla=data.provider_sla,
            risk_score=0.0,
        )
        self.db.add(provider)
        await self.db.flush()

        sighting.status = "registered"
        sighting.registered_provider_id = provider.id
        sighting.resolved_at = datetime.now(timezone.utc)

        await self.db.commit()
        await self.db.refresh(sighting)
        return sighting

    async def summary_counts(self, org_id: int) -> dict:
        result = await self.db.execute(
            select(ShadowAISighting.status, func.count(ShadowAISighting.id))
            .where(ShadowAISighting.org_id == org_id)
            .group_by(ShadowAISighting.status)
        )
        return {row[0]: row[1] for row in result.all()}

    async def find_open_sighting_by_domain(
        self, org_id: int, domain: str
    ) -> Optional[ShadowAISighting]:
        """
        Used by the telemetry ingestion pipeline to avoid creating a new
        sighting (and re-notifying) for every single repeat event against
        a domain that already has an unresolved sighting open.
        """
        result = await self.db.execute(
            select(ShadowAISighting).where(
                ShadowAISighting.org_id == org_id,
                ShadowAISighting.domain == domain,
                ShadowAISighting.status.in_(["new", "reviewing", "confirmed_shadow"]),
            )
        )
        return result.scalars().first()



    # ------------------------------------------------------------ people
    # Who visited a domain sighting's AI service, read from the raw visits
    # (ai_telemetry_events, kept as long as Settings -> Data retention says).
    # user_hint is what the browser reported - the organization sets it by
    # policy for its extensions (userEmail); a browser without it counts as
    # one unidentified browser (its install id).

    @staticmethod
    def _visit_domain(sighting: ShadowAISighting) -> Optional[str]:
        meta = sighting.display_meta or {}
        if meta.get("kind") == "domain" and sighting.domain:
            return sighting.domain
        return None

    async def people_counts(self, org_id: int, sightings: List[ShadowAISighting]) -> Dict[str, Tuple[int, int]]:
        """domain -> (identified people, unidentified browsers) for these sightings."""
        from sqlalchemy import case, distinct, func

        from app.models.ai_telemetry_event import AITelemetryEvent
        from app.schemas.telemetry import DOMAIN_EVENT_TYPE

        domains = sorted({d for d in (self._visit_domain(s) for s in sightings) if d})
        if not domains:
            return {}
        E = AITelemetryEvent
        rows = await self.db.execute(
            select(
                E.domain,
                func.count(distinct(E.user_hint)),
                func.count(distinct(case((E.user_hint.is_(None), E.agent_id)))),
            )
            .where(E.org_id == org_id, E.event_type == DOMAIN_EVENT_TYPE, E.domain.in_(domains))
            .group_by(E.domain)
        )
        return {d: (int(p or 0), int(b or 0)) for d, p, b in rows.all()}

    async def people(self, org_id: int, sighting_id: int) -> dict:
        from sqlalchemy import Integer, case, distinct, func

        from app.models.ai_telemetry_event import AITelemetryEvent
        from app.schemas.telemetry import DOMAIN_EVENT_TYPE

        sighting = await self._get(sighting_id, org_id)
        domain = self._visit_domain(sighting)
        out = {"people": [], "unidentified_browsers": 0, "unidentified_visits": 0}
        if not domain:
            return out
        E = AITelemetryEvent
        visits = (E.org_id == org_id, E.event_type == DOMAIN_EVENT_TYPE, E.domain == domain)
        # a browser reports each visit; a DNS or proxy log import one event
        # per person and computer with how many lines it stands for (hits)
        hits = func.coalesce(E.metadata_json["hits"].astext.cast(Integer), 1)
        blocked = func.coalesce(
            E.metadata_json["blocked_hits"].astext.cast(Integer),
            case((E.action_taken == "blocked", 1), else_=0),
        )
        rows = await self.db.execute(
            select(
                E.user_hint,
                func.sum(hits),
                func.sum(blocked),
                func.max(E.occurred_at),
            )
            .where(*visits, E.user_hint.is_not(None))
            .group_by(E.user_hint)
            .order_by(func.max(E.occurred_at).desc())
            .limit(500)
        )
        out["people"] = [
            {"user": u, "visits": int(n), "blocked": int(b), "last_seen_at": last} for u, n, b, last in rows.all()
        ]
        browsers, anon = (await self.db.execute(
            select(func.count(distinct(E.agent_id)), func.sum(hits)).where(*visits, E.user_hint.is_(None))
        )).one()
        out["unidentified_browsers"], out["unidentified_visits"] = int(browsers or 0), int(anon or 0)
        return out
