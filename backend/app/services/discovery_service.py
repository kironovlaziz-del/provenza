from datetime import datetime, timezone
from typing import List, Optional, Tuple

from fastapi import HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.discovered_service import DiscoveredService
from app.models.service_connection import ServiceConnection
from app.schemas.discovery import (
    DiscoveredServiceIn,
    ServiceConnectRequest,
)
from app.core.errors import api_error
from app.services.discovery_connect_handlers import (
    CONNECT_HANDLERS,
    CREDENTIAL_SERVICE_TYPES,
    ServiceConnectError,
    verify_connection,
)


class DiscoveryService:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ---- ingestion from the discovery layer -------------------------------

    async def report_services(
        self, org_id: int, services: List[DiscoveredServiceIn], reported_by: Optional[str] = None
    ) -> Tuple[int, int]:
        """
        Upsert discovered services. Re-discovering the same
        (service_type, host) bumps last_seen_at and refreshes details
        rather than creating a duplicate - discovery runs repeatedly, and
        the admin cares about "what's on my network now", not a log of
        every scan. Returns (new_count, updated_count).

        Crucially this ONLY records observations - it never initiates any
        connection. connect_status stays "discovered" until an admin acts.

        Telemetry never moves a known service: the host+type pair is the
        identity, and a different port in a later report is recorded in
        details["reported_port"] instead of replacing the port an admin may
        already have connected (otherwise a collector key could downgrade a
        domain controller from 636 to a cleartext port).
        """
        new_count = 0
        updated_count = 0
        now = datetime.now(timezone.utc)

        for svc in services:
            result = await self.db.execute(
                select(DiscoveredService).where(
                    DiscoveredService.org_id == org_id,
                    DiscoveredService.service_type == svc.service_type,
                    DiscoveredService.host == svc.host,
                )
            )
            existing = result.scalar_one_or_none()

            if existing:
                existing.last_seen_at = now
                details = dict(svc.details or existing.details or {})
                if svc.port is not None and existing.port is None and existing.connect_status == "discovered":
                    existing.port = svc.port
                elif svc.port is not None and svc.port != existing.port:
                    details["reported_port"] = svc.port
                if reported_by:
                    details["reported_by"] = reported_by
                existing.details = details
                existing.discovered_via = svc.discovered_via
                updated_count += 1
            else:
                self.db.add(
                    DiscoveredService(
                        org_id=org_id,
                        service_type=svc.service_type,
                        host=svc.host,
                        port=svc.port,
                        discovered_via=svc.discovered_via,
                        details={**(svc.details or {}), **({"reported_by": reported_by} if reported_by else {})},
                        connect_status="discovered",
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                )
                new_count += 1

        await self.db.commit()
        return new_count, updated_count

    # ---- listing ----------------------------------------------------------

    async def list_services(
        self, org_id: int, status_filter: Optional[str] = None, skip: int = 0, limit: int = 100
    ) -> Tuple[List[DiscoveredService], int]:
        base = select(DiscoveredService).where(DiscoveredService.org_id == org_id)
        if status_filter:
            base = base.where(DiscoveredService.connect_status == status_filter)
        total = await self.db.scalar(select(func.count()).select_from(base.subquery()))
        result = await self.db.execute(
            base.order_by(DiscoveredService.last_seen_at.desc()).offset(skip).limit(limit)
        )
        return list(result.scalars().all()), int(total or 0)

    async def _get(self, service_id: int, org_id: int) -> DiscoveredService:
        result = await self.db.execute(
            select(DiscoveredService).where(
                DiscoveredService.id == service_id, DiscoveredService.org_id == org_id
            )
        )
        svc = result.scalar_one_or_none()
        if not svc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Discovered service not found"
            )
        return svc

    # ---- explicit connect / ignore ---------------------------------------

    async def ignore_service(
        self, service_id: int, org_id: int, reason: Optional[str]
    ) -> DiscoveredService:
        svc = await self._get(service_id, org_id)
        svc.connect_status = "ignored"
        if reason:
            svc.connect_error = None
            details = dict(svc.details or {})
            details["ignore_reason"] = reason
            svc.details = details
        await self.db.commit()
        await self.db.refresh(svc)
        return svc

    async def connect_service(
        self, service_id: int, org_id: int, connected_by: int, creds: ServiceConnectRequest
    ) -> DiscoveredService:
        """
        Attempt to connect ONE discovered service using credentials the
        admin explicitly supplied. This is the ONLY path that ever
        establishes a real connection to a discovered service - there is
        no anonymous/automatic attach anywhere in the system.

        The actual per-service connection logic (LDAP bind for AD, DNS
        reachability check) is delegated to a type-specific handler in
        discovery_connect_handlers.CONNECT_HANDLERS. A service type with
        no registered handler is marked "needs_credentials" with a clear
        message rather than pretending it worked.
        """
        svc = await self._get(service_id, org_id)

        # Credentials go only to the address the admin looked at: the
        # wizard echoes the host and port it displayed, and a record that
        # changed in between (or a client that did not confirm) is refused.
        if svc.service_type in CREDENTIAL_SERVICE_TYPES:
            if creds.expected_host is None:
                raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "discovery.confirm_target_required")
            if creds.expected_host != svc.host or creds.expected_port != svc.port:
                raise api_error(status.HTTP_409_CONFLICT, "discovery.target_changed")

        handler = CONNECT_HANDLERS.get(svc.service_type)
        if handler is None:
            svc.connect_status = "needs_credentials"
            svc.connect_error = (
                f"Connecting '{svc.service_type}' services is not supported yet. "
                "The credentials were not used or stored."
            )
            await self.db.commit()
            await self.db.refresh(svc)
            return svc

        # A handler exists: run it. Handlers must NEVER auto-connect on
        # their own - they only run because we reached here from an
        # explicit admin action with supplied credentials.
        try:
            ref_type, ref_id = await handler(self.db, org_id, svc, creds, connected_by)
            svc.connect_status = "connected"
            svc.connect_error = None
            svc.connected_ref_type = ref_type
            svc.connected_ref_id = ref_id
            svc.connected_by = connected_by
            svc.connected_at = datetime.now(timezone.utc)
        except ServiceConnectError as exc:
            svc.connect_status = "error"
            svc.connect_error = str(exc)[:500]

        await self.db.commit()
        await self.db.refresh(svc)
        return svc

    async def get_connection(self, service_id: int, org_id: int):
        """
        Return the ServiceConnection for a discovered service, or None if
        it has never been connected. Used by the UI to show connection
        details (bind DN, what the one-time read found, last verification
        time) without ever exposing the stored secret.
        """
        # Ensure the discovered service exists and belongs to this org.
        await self._get(service_id, org_id)
        result = await self.db.execute(
            select(ServiceConnection).where(
                ServiceConnection.discovered_service_id == service_id,
                ServiceConnection.org_id == org_id,
            )
        )
        return result.scalar_one_or_none()

    async def reverify_connection(self, service_id: int, org_id: int):
        """Re-check a single stored connection (manual 'Re-verify' button).
        Returns the updated ServiceConnection, or None if the service was
        never connected."""
        conn = await self.get_connection(service_id, org_id)
        if conn is None:
            return None
        await verify_connection(conn)
        await self.db.commit()
        await self.db.refresh(conn)
        return conn

    async def reverify_all(self):
        """Re-check EVERY stored connection across all orgs. Called by the
        scheduled Celery beat task. Commits once at the end. Returns a
        (checked, ok, failed) tuple for the task log."""
        result = await self.db.execute(select(ServiceConnection))
        conns = list(result.scalars().all())
        ok = 0
        for conn in conns:
            if await verify_connection(conn):
                ok += 1
        await self.db.commit()
        return len(conns), ok, len(conns) - ok
