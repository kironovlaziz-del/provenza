import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy import func, literal_column
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_telemetry_event import AITelemetryEvent
from app.models.endpoint_device import DiscoveredAgent, EndpointDevice
from app.schemas.incident import IncidentCreate
from app.schemas.shadow_ai import ShadowSightingCreate
from app.schemas.telemetry import (
    AGENT_EVENT_TYPE,
    DOMAIN_EVENT_TYPE,
    LOCAL_SIGNAL_EVENT_TYPES,
    TelemetryEventIn,
    TelemetryIngestResponse,
)
from app.services import notification_service
from app.services.agent_catalog import AGENT_PRODUCTS, describe as describe_agent, is_custom
from app.services.domain_catalog_service import DomainCatalogService
from app.services.incident_service import IncidentService
from app.services.shadow_ai_service import ShadowAIService


_PRODUCT_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,59}")
_MAX_AGENT_NOTIFICATIONS = 5
# Never stored, whatever an (older) collector sends: a process command line
# can carry API keys and tokens.
_DROPPED_PAYLOAD_KEYS = ("cmdline", "command_line", "argv", "env")


def _host_id(event: TelemetryEventIn) -> str:
    """The reporting device as it names itself, without control characters."""
    raw = re.sub(r"[\x00-\x1f\x7f]+", " ", event.agent_id or "")
    return _clip(raw, 255) or "unknown"


def _clip(value, limit: int) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text[:limit] or None


def _one_line(text: str) -> str:
    """No line breaks in a value that goes into a mail subject."""
    return re.sub(r"[\r\n\t]+", " ", text)[:120]


_HOST = re.compile(r"[a-z0-9][a-z0-9.-]{0,99}")
_ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_SDK = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")


def _str_list(value, pattern: re.Pattern, limit: int) -> List[str]:
    if not isinstance(value, list):
        return []
    out = [v for v in value if isinstance(v, str) and pattern.fullmatch(v)]
    return sorted(set(out))[:limit]


def _behavior_evidence(payload: dict) -> dict:
    """Signals of an agent found by behavior (endpoint agent >= 1.3.0):
    which LLM APIs it talks to, which key variable NAMES it has, which SDKs
    are loaded, and how sure the collector is. Anything else is dropped."""
    if payload.get("matched_by") != "behavior":
        return {}
    conf = payload.get("confidence")
    return {
        "confidence": conf if conf in ("high", "medium") else None,
        "api_hosts": _str_list(payload.get("api_hosts"), _HOST, 10),
        "env_keys": _str_list(payload.get("env_keys"), _ENV_NAME, 10),
        "sdks": _str_list(payload.get("sdks"), _SDK, 5),
    }


def _safe_payload(payload: Optional[dict]) -> Optional[dict]:
    if not payload:
        return payload
    return {k: v for k, v in payload.items() if k not in _DROPPED_PAYLOAD_KEYS}


class TelemetryService:
    """
    Shadow AI Monitor ingestion pipeline for the real, already-deployed
    producers: the Go endpoint agent (agent/) and the browser extension
    (extension/). Two genuinely different kinds of signal arrive on the
    same batch endpoint:

    1. "domain_visit" (from the browser extension today; a future
       network-level collector could add more) - a real outbound domain,
       classified against the org's domain catalog exactly as designed
       in Shadow AI Monitor stage 1: blocked -> sighting + incident,
       unknown -> sighting, allowed -> logged only.

    2. "process_detected" / "network_conn" / "local_model_found" (from
       the endpoint agent) - a local AI tool was found running or
       installed on one specific machine. There is no domain to classify
       here (domain_catalog has no concept of "is Ollama allowed"), so
       these always raise a sighting - but see the per-agent dedup note
       on _local_signal_identity below, since collapsing these across
       different people's machines the way domain dedup works would
       hide exactly the fact that matters (how many people are running
       this, not just whether anyone is).

    3. "agent_detected" (endpoint agent >= 1.2.0) - an AI agent product
       (Claude Code, Cursor, CrewAI, ...) found running; recorded per
       device in discovered_agents for review in Discovery -> Agents Found.

    Every event also refreshes its device (endpoint_devices), so the list
    of reporting machines keeps itself current.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.catalog = DomainCatalogService(db)
        self.shadow_ai = ShadowAIService(db)
        self.incidents = IncidentService(db)

    async def ingest_events(
        self, org_id: int, ingestion_source_id: int, events: List[TelemetryEventIn]
    ) -> TelemetryIngestResponse:
        counts = {"allowed": 0, "unknown": 0, "blocked": 0}
        local_signals = 0
        sightings_created = 0
        incidents_created = 0
        agents_found = 0
        new_agents: List[dict] = []

        devices = await self._upsert_devices(org_id, ingestion_source_id, events)

        for event in events:
            if event.event_type == AGENT_EVENT_TYPE:
                self._log_raw_event(org_id, ingestion_source_id, event, matched_policy_status=None)
                found = await self._handle_agent_detected(org_id, devices[_host_id(event)], event)
                if found:
                    agents_found += 1
                    new_agents.append(found)
            elif event.event_type == DOMAIN_EVENT_TYPE:
                policy_status, sighting_delta, incident_delta = await self._handle_domain_visit(
                    org_id, ingestion_source_id, event
                )
                counts[policy_status] += 1
                sightings_created += sighting_delta
                incidents_created += incident_delta
            elif event.event_type in LOCAL_SIGNAL_EVENT_TYPES:
                local_signals += 1
                sightings_created += await self._handle_local_signal(
                    org_id, ingestion_source_id, event
                )
            else:
                # An event_type we don't recognize yet (a newer agent
                # version, or a typo) is still logged for the record,
                # just not acted on - better than silently dropping it
                # or rejecting the whole batch over one unknown type.
                self._log_raw_event(org_id, ingestion_source_id, event, matched_policy_status=None)

        await self.db.commit()
        await self._notify_new_agents(org_id, new_agents)

        return TelemetryIngestResponse(
            received=len(events),
            allowed=counts["allowed"],
            unknown=counts["unknown"],
            blocked=counts["blocked"],
            local_signals=local_signals,
            sightings_created=sightings_created,
            incidents_created=incidents_created,
            agents_found=agents_found,
            devices_seen=len(devices),
        )

    def _log_raw_event(
        self,
        org_id: int,
        ingestion_source_id: int,
        event: TelemetryEventIn,
        matched_policy_status: Optional[str],
    ) -> None:
        self.db.add(
            AITelemetryEvent(
                org_id=org_id,
                ingestion_source_id=ingestion_source_id,
                event_type=event.event_type,
                domain=event.domain,
                agent_id=event.agent_id,
                user_hint=event.user_id,
                risk_score=event.risk_score,
                action_taken=event.action_taken,
                occurred_at=event.timestamp or datetime.now(timezone.utc),
                matched_policy_status=matched_policy_status,
                metadata_json=_safe_payload(event.payload),
            )
        )

    # ------------------------------------------------------------ devices / agents
    async def _upsert_devices(
        self, org_id: int, ingestion_source_id: int, events: List[TelemetryEventIn]
    ) -> Dict[str, int]:
        """One row per reporting device (host_id), refreshed on every batch.
        INSERT ... ON CONFLICT, so concurrent workers never race into a
        duplicate. Returns {host_id: device_id}."""
        per_host: Dict[str, dict] = {}
        for e in events:
            payload = e.payload or {}
            row = per_host.setdefault(_host_id(e), {"events": 0, "user": None, "os": None, "version": None})
            row["events"] += 1
            row["user"] = _clip(e.user_id, 255) or row["user"]
            row["os"] = _clip(payload.get("os"), 30) or row["os"]
            row["version"] = _clip(payload.get("agent_version"), 30) or row["version"]

        ids: Dict[str, int] = {}
        # sorted: concurrent batches lock device rows in the same order (no deadlock)
        for host in sorted(per_host):
            row = per_host[host]
            stmt = pg_insert(EndpointDevice).values(
                org_id=org_id, ingestion_source_id=ingestion_source_id, host_id=host,
                last_user=row["user"], os=row["os"], agent_version=row["version"], event_count=row["events"],
            )
            ex = stmt.excluded
            stmt = stmt.on_conflict_do_update(
                constraint="uq_endpoint_devices_host",
                set_={
                    "last_seen_at": func.now(),
                    "event_count": EndpointDevice.event_count + ex.event_count,
                    "last_user": func.coalesce(ex.last_user, EndpointDevice.last_user),
                    "os": func.coalesce(ex.os, EndpointDevice.os),
                    "agent_version": func.coalesce(ex.agent_version, EndpointDevice.agent_version),
                },
            ).returning(EndpointDevice.id)
            ids[host] = (await self.db.execute(stmt)).scalar_one()
        return ids

    async def _handle_agent_detected(self, org_id: int, device_id: int, event: TelemetryEventIn) -> Optional[dict]:
        """Record an AI agent found on a device. Returns it when it is new."""
        payload = event.payload or {}
        product = str(payload.get("product") or "").strip().lower()
        if not _PRODUCT_ID.fullmatch(product):
            return None  # malformed or missing id: the raw event is logged, nothing else
        evidence = {
            "process_name": _clip(payload.get("process_name"), 255),
            "matched_by": _clip(payload.get("matched_by"), 20),
            **_behavior_evidence(payload),
        }
        stmt = pg_insert(DiscoveredAgent).values(
            org_id=org_id, device_id=device_id, product=product, risk_score=event.risk_score, evidence=evidence,
        )
        stmt = stmt.on_conflict_do_update(
            constraint="uq_discovered_agents_device_product",
            set_={
                "last_seen_at": func.now(),
                "seen_count": DiscoveredAgent.seen_count + 1,
                "evidence": stmt.excluded.evidence,
                "risk_score": func.coalesce(stmt.excluded.risk_score, DiscoveredAgent.risk_score),
            },
        ).returning(DiscoveredAgent.id, literal_column("(xmax = 0)").label("inserted"))
        found_id, inserted = (await self.db.execute(stmt)).one()
        if not inserted:
            return None
        return {"id": found_id, "product": product, "host": _host_id(event)}

    async def _notify_new_agents(self, org_id: int, new_agents: List[dict]) -> None:
        """After the batch is committed: one message per new finding of a
        known product, or a single summary when a batch brings many (a
        rollout to a fleet must not flood the channels). Unknown product ids
        are recorded but do not notify - an ingestion key alone should not
        be able to send arbitrary text to every channel."""
        known = [a for a in new_agents if a["product"] in AGENT_PRODUCTS or is_custom(a["product"])]
        if not known:
            return
        if len(known) > _MAX_AGENT_NOTIFICATIONS:
            hosts = sorted({a["host"] for a in known})
            await notification_service.notify(
                self.db, org_id, "agent_discovered",
                f"{len(known)} AI agents found on {len(hosts)} devices",
                "Found automatically by the endpoint agent. Review them in Discovery -> Agents Found.",
                {"count": len(known), "devices": len(hosts)},
            )
            return
        for a in known:
            name = describe_agent(a["product"])["name"]
            host = _one_line(a["host"])
            kind = "Unrecognized AI agent" if is_custom(a["product"]) else "AI agent"
            await notification_service.notify(
                self.db, org_id, "agent_discovered",
                f"{kind} found: {name} on {host}",
                "Found automatically by the endpoint agent. Register it to put it under "
                "policies, or ignore it, in Discovery -> Agents Found.",
                {"discovered_agent_id": a["id"], "product": a["product"], "device": host},
            )

    async def _handle_domain_visit(
        self, org_id: int, ingestion_source_id: int, event: TelemetryEventIn
    ) -> Tuple[str, int, int]:
        domain = event.domain or "unknown"
        match = await self.catalog.match_domain(org_id, domain)
        self._log_raw_event(org_id, ingestion_source_id, event, matched_policy_status=match.policy_status)

        if match.policy_status == "allowed":
            return "allowed", 0, 0

        existing = await self.shadow_ai.find_open_sighting_by_domain(org_id, domain)
        if existing:
            # Already flagged and still unresolved - the raw event is
            # still logged above, but instead of a new sighting we bump
            # the repeat counter so the UI shows it's ongoing.
            await self.shadow_ai.record_repeat_sighting(existing)
            return match.policy_status, 0, 0

        # A payload-supplied tool_name (the extension already knows this
        # from its own domain catalog) beats the org catalog's hint,
        # which in turn beats the bare domain string.
        payload = event.payload or {}
        payload_tool_name = payload.get("tool_name")
        display_meta = {
            "kind": "domain",
            "domain": domain,
            "category": payload.get("category") or match.category,
            "url": payload.get("url"),
            "agent_id": event.agent_id,
        }
        sighting = await self.shadow_ai.create_sighting(
            org_id,
            reported_by=None,
            data=ShadowSightingCreate(
                tool_name=payload_tool_name or match.tool_name or domain,
                domain=domain,
                detected_via=event.event_type,
                user_hint=event.user_id,
                display_meta=display_meta,
                notes=(
                    f"Auto-detected via telemetry ingestion "
                    f"(category: {payload.get('category') or match.category or 'unclassified'})."
                ),
            ),
        )

        if match.policy_status == "blocked":
            incident = await self.incidents.create_incident(
                org_id,
                IncidentCreate(
                    severity="high",
                    category="shadow_ai",
                    summary=(
                        f"Blocked AI domain detected: {domain}"
                        + (f" (user: {event.user_id})" if event.user_id else "")
                    ),
                    impact=(
                        "Traffic to a domain explicitly marked 'blocked' in this "
                        "organization's AI domain catalog was observed."
                    ),
                ),
            )
            await notification_service.notify(
                self.db,
                org_id,
                "shadow_ai_blocked_domain",
                f"Blocked AI domain detected: {domain}",
                f"Incident #{incident.id} was created automatically. "
                f"Sighting #{sighting.id} in Shadow AI Monitor.",
                {"sighting_id": sighting.id, "incident_id": incident.id},
            )
            return "blocked", 1, 1

        await notification_service.notify(
            self.db,
            org_id,
            "shadow_ai_reported",
            f"Unsanctioned AI usage detected: {sighting.tool_name}",
            f"Detected automatically via {event.event_type}. "
            f"Needs review in Shadow AI Monitor.",
            {"sighting_id": sighting.id},
        )
        return "unknown", 1, 0

    @staticmethod
    def _local_signal_identity(event: TelemetryEventIn) -> Tuple[str, str]:
        """
        Returns (dedup_key, tool_name). The dedup key is stored in
        ShadowAISighting.domain (reusing the existing dedup mechanism
        rather than inventing a parallel one) and is deliberately scoped
        per agent_id: two different people independently running Ollama
        are two separate facts worth knowing, not one. Domain-visit
        dedup is intentionally org-wide instead (see _handle_domain_visit)
        because that's about a policy violation existing at all, not
        about who specifically triggered it.
        """
        payload = event.payload or {}
        agent = event.agent_id or "unknown-agent"

        if event.event_type == "process_detected":
            name = payload.get("process_name") or payload.get("ai_tool") or "unknown-process"
            return f"local:{agent}:process:{name}", payload.get("ai_tool") or name

        if event.event_type == "network_conn":
            port = payload.get("port", "unknown-port")
            service = payload.get("service") or f"port {port}"
            return f"local:{agent}:port:{port}", service

        # local_model_found
        path = payload.get("file_path") or "unknown-file"
        name = payload.get("file_name") or path
        key = f"local:{agent}:model:{path}"
        # Column is String(255); a long absolute path could overflow it,
        # so fall back to just the filename for the dedup key in that
        # case - collisions across identically-named files in different
        # directories on the same machine are an acceptable trade for
        # never hitting a DB length error on a legitimate long path.
        if len(key) > 255:
            key = f"local:{agent}:model:{name}"[:255]
        return key, name

    @staticmethod
    def _local_display_meta(event: TelemetryEventIn) -> dict:
        """Human-readable specifics the UI can render, extracted per
        event type from the collector's payload (see the Go agent's
        collectors/*.go). Kept separate from the raw dedup key so the
        UI never has to show 'local:host:port:8000' to a person."""
        payload = event.payload or {}
        base = {"agent_id": event.agent_id}
        if event.event_type == "process_detected":
            return {
                **base,
                "kind": "process",
                "process_name": payload.get("process_name"),
                "pid": payload.get("pid"),
                "ai_tool": payload.get("ai_tool"),
            }
        if event.event_type == "network_conn":
            return {
                **base,
                "kind": "network",
                "port": payload.get("port"),
                "service": payload.get("service"),
                "target_host": payload.get("target_host"),
            }
        # local_model_found
        return {
            **base,
            "kind": "model_file",
            "file_name": payload.get("file_name"),
            "file_path": payload.get("file_path"),
            "size_mb": payload.get("size_mb"),
            "extension": payload.get("extension"),
        }

    async def _handle_local_signal(
        self, org_id: int, ingestion_source_id: int, event: TelemetryEventIn
    ) -> int:
        self._log_raw_event(org_id, ingestion_source_id, event, matched_policy_status=None)

        dedup_key, tool_name = self._local_signal_identity(event)
        existing = await self.shadow_ai.find_open_sighting_by_domain(org_id, dedup_key)
        if existing:
            await self.shadow_ai.record_repeat_sighting(existing)
            return 0

        sighting = await self.shadow_ai.create_sighting(
            org_id,
            reported_by=None,
            data=ShadowSightingCreate(
                tool_name=tool_name,
                domain=dedup_key,
                detected_via=event.event_type,
                user_hint=event.user_id,
                display_meta=self._local_display_meta(event),
                notes=f"Auto-detected on endpoint '{event.agent_id or 'unknown'}' via {event.event_type}.",
            ),
        )
        await notification_service.notify(
            self.db,
            org_id,
            "shadow_ai_reported",
            f"Local AI tool detected: {sighting.tool_name}",
            f"Found on device '{event.agent_id or 'unknown'}' via {event.event_type}. "
            f"Needs review in Shadow AI Monitor.",
            {"sighting_id": sighting.id},
        )
        return 1
