from pydantic import BaseModel, field_validator
from datetime import datetime
from typing import Optional, Dict, Any, List

# The wire format below matches what the actual Go endpoint agent and
# browser extension send (see agent/reporters/api.go's TelemetryEvent
# struct and extension/background/service-worker.js's sendBatch) -
# these are real, already-deployed producers, not something designed in
# isolation, so the schema follows them rather than the other way
# around.
DOMAIN_EVENT_TYPE = "domain_visit"
LOCAL_SIGNAL_EVENT_TYPES = {"process_detected", "network_conn", "local_model_found"}
# An AI agent product found running (endpoint agent >= 1.2.0); payload
# {"product": "<catalog id>", "process_name", "matched_by"}.
AGENT_EVENT_TYPE = "agent_detected"
KNOWN_EVENT_TYPES = {DOMAIN_EVENT_TYPE, AGENT_EVENT_TYPE} | LOCAL_SIGNAL_EVENT_TYPES


class TelemetryEventIn(BaseModel):
    event_id: Optional[str] = None
    event_type: str
    agent_id: Optional[str] = None
    # Real hostname for "domain_visit" (from the browser extension);
    # a fixed placeholder ("localhost", "local_filesystem", etc.) for the
    # three local-signal types, which describe something running or
    # stored ON the endpoint rather than an outbound domain - those
    # placeholders are never looked up in the domain catalog, only used
    # for display, so they don't need the same validation a real
    # candidate-for-blocking domain would.
    domain: Optional[str] = None
    user_id: Optional[str] = None
    risk_score: Optional[float] = None
    action_taken: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    timestamp: Optional[datetime] = None

    @field_validator("domain")
    @classmethod
    def normalize_domain(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip().lower()
        return v or None


class TelemetryIngestRequest(BaseModel):
    events: List[TelemetryEventIn]

    @field_validator("events")
    @classmethod
    def non_empty_and_bounded(cls, v: List[TelemetryEventIn]) -> List[TelemetryEventIn]:
        if not v:
            raise ValueError("events must not be empty")
        if len(v) > 500:
            raise ValueError("a single batch cannot exceed 500 events")
        return v


class TelemetryIngestResponse(BaseModel):
    received: int
    allowed: int
    unknown: int
    blocked: int
    local_signals: int
    sightings_created: int
    incidents_created: int
    agents_found: int = 0
    devices_seen: int = 0


class TelemetryIngestAcceptedResponse(BaseModel):
    """
    Returned immediately by POST /shadow-ai/ingest (202) once the batch
    is handed off to a Celery worker - actual classification/sighting/
    incident counts are not known yet at this point, only that the
    batch was accepted for processing. See telemetry_tasks.py.
    """

    status: str = "accepted"
    received: int
    task_id: str
