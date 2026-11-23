# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
PVP decisions as OpenTelemetry log records (docs/opentelemetry.md).

What goes out
  Every event the live view shows (app/core/obs_hooks.py) - a policy check, a
  recorded action, an LLM gateway call, a delegation hop, an incident - as
  one OTLP log record with an event name (pvp.action.checked, ...). Metadata
  only, exactly as the live view: ids, tool or model name, verdict, the
  OWASP codes found in the reason, tokens, duration. Never arguments,
  prompts, outputs, the free-text reason or incident details.

  Attributes are PVP's own (pvp.*), so the protocol is named in every
  record, plus the OpenTelemetry GenAI semantic conventions where one fits
  (gen_ai.agent.id, gen_ai.tool.name, gen_ai.operation.name,
  gen_ai.request.model, gen_ai.usage.*), so dashboards that know those
  read the records as they are. When the agent sent a W3C trace context
  (app/core/trace_context.py) the record carries its trace and span ids:
  the decision shows inside the agent's own trace.

  Logs, not spans: Provenza decides about an action at one moment; it does
  not run it. Span events are not used either - OpenTelemetry deprecates
  them in favour of log-based events.

How
  OTLP/HTTP with JSON encoding (the protobuf JSON mapping), POSTed to the
  collector the administrator names - an OpenTelemetry Collector, or any
  backend that takes OTLP/HTTP. The database is the source: every 30 seconds
  a worker reads what is new since its cursor (rows at least LAG_SECONDS
  old, so a transaction still open is not skipped), sends it and moves the
  cursor only when the collector took it. A collector that is down or
  refusing keeps the events waiting; a request the collector calls malformed
  (400) or too large (413) is dropped, as the OTLP specification says, and
  noted. An export starts from the moment it is switched on: the past is not
  replayed.

  The endpoint is outbound traffic to the host it names, through the
  server's SSRF-guarded client (app/core/outbound.py): HTTPS, or plain HTTP
  only to a host the operator lists in OUTBOUND_PRIVATE_ALLOWLIST. One
  optional header (Authorization, x-honeycomb-team, DD-API-KEY, ...) is
  stored encrypted and never shown again.

This copy is for monitoring. The record of what happened is the signed audit
log and the PVP receipts; nothing here is signed.
"""

import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from fastapi import status
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from app.core import obs_hooks
from app.core.config import settings
from app.core.crypto import decrypt_secret, encrypt_secret
from app.core.errors import api_error
from app.core.outbound import _allowlist, guarded_async_client, validate_url
from app.models.agent import Agent
from app.models.agent_action import ActionCheck, AgentAction, AgentIncident
from app.models.delegation import DelegationHop
from app.models.gateway import GatewayCall
from app.models.otel_export import OtelExportSettings

LOGS_PATH = "/v1/logs"
SCOPE_NAME = "provenza.pvp"
SCOPE_VERSION = "1"
LAG_SECONDS = 15
BATCH = 200                 # rows of one kind per request
MAX_ROUNDS = 5              # requests per organization per run
TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 64 * 1024
# pg_try_advisory_xact_lock(LOCK_KEY, org_id): one exporter per organization at a time.
# "PVZO", beside audit_chain's "PVZA" / "PVZC" and the sealer's "PVZS".
LOCK_KEY = 0x50565A4F

# kind -> model; the order the records are sent in
SOURCES: Tuple[Tuple[str, Any], ...] = (
    ("action.checked", ActionCheck),
    ("action.recorded", AgentAction),
    ("llm.call", GatewayCall),
    ("delegation.hop", DelegationHop),
    ("incident.created", AgentIncident),
)
KINDS = tuple(k for k, _ in SOURCES)

# OpenTelemetry severity numbers
INFO, WARN, ERROR = 9, 13, 17
_SEVERITY_TEXT = {INFO: "INFO", WARN: "WARN", ERROR: "ERROR"}

_HEADER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,99}$")
_HEADER_VALUE = re.compile(r"^[\x20-\x7e]{1,4000}$")
_FORBIDDEN_HEADERS = {
    "host", "content-type", "content-length", "content-encoding", "transfer-encoding", "connection",
    "keep-alive", "te", "trailer", "upgrade", "expect", "proxy-authorization", "proxy-connection", "cookie",
}


class ExportError(Exception):
    def __init__(self, code: str, detail: str = "", *, drop: bool = False):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail, self.drop = code, detail, drop


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ----------------------------------------------------------------------------- settings

def logs_url(endpoint: str) -> str:
    """The URL records are POSTed to: the endpoint as given when it already
    ends in /v1/logs, else the endpoint with /v1/logs appended (the OTLP/HTTP
    base URL a collector or vendor documents)."""
    endpoint = endpoint.rstrip("/")
    return endpoint if endpoint.endswith(LOGS_PATH) else endpoint + LOGS_PATH


def _allowlisted(host: Optional[str]) -> bool:
    hosts, nets = _allowlist()
    host = (host or "").lower()
    if host in hosts:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in n for n in nets)


def check_endpoint(endpoint: Optional[str]) -> str:
    """The endpoint as stored. HTTPS; plain HTTP only to a host on the
    operator's own network (OUTBOUND_PRIVATE_ALLOWLIST)."""
    def bad(code: str, detail: str = ""):
        return api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, code, **({"detail": detail} if detail else {}))
    endpoint = (endpoint or "").strip().rstrip("/")
    if not endpoint:
        raise bad("otel.no_endpoint")
    if len(endpoint) > 480:
        raise bad("otel.bad_url", "too long")
    try:
        endpoint = validate_url(endpoint).rstrip("/")
    except ValueError as exc:
        raise bad("otel.bad_url", str(exc)[:200])
    parsed = urlparse(endpoint)
    if parsed.query or parsed.fragment:
        raise bad("otel.bad_url", "no query or fragment")
    if parsed.scheme != "https" and not _allowlisted(parsed.hostname):
        raise bad("otel.https_required")
    return endpoint


def check_header(name: Optional[str], value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """(name, value) of the optional header, checked. A name without a value
    keeps the stored value (the caller decides); no name: no header."""
    name = (name or "").strip()
    if not name:
        return None, None
    if not _HEADER_NAME.match(name) or name.lower() in _FORBIDDEN_HEADERS:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "otel.bad_header_name")
    if value is not None:
        value = value.strip()
        if not _HEADER_VALUE.match(value):
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "otel.bad_header_value")
    return name, value


async def get_settings(db: AsyncSession, org_id: int) -> Optional[OtelExportSettings]:
    q = select(OtelExportSettings).where(OtelExportSettings.org_id == org_id)
    return (await db.execute(q)).scalar_one_or_none()


async def _settings_row(db: AsyncSession, org_id: int) -> OtelExportSettings:
    row = await get_settings(db, org_id)
    if row is not None:
        return row
    try:
        async with db.begin_nested():
            db.add(OtelExportSettings(org_id=org_id, enabled=False, cursors={}))
    except IntegrityError:
        pass                                    # made meanwhile by another request
    return await get_settings(db, org_id)


async def current_cursors(db: AsyncSession) -> Dict[str, int]:
    """The newest id of every kind: where an export switched on now starts."""
    out = {}
    for kind, model in SOURCES:
        out[kind] = int((await db.execute(select(func.coalesce(func.max(model.id), 0)))).scalar_one())
    return out


def _headers(name: Optional[str], value: Optional[str]) -> Dict[str, str]:
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    if name and value:
        h[name] = value
    return h


async def save_settings(db: AsyncSession, org_id: int, user_id: int, *, enabled: bool, endpoint: Optional[str],
                        header_name: Optional[str], header_value: Optional[str]) -> OtelExportSettings:
    """Switched on, one test record is sent first: settings the collector
    does not accept are refused, not stored. header_value None keeps the
    stored one (for the same header name); no header_name removes the header."""
    row = await _settings_row(db, org_id)
    given = (endpoint or "").strip().rstrip("/") or None
    if enabled or (given and given != row.endpoint):
        endpoint = check_endpoint(given)
    else:
        endpoint = row.endpoint                 # switching off always works, whatever is stored
    name, value = check_header(header_name, header_value)
    if name and value is None:
        if not row.header_value_enc or (row.header_name or "").lower() != name.lower():
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "otel.no_header_value")
        try:
            value = decrypt_secret(row.header_value_enc)
        except ValueError:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "otel.header_unreadable")
    try:
        async with db.begin_nested():           # a collector that refuses undoes only this change
            if enabled and not row.enabled:
                row.cursors = await current_cursors(db)     # from now on; the past is not replayed
            if enabled or endpoint != row.endpoint:
                row.last_error = row.last_error_at = None
            row.enabled, row.endpoint, row.header_name = enabled, endpoint, name
            row.header_value_enc = encrypt_secret(value) if name and value else None
            row.config_rev = (row.config_rev or 0) + 1
            row.updated_by, row.updated_at = user_id, _now()
            await db.flush()
            if enabled:
                # tried as stored - the address every later export uses, through the SSRF-guarded client
                await send_stored(await get_settings(db, org_id), probe_payload(org_id))
    except ExportError as exc:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, exc.code, detail=(exc.detail or "")[:200])
    await db.commit()
    return row


def settings_out(row: Optional[OtelExportSettings]) -> Dict[str, Any]:
    if row is None:
        return {"enabled": False, "endpoint": None, "logs_url": None, "outbound_host": None, "header_name": None,
                "header_set": False, "last_success_at": None, "last_error": None, "last_error_at": None,
                "exported_total": 0, "updated_at": None}
    iso = lambda d: d.isoformat() if d else None  # noqa: E731
    return {
        "enabled": bool(row.enabled),
        "endpoint": row.endpoint,
        "logs_url": logs_url(row.endpoint) if row.endpoint else None,
        "outbound_host": urlparse(row.endpoint).hostname if row.endpoint else None,
        "header_name": row.header_name,
        "header_set": bool(row.header_value_enc),
        "last_success_at": iso(row.last_success_at),
        "last_error": row.last_error,
        "last_error_at": iso(row.last_error_at),
        "exported_total": int(row.exported_total or 0),
        "updated_at": iso(row.updated_at),
    }


# ----------------------------------------------------------------------------- OTLP JSON

def _value(v: Any) -> Optional[Dict[str, Any]]:
    """An OTLP AnyValue (protobuf JSON mapping: 64-bit integers as strings)."""
    if isinstance(v, bool):
        return {"boolValue": v}
    if isinstance(v, int):
        return {"intValue": str(v)}
    if isinstance(v, float):
        return {"doubleValue": v}
    if isinstance(v, str):
        return {"stringValue": v}
    if isinstance(v, (list, tuple)):
        values = [x for x in (_value(i) for i in v) if x is not None]
        return {"arrayValue": {"values": values}}
    return None


def _attributes(pairs: Iterable[Tuple[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for key, v in pairs:
        if v is None or v == [] or v == "":
            continue
        val = _value(v)
        if val is not None:
            out.append({"key": key, "value": val})
    return out


def _nanos(ts: Optional[datetime]) -> str:
    ts = ts or _now()
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return str(int(ts.timestamp() * 1_000_000) * 1000)


def _decision_severity(decision: Optional[str]) -> int:
    return INFO if decision in ("allowed", None) else WARN


def record(kind: str, ev: Dict[str, Any], row: Any, names: Dict[int, str]) -> Dict[str, Any]:
    """One OTLP LogRecord for one event (ev: obs_hooks.to_event of the row)."""
    agent_id = ev.get("agent_id")
    common = [
        ("pvp.event.type", kind),
        ("pvp.event.id", ev.get("id")),
        ("gen_ai.agent.id", str(agent_id) if agent_id is not None else None),
        ("gen_ai.agent.name", names.get(agent_id)),
        ("pvp.chain.id", ev.get("chain_id")),
    ]
    if kind in ("action.checked", "action.recorded"):
        action_type, tool, decision = ev.get("action_type"), ev.get("tool"), ev.get("decision")
        tool_call = action_type == "tool_call"
        attrs = common + [
            ("gen_ai.operation.name", "execute_tool" if tool_call else None),
            ("gen_ai.tool.name", tool if tool_call else None),
            ("pvp.action.type", action_type),
            ("pvp.tool.name", tool),
            ("pvp.decision", decision),
            ("pvp.policy.id", ev.get("policy_id")),
            ("pvp.guards", ev.get("guards")),
        ]
        if kind == "action.checked":
            attrs.append(("pvp.incident.type", ev.get("incident_type")))
            title = "PVP check"
        else:
            attrs += [("pvp.duration_ms", ev.get("duration_ms")), ("pvp.checked", ev.get("has_check"))]
            title = "PVP action"
        severity = _decision_severity(decision)
        body = f"{title}: {decision or 'recorded'} {action_type or 'action'} {tool or ''}".rstrip()
    elif kind == "llm.call":
        st = ev.get("status")
        attrs = common + [
            ("gen_ai.operation.name", "chat"),
            ("gen_ai.request.model", ev.get("model")),
            ("gen_ai.usage.input_tokens", ev.get("prompt_tokens")),
            ("gen_ai.usage.output_tokens", ev.get("completion_tokens")),
            ("pvp.llm.status", st),
            ("pvp.provider.id", ev.get("provider_id")),
            ("pvp.duration_ms", ev.get("duration_ms")),
            ("pvp.flags", ev.get("flags")),
            ("pvp.guards", ev.get("guards")),
        ]
        severity = INFO if st == "completed" else WARN
        body = f"PVP LLM call: {st or 'unknown'} {ev.get('model') or ''}".rstrip()
    elif kind == "delegation.hop":
        to = ev.get("to_agent_id")
        attrs = common + [
            ("pvp.delegation.to_agent.id", str(to) if to is not None else None),
            ("pvp.delegation.to_agent.name", names.get(to)),
            ("pvp.delegation.depth", ev.get("depth")),
            ("pvp.delegation.capabilities", ev.get("capabilities")),
            ("pvp.delegation.verified", ev.get("verified")),
        ]
        severity = INFO if ev.get("verified") else WARN
        body = f"PVP delegation: agent {agent_id} -> agent {to} (depth {ev.get('depth')})"
    else:  # incident.created
        sev = ev.get("severity")
        attrs = common + [("pvp.incident.type", ev.get("incident_type")), ("pvp.incident.severity", sev)]
        severity = ERROR if sev in ("critical", "high") else WARN if sev == "medium" else INFO
        body = f"PVP incident: {ev.get('incident_type') or 'unknown'} ({sev or 'unknown'})"
    out: Dict[str, Any] = {
        "timeUnixNano": _nanos(getattr(row, "created_at", None)),
        "observedTimeUnixNano": _nanos(None),
        "severityNumber": severity,
        "severityText": _SEVERITY_TEXT[severity],
        "eventName": "pvp." + kind,
        "body": {"stringValue": body},
        "attributes": _attributes(attrs),
    }
    trace_id, span_id = getattr(row, "trace_id", None), getattr(row, "span_id", None)
    if trace_id and span_id:
        out["traceId"], out["spanId"] = trace_id, span_id
    return out


def _resource(org_id: int) -> Dict[str, Any]:
    pairs = [("service.name", "provenza"), ("provenza.org.id", org_id)]
    if settings.PUBLIC_BASE_URL:
        pairs.append(("provenza.url", settings.PUBLIC_BASE_URL.rstrip("/")))
    return {"attributes": _attributes(pairs)}


def payload(org_id: int, records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """An OTLP ExportLogsServiceRequest, JSON encoded."""
    return {"resourceLogs": [{
        "resource": _resource(org_id),
        "scopeLogs": [{"scope": {"name": SCOPE_NAME, "version": SCOPE_VERSION}, "logRecords": records}],
    }]}


def probe_payload(org_id: int) -> Dict[str, Any]:
    return payload(org_id, [{
        "timeUnixNano": _nanos(None), "observedTimeUnixNano": _nanos(None),
        "severityNumber": INFO, "severityText": "INFO", "eventName": "pvp.test",
        "body": {"stringValue": "Provenza OpenTelemetry export: test record"},
        "attributes": _attributes([("pvp.event.type", "test")]),
    }])


# ----------------------------------------------------------------------------- sending

def _short(text_: str, n: int = 200) -> str:
    return re.sub(r"[\x00-\x1f\x7f]+", " ", text_ or "").strip()[:n]


async def send(url: str, body: Dict[str, Any], headers: Dict[str, str]) -> Optional[str]:
    """POST one request. None, or a note about records the collector
    rejected (OTLP partial success). Raises ExportError; drop=True when the
    OTLP specification says the data must not be retried (400, 413)."""
    data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    try:
        async with guarded_async_client(timeout=TIMEOUT_SECONDS) as client:
            async with client.stream("POST", url, content=data, headers=headers) as resp:
                answer = b""
                async for chunk in resp.aiter_bytes():
                    answer += chunk
                    if len(answer) > MAX_RESPONSE_BYTES:
                        raise ExportError("otel.response_too_large")
                code = resp.status_code
    except httpx.HTTPError as exc:
        raise ExportError("otel.unreachable", _short(f"{type(exc).__name__}: {exc}", 150))
    text_ = answer.decode("utf-8", "replace")
    if 200 <= code < 300:
        try:
            partial = (json.loads(text_) or {}).get("partialSuccess") if text_.strip() else None
        except (ValueError, AttributeError):
            partial = None
        if isinstance(partial, dict) and str(partial.get("rejectedLogRecords") or "0") not in ("0", ""):
            return _short(f"{partial.get('rejectedLogRecords')} records rejected: {partial.get('errorMessage') or ''}")
        return None
    detail = _short(f"HTTP {code}: {text_}")
    # OTLP/HTTP: 429, 502, 503, 504 are retried; 400 and 413 are not. Any other
    # answer (401, 403, 404, 500, ...) is a collector or a setting to fix: the
    # events wait for it, here they cost nothing but a cursor.
    raise ExportError("otel.http_error", detail, drop=code in (400, 413))


async def send_stored(row: OtelExportSettings, body: Dict[str, Any]) -> Optional[str]:
    """send() to the organization's endpoint with its header, both as stored."""
    if row is None or not row.endpoint:
        raise ExportError("otel.no_endpoint")
    try:
        value = decrypt_secret(row.header_value_enc) if row.header_value_enc else None
    except ValueError:
        raise ExportError("otel.header_unreadable")
    return await send(logs_url(row.endpoint), body, _headers(row.header_name, value))


# ----------------------------------------------------------------------------- the worker

# columns an event never reads (content, signatures): not loaded
_UNREAD = {
    AgentAction: ("input_data", "output_data", "signed_payload", "evidence", "witness", "signature",
                  "pq_signature", "signer_public_key", "signer_pq_public_key"),
    ActionCheck: ("requested", "action_capabilities"),
    DelegationHop: ("signed_payload", "task_description", "signature", "pq_signature", "signer_public_key",
                    "signer_pq_public_key"),
    AgentIncident: ("details",),
}


async def _batch(db: AsyncSession, org_id: int, model: Any, after: int, cutoff: datetime) -> List[Any]:
    q = (select(model).where(model.org_id == org_id, model.id > after, model.created_at <= cutoff)
         .order_by(model.id).limit(BATCH))
    unread = _UNREAD.get(model)
    if unread:
        q = q.options(*(defer(getattr(model, c)) for c in unread))
    return list((await db.execute(q)).scalars().all())


async def _names(db: AsyncSession, org_id: int, ids: Iterable[int]) -> Dict[int, str]:
    ids = {i for i in ids if i is not None}
    if not ids:
        return {}
    rows = await db.execute(select(Agent.id, Agent.name).where(Agent.org_id == org_id, Agent.id.in_(ids)))
    return {i: n for i, n in rows.all()}


async def export_org(db: AsyncSession, org_id: int) -> Dict[str, Any]:
    """Send what is new for one organization. {"sent": n} or {"skipped":
    reason} or {"failed": code}."""
    got = (await db.execute(text("SELECT pg_try_advisory_xact_lock(:k, :o)"), {"k": LOCK_KEY, "o": org_id})).scalar()
    if not got:
        await db.commit()
        return {"skipped": "busy"}
    row = await get_settings(db, org_id)
    if row is None or not row.enabled or not row.endpoint:
        await db.commit()                        # ends the transaction, and with it the lock
        return {"skipped": "off"}
    rev = row.config_rev
    if row.header_value_enc:
        try:
            decrypt_secret(row.header_value_enc)
        except ValueError:
            return await _note(db, org_id, rev, error=ExportError("otel.header_unreadable"))
    cursors: Dict[str, int] = {k: int((row.cursors or {}).get(k) or 0) for k in KINDS}
    sent, note = 0, None
    for _ in range(MAX_ROUNDS):
        cutoff = _now() - timedelta(seconds=LAG_SECONDS)
        rows_by_kind = {kind: await _batch(db, org_id, model, cursors[kind], cutoff) for kind, model in SOURCES}
        if not any(rows_by_kind.values()):
            break
        ids = [getattr(r, "agent_id", None) for rs in rows_by_kind.values() for r in rs]
        ids += [getattr(r, "from_agent_id", None) for r in rows_by_kind["delegation.hop"]]
        ids += [getattr(r, "to_agent_id", None) for r in rows_by_kind["delegation.hop"]]
        names = await _names(db, org_id, ids)
        records, moved = [], dict(cursors)
        for kind, rows in rows_by_kind.items():
            for r in rows:
                moved[kind] = max(moved[kind], r.id)
                item = obs_hooks.to_event(r)
                if item is not None:               # LLM calls' own action rows are sent as llm.call
                    records.append(record(kind, item[1], r, names))
        if records:
            try:
                note = await send_stored(row, payload(org_id, records)) or note
            except ExportError as exc:
                if exc.drop:
                    cursors = moved                # malformed or too large for this collector: not retried
                return await _note(db, org_id, rev, cursors=cursors, sent=sent, error=exc)
        cursors, sent = moved, sent + len(records)
        if all(len(rs) < BATCH for rs in rows_by_kind.values()):
            break
    return await _note(db, org_id, rev, cursors=cursors, sent=sent, partial=note)


async def _note(db: AsyncSession, org_id: int, rev: int, *, cursors: Optional[Dict[str, int]] = None,
                sent: int = 0, error: Optional[ExportError] = None, partial: Optional[str] = None) -> Dict[str, Any]:
    """Write the outcome back - unless an administrator changed the settings
    meanwhile: then this run's cursors are not theirs."""
    row = (await db.execute(select(OtelExportSettings).where(OtelExportSettings.org_id == org_id)
                            .with_for_update())).scalar_one_or_none()
    if row is None or row.config_rev != rev:
        await db.commit()
        return {"skipped": "changed"}
    if cursors is not None:
        row.cursors = {k: int(v) for k, v in cursors.items()}
    row.exported_total = int(row.exported_total or 0) + sent
    now = _now()
    if error is not None:
        row.last_error = _short(f"{error.code}: {error.detail}" if error.detail else error.code, 500)
        row.last_error_at = now
    else:
        if sent:
            row.last_success_at = now
        row.last_error = partial
        row.last_error_at = now if partial else None
    await db.commit()
    if error is not None:
        return {"failed": error.code, "sent": sent}
    return {"sent": sent}


async def export_all(db: AsyncSession) -> Dict[str, int]:
    """Every organization with the export switched on (the scheduler, every 30 seconds)."""
    q = select(OtelExportSettings.org_id).where(OtelExportSettings.enabled.is_(True))
    orgs = (await db.execute(q)).scalars().all()
    await db.commit()
    total = {"sent": 0, "failed": 0, "skipped": 0}
    for org_id in orgs:
        try:
            out = await export_org(db, org_id)
        except Exception:  # noqa: BLE001 - one organization must not stop the others
            await db.rollback()
            total["failed"] += 1
            continue
        total["sent"] += out.get("sent", 0)
        if "failed" in out:
            total["failed"] += 1
        elif "skipped" in out:
            total["skipped"] += 1
    return total


async def send_test(db: AsyncSession, org_id: int) -> Dict[str, Any]:
    """One test record with the stored settings."""
    try:
        note = await send_stored(await get_settings(db, org_id), probe_payload(org_id))
    except ExportError as exc:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, exc.code, detail=(exc.detail or "")[:200])
    return {"ok": True, "note": note}
