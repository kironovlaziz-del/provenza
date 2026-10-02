# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Agent observability: history, aggregates and time series read from the
agent_events_v view, in the same event shape the live stream uses.

The view unions everything an agent does - policy checks, recorded actions,
LLM calls through the gateway, A2A messages, delegation hops, incidents -
with metadata columns only (no arguments, prompts, outputs, reasons or
details). Content is attached separately, masked (obs_content).

A "decision" is one verdict on one action: every check, plus recorded
actions that were not checked first (legacy /actions/record without a
check_id). Counting both a check and its record would show every action
twice.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from sqlalchemy import DDL, event, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import Base
from app.models.a2a import A2AMessage
from app.models.agent import Agent
from app.models.agent_action import ActionCheck, AgentAction, AgentIncident
from app.models.delegation import DelegationHop
from app.models.gateway import GatewayCall

VIEW = "agent_events_v"
WINDOWS = {15: 15, 60: 60, 360: 300, 1440: 900, 10080: 7200, 43200: 28800}  # minutes -> bucket seconds
DECISION = "(event_type = 'action.checked' OR (event_type = 'action.recorded' AND NOT has_check))"
LLM_ERRORS = "('failed', 'blocked', 'denied', 'rate_limited', 'filtered')"

# guard codes found in a text column; no non-capturing group: alembic runs
# this through text(), which would read "?:0" as a bind parameter
_GUARDS = r"""ARRAY(SELECT DISTINCT (r.m)[1] FROM regexp_matches(upper({col}), '\m(ASI(0[1-9]|10))\M', 'g') AS r(m))"""


def build_view_sql() -> str:
    """DROP + CREATE VIEW agent_events_v - metadata columns only.
    Used by the migration (as literal SQL) and by metadata.create_all."""
    check_cols = set(ActionCheck.__table__.columns.keys())
    if "created_at" in check_cols:
        check_ts = "c.created_at"
    else:  # a check is issued CHECK_TTL_SECONDS before it expires
        from app.services.agent_audit import CHECK_TTL_SECONDS
        check_ts = f"c.expires_at - interval '{int(CHECK_TTL_SECONDS)} seconds'"
    g = _GUARDS.format
    return f"""
DROP VIEW IF EXISTS {VIEW};
CREATE VIEW {VIEW} AS
SELECT 'action.recorded'::text AS event_type, a.id AS source_id, a.org_id, a.agent_id, a.chain_id,
       a.created_at AS ts, a.action_type::varchar AS action_type, a.tool_name::varchar AS tool_name,
       a.policy_check_result::varchar AS decision, {g(col="coalesce(a.reason, '')")} AS guards,
       NULL::varchar AS incident_type, NULL::varchar AS severity, a.duration_ms, a.policy_id,
       (a.check_id IS NOT NULL) AS has_check, NULL::boolean AS resolved,
       NULL::varchar AS model, NULL::varchar AS status, NULL::integer AS prompt_tokens,
       NULL::integer AS completion_tokens, NULL::integer AS to_agent_id
  FROM {AgentAction.__tablename__} a
UNION ALL
SELECT 'action.checked', c.id, c.org_id, c.agent_id, c.chain_id,
       {check_ts}, c.action_type, c.tool_name,
       c.decision, {g(col="coalesce(c.reason, '')")},
       c.incident_type, NULL, NULL, c.policy_id,
       NULL, NULL, NULL, NULL, NULL, NULL, NULL
  FROM {ActionCheck.__tablename__} c
UNION ALL
SELECT 'llm.call', l.id, l.org_id, l.agent_id, NULL,
       l.created_at, 'model_call', NULL,
       NULL, {g(col="coalesce(l.reason, '') || ' ' || coalesce(l.flags::text, '')")},
       NULL, NULL, l.latency_ms, NULL,
       NULL, NULL, l.model, l.status, l.prompt_tokens, l.completion_tokens, NULL
  FROM {GatewayCall.__tablename__} l
UNION ALL
SELECT 'a2a.message', m.id, m.org_id, m.from_agent_id, m.chain_id,
       m.created_at, m.message_type, NULL,
       NULL, CASE WHEN m.status <> 'accepted' THEN ARRAY['ASI07']::text[] ELSE ARRAY[]::text[] END,
       NULL, NULL, NULL, NULL,
       NULL, NULL, NULL, m.status, NULL, NULL, m.to_agent_id
  FROM {A2AMessage.__tablename__} m
UNION ALL
SELECT 'delegation.hop', h.id, h.org_id, h.from_agent_id, h.chain_id,
       h.created_at, 'delegate', NULL,
       NULL, ARRAY[]::text[],
       NULL, NULL, NULL, NULL,
       NULL, NULL, NULL, CASE WHEN h.verified THEN 'verified' ELSE 'unverified' END, NULL, NULL, h.to_agent_id
  FROM {DelegationHop.__tablename__} h
UNION ALL
SELECT 'incident.created', i.id, i.org_id, i.agent_id, i.chain_id,
       i.created_at, NULL, NULL,
       NULL, ARRAY[]::text[],
       i.incident_type, i.severity, NULL, NULL,
       NULL, i.resolved, NULL, NULL, NULL, NULL, NULL
  FROM {AgentIncident.__tablename__} i;
"""


# Databases built with metadata.create_all (tests) get the view too; it is
# dropped before the tables so drop_all keeps working.
for _stmt in [s for s in build_view_sql().split(";") if s.strip()]:
    event.listen(Base.metadata, "after_create", DDL(_stmt.replace("%", "%%")))
event.listen(Base.metadata, "before_drop", DDL(f"DROP VIEW IF EXISTS {VIEW}"))


def _row_event(r) -> dict:
    t = r["event_type"]
    ev = {"v": 1, "type": t, "id": r["source_id"], "ts": r["ts"].isoformat() if r["ts"] else None,
          "agent_id": r["agent_id"], "chain_id": r["chain_id"], "guards": list(r["guards"] or [])}
    if t == "incident.created":
        ev.update(incident_type=r["incident_type"], severity=r["severity"], resolved=r["resolved"])
    elif t == "llm.call":
        ev.update(model=r["model"], status=r["status"], duration_ms=r["duration_ms"],
                  prompt_tokens=r["prompt_tokens"], completion_tokens=r["completion_tokens"])
    elif t == "a2a.message":
        ev.update(to_agent_id=r["to_agent_id"], message_type=r["action_type"], status=r["status"])
    elif t == "delegation.hop":
        ev.update(to_agent_id=r["to_agent_id"], verified=r["status"] == "verified")
    else:
        ev.update(action_type=r["action_type"], tool=r["tool_name"], policy_id=r["policy_id"], decision=r["decision"])
        if t == "action.checked":
            ev["incident_type"] = r["incident_type"]
        else:
            ev.update(duration_ms=r["duration_ms"], has_check=r["has_check"])
    return {k: v for k, v in ev.items() if v is not None and v != []}


def _filters(org_id: int, since: datetime, agent_ids: Optional[Sequence[int]], types: Optional[Sequence[str]]):
    where = ["org_id = :org", "ts >= :since"]
    params: Dict[str, object] = {"org": org_id, "since": since}
    if agent_ids:
        where.append("(agent_id = ANY(:agents) OR to_agent_id = ANY(:agents))")
        params["agents"] = list(agent_ids)
    if types:
        where.append("event_type = ANY(:types)")
        params["types"] = list(types)
    return " AND ".join(where), params


async def history(db: AsyncSession, org_id: int, *, minutes: int, agent_ids=None, types=None,
                  limit: int = 500, before_ts: Optional[datetime] = None) -> List[dict]:
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    where, params = _filters(org_id, since, agent_ids, types)
    if before_ts is not None:
        where += " AND ts < :before"
        params["before"] = before_ts
    params["limit"] = limit
    rows = (await db.execute(text(
        f"SELECT * FROM {VIEW} WHERE {where} ORDER BY ts DESC, source_id DESC LIMIT :limit"
    ), params)).mappings().all()
    return [_row_event(r) for r in rows]


def _num(v):
    return None if v is None else round(float(v), 1)


async def summary(db: AsyncSession, org_id: int, *, minutes: int, agent_ids=None) -> dict:
    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=minutes)
    where, params = _filters(org_id, since, agent_ids, None)
    ev = f"WITH ev AS (SELECT * FROM {VIEW} WHERE {where})"

    tot = (await db.execute(text(f"""{ev}
        SELECT
          count(*) AS events,
          count(*) FILTER (WHERE {DECISION}) AS decisions,
          count(*) FILTER (WHERE {DECISION} AND decision = 'allowed') AS allowed,
          count(*) FILTER (WHERE {DECISION} AND decision = 'denied') AS denied,
          count(*) FILTER (WHERE {DECISION} AND decision = 'pending_approval') AS pending,
          count(*) FILTER (WHERE event_type = 'incident.created') AS incidents,
          count(*) FILTER (WHERE event_type = 'action.recorded') AS recorded,
          percentile_cont(0.5) WITHIN GROUP (ORDER BY duration_ms)
            FILTER (WHERE event_type = 'action.recorded' AND duration_ms IS NOT NULL) AS p50_ms,
          percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms)
            FILTER (WHERE event_type = 'action.recorded' AND duration_ms IS NOT NULL) AS p95_ms,
          count(*) FILTER (WHERE event_type = 'llm.call') AS llm_calls,
          count(*) FILTER (WHERE event_type = 'llm.call' AND status IN {LLM_ERRORS}) AS llm_errors,
          coalesce(sum(coalesce(prompt_tokens, 0) + coalesce(completion_tokens, 0))
            FILTER (WHERE event_type = 'llm.call'), 0) AS llm_tokens,
          percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms)
            FILTER (WHERE event_type = 'llm.call' AND duration_ms IS NOT NULL) AS llm_p95_ms,
          count(*) FILTER (WHERE event_type = 'a2a.message') AS a2a_messages,
          count(*) FILTER (WHERE event_type = 'delegation.hop') AS delegations,
          count(DISTINCT agent_id) AS active_agents
        FROM ev"""), params)).mappings().one()

    per_agent = (await db.execute(text(f"""{ev}
        SELECT agent_id,
          count(*) AS events,
          count(*) FILTER (WHERE {DECISION}) AS decisions,
          count(*) FILTER (WHERE {DECISION} AND decision = 'denied') AS denied,
          count(*) FILTER (WHERE {DECISION} AND decision = 'pending_approval') AS pending,
          count(*) FILTER (WHERE event_type = 'incident.created') AS incidents,
          count(*) FILTER (WHERE event_type = 'llm.call') AS llm_calls,
          coalesce(sum(coalesce(prompt_tokens, 0) + coalesce(completion_tokens, 0))
            FILTER (WHERE event_type = 'llm.call'), 0) AS llm_tokens,
          max(ts) AS last_seen,
          percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms)
            FILTER (WHERE event_type IN ('action.recorded', 'llm.call') AND duration_ms IS NOT NULL) AS p95_ms
        FROM ev WHERE agent_id IS NOT NULL GROUP BY agent_id"""), params)).mappings().all()

    open_incidents = (await db.execute(text(
        f"SELECT count(*) FROM {VIEW} WHERE org_id = :org AND event_type = 'incident.created' AND resolved = false"
    ), {"org": org_id})).scalar_one()

    agents = (await db.execute(
        select(Agent.id, Agent.name, Agent.status, Agent.agent_type, Agent.api_key_revoked_at)
        .where(Agent.org_id == org_id).order_by(Agent.name).limit(1000)
    )).all()
    stats = {r["agent_id"]: r for r in per_agent}

    agent_rows = []
    for a in agents:
        s = stats.get(a.id)
        row = {"id": a.id, "name": a.name, "status": a.status, "agent_type": a.agent_type,
               "key_revoked": a.api_key_revoked_at is not None}
        for k in ("events", "decisions", "denied", "pending", "incidents", "llm_calls", "llm_tokens"):
            row[k] = int(s[k]) if s else 0
        row["last_seen"] = s["last_seen"].isoformat() if s and s["last_seen"] else None
        row["p95_ms"] = _num(s["p95_ms"]) if s else None
        agent_rows.append(row)

    decisions = tot["decisions"] or 0
    totals = {k: (int(tot[k]) if tot[k] is not None else 0) for k in (
        "events", "decisions", "allowed", "denied", "pending", "incidents", "recorded", "llm_calls", "llm_errors",
        "llm_tokens", "a2a_messages", "delegations", "active_agents")}
    totals.update(deny_rate=round(100.0 * tot["denied"] / decisions, 1) if decisions else None,
                  p50_ms=_num(tot["p50_ms"]), p95_ms=_num(tot["p95_ms"]), llm_p95_ms=_num(tot["llm_p95_ms"]),
                  open_incidents=open_incidents)
    return {"window_minutes": minutes, "bucket_seconds": WINDOWS[minutes], "generated_at": now.isoformat(),
            "totals": totals, "agents": agent_rows}


# ---------------------------------------------------------------- time series

# dimension -> (key expression, extra condition, needs unnest(guards))
DIMS: Dict[str, Tuple[str, str, bool]] = {
    "type": ("event_type", "TRUE", False),
    "decision": ("decision", DECISION, False),
    "agent": ("agent_id::text", "agent_id IS NOT NULL", False),
    "model": ("model", "event_type = 'llm.call' AND model IS NOT NULL", False),
    "llm_status": ("status", "event_type = 'llm.call'", False),
    "tool": ("tool_name", f"{DECISION} AND tool_name IS NOT NULL", False),
    "guard": ("g", "TRUE", True),
    "incident": ("incident_type", "event_type = 'incident.created'", False),
    "a2a_status": ("status", "event_type = 'a2a.message'", False),
}
METRICS = {
    "count": ("count(*)", True),
    "tokens": ("coalesce(sum(coalesce(prompt_tokens, 0) + coalesce(completion_tokens, 0)), 0)", True),
    "p95_ms": ("percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms)", False),
}
TOP_KEYS = 10


async def timeseries(db: AsyncSession, org_id: int, *, minutes: int, dim: str, metric: str = "count",
                     agent_ids=None) -> dict:
    """Stacked series: one value per bucket per key; the TOP_KEYS biggest keys,
    the rest summed into "other" (for additive metrics)."""
    bucket = WINDOWS[minutes]
    key_expr, cond, unnest = DIMS[dim]
    agg, additive = METRICS[metric]
    if metric == "p95_ms":
        cond = f"({cond}) AND duration_ms IS NOT NULL"
    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=minutes)
    where, params = _filters(org_id, since, agent_ids, None)
    src = f"ev, unnest(guards) AS g" if unnest else "ev"
    rows = (await db.execute(text(f"""
        WITH ev AS (SELECT * FROM {VIEW} WHERE {where})
        SELECT {key_expr} AS key,
               (floor(extract(epoch FROM ts)::double precision / {bucket}) * {bucket})::bigint AS t,
               {agg} AS v
          FROM {src}
         WHERE {cond} AND {key_expr} IS NOT NULL
         GROUP BY 1, 2"""), params)).mappings().all()

    first = int(since.timestamp() // bucket * bucket)
    last = int(now.timestamp() // bucket * bucket)
    times = list(range(first, last + 1, bucket))
    index = {t: i for i, t in enumerate(times)}
    by_key: Dict[str, List[float]] = {}
    for r in rows:
        i = index.get(int(r["t"]))
        if i is None:
            continue
        by_key.setdefault(str(r["key"]), [0.0] * len(times))[i] = float(r["v"] or 0)

    def weight(vals):
        return sum(vals) if additive else max(vals)

    ranked = sorted(by_key.items(), key=lambda kv: -weight(kv[1]))
    series = [{"key": k, "total": round(weight(v), 1), "values": [round(x, 1) for x in v]} for k, v in ranked[:TOP_KEYS]]
    if additive and len(ranked) > TOP_KEYS:
        other = [0.0] * len(times)
        for _, v in ranked[TOP_KEYS:]:
            other = [a + b for a, b in zip(other, v)]
        series.append({"key": "other", "total": round(sum(other), 1), "values": [round(x, 1) for x in other]})
    return {"dim": dim, "metric": metric, "window_minutes": minutes, "bucket_seconds": bucket,
            "buckets": [datetime.fromtimestamp(t, timezone.utc).isoformat() for t in times], "series": series}


async def breakdown(db: AsyncSession, org_id: int, *, minutes: int, dim: str, by: str, agent_ids=None,
                    limit: int = 12) -> dict:
    """Totals of `dim` split by `by` (e.g. tools by decision), biggest first."""
    key_expr, cond, unnest = DIMS[dim]
    by_expr, by_cond, by_unnest = DIMS[by]
    if unnest or by_unnest:
        raise ValueError("guard cannot be combined")
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    where, params = _filters(org_id, since, agent_ids, None)
    rows = (await db.execute(text(f"""
        WITH ev AS (SELECT * FROM {VIEW} WHERE {where})
        SELECT {key_expr} AS key, {by_expr} AS by, count(*) AS v
          FROM ev WHERE {cond} AND {by_cond} AND {key_expr} IS NOT NULL AND {by_expr} IS NOT NULL
         GROUP BY 1, 2"""), params)).mappings().all()
    totals: Dict[str, Dict[str, int]] = {}
    for r in rows:
        totals.setdefault(str(r["key"]), {})[str(r["by"])] = int(r["v"])
    ranked = sorted(totals.items(), key=lambda kv: -sum(kv[1].values()))[:limit]
    return {"dim": dim, "by": by, "rows": [{"key": k, "total": sum(v.values()), "parts": v} for k, v in ranked]}
