# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Retention of agent telemetry, run by the request sweep (queue_ttl.sweep_org).

  checks    policy verdicts (agent_action_checks) older than the check
            retention are deleted - except checks another row still points
            to (an action recorded with that check, an approval...), found
            from the foreign keys in the model metadata, so nothing breaks.
            Deleted in batches so a backlog never locks the table for long.

  content   past the content retention, what agents sent and got back is
            erased while the row stays for the audit trail and the charts:
            agent_actions.input_data / output_data / signed_payload, and for
            LLM calls through the gateway the masked prompt and the answer.
            Old signatures can no longer be re-verified after that - the
            verdict, time, agent and tool remain.

None for a period means "keep indefinitely".
"""

from datetime import datetime, timedelta
from typing import Dict, Optional

from sqlalchemy import delete, literal, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import Base
from app.models.agent_action import ActionCheck, AgentAction
from app.models.ai_request import AIRequest
from app.models.ai_response import AIResponse

BATCH = 5000
GATEWAY_PURPOSE = "gateway:%"


def _blank(attr):
    """The "erased" value for a column: NULL when allowed, else an empty value."""
    col = attr.property.columns[0]
    if col.nullable:
        return None
    return {} if col.type.__class__.__name__.upper() in ("JSON", "JSONB") else ""


def _filled(attr):
    """Condition "still holds content" that also matches non-nullable columns."""
    blank = _blank(attr)
    return attr.is_not(None) if blank is None else attr != blank


def _check_time():
    return ActionCheck.created_at if hasattr(ActionCheck, "created_at") else ActionCheck.expires_at


def _referencing_columns():
    """Columns of other tables with a foreign key to agent_action_checks.id."""
    target = ActionCheck.__tablename__
    return [fk.parent for table in Base.metadata.tables.values() if table.name != target
            for fk in table.foreign_keys if fk.column.table.name == target]


async def purge(db: AsyncSession, org_id: int, now: datetime, check_days: Optional[int],
                content_days: Optional[int]) -> Dict[str, int]:
    counts = {"purged_checks": 0, "scrubbed_content": 0}

    if check_days:
        cutoff = now - timedelta(days=check_days)
        unreferenced = [~select(literal(1)).where(col == ActionCheck.id).exists() for col in _referencing_columns()]
        ids = (select(ActionCheck.id)
               .where(ActionCheck.org_id == org_id, _check_time() < cutoff, *unreferenced)
               .limit(BATCH).scalar_subquery())
        r = await db.execute(delete(ActionCheck).where(ActionCheck.id.in_(ids))
                             .execution_options(synchronize_session=False))
        counts["purged_checks"] = r.rowcount or 0

    if content_days:
        cutoff = now - timedelta(days=content_days)
        r1 = await db.execute(
            update(AgentAction)
            .where(AgentAction.org_id == org_id, AgentAction.created_at < cutoff,
                   or_(_filled(AgentAction.input_data), _filled(AgentAction.output_data),
                       _filled(AgentAction.signed_payload)))
            .values(input_data=_blank(AgentAction.input_data), output_data=_blank(AgentAction.output_data),
                    signed_payload=_blank(AgentAction.signed_payload))
            .execution_options(synchronize_session=False))
        old_llm = (select(AIRequest.id)
                   .where(AIRequest.org_id == org_id, AIRequest.created_at < cutoff,
                          AIRequest.purpose.like(GATEWAY_PURPOSE)))
        r2 = await db.execute(
            update(AIRequest)
            .where(AIRequest.id.in_(old_llm), _filled(AIRequest.masked_input_text))
            .values(masked_input_text=_blank(AIRequest.masked_input_text))
            .execution_options(synchronize_session=False))
        r3 = await db.execute(
            update(AIResponse)
            .where(AIResponse.request_id.in_(old_llm),
                   or_(_filled(AIResponse.response_text), _filled(AIResponse.provider_response_json)))
            .values(response_text=_blank(AIResponse.response_text),
                    provider_response_json=_blank(AIResponse.provider_response_json))
            .execution_options(synchronize_session=False))
        counts["scrubbed_content"] = (r1.rowcount or 0) + (r2.rowcount or 0) + (r3.rowcount or 0)

    return counts
