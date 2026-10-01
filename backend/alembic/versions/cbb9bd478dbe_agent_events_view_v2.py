"""agent observability: agent_events_v - metadata-only view over checks, actions,
LLM calls, A2A messages, delegation hops and incidents

Revision ID: cbb9bd478dbe
Revises: d7660f3a8a3d
"""
from alembic import op

revision = "cbb9bd478dbe"
down_revision = "d7660f3a8a3d"
branch_labels = None
depends_on = None

# one statement per execute: asyncpg runs prepared statements, not scripts
STATEMENTS = [
    r"""DROP VIEW IF EXISTS agent_events_v""",
    r"""CREATE VIEW agent_events_v AS
SELECT 'action.recorded'::text AS event_type, a.id AS source_id, a.org_id, a.agent_id, a.chain_id,
       a.created_at AS ts, a.action_type::varchar AS action_type, a.tool_name::varchar AS tool_name,
       a.policy_check_result::varchar AS decision, ARRAY(SELECT DISTINCT (r.m)[1] FROM regexp_matches(upper(coalesce(a.reason, '')), '\m(ASI(0[1-9]|10))\M', 'g') AS r(m)) AS guards,
       NULL::varchar AS incident_type, NULL::varchar AS severity, a.duration_ms, a.policy_id,
       (a.check_id IS NOT NULL) AS has_check, NULL::boolean AS resolved,
       NULL::varchar AS model, NULL::varchar AS status, NULL::integer AS prompt_tokens,
       NULL::integer AS completion_tokens, NULL::integer AS to_agent_id
  FROM agent_actions a
UNION ALL
SELECT 'action.checked', c.id, c.org_id, c.agent_id, c.chain_id,
       c.created_at, c.action_type, c.tool_name,
       c.decision, ARRAY(SELECT DISTINCT (r.m)[1] FROM regexp_matches(upper(coalesce(c.reason, '')), '\m(ASI(0[1-9]|10))\M', 'g') AS r(m)),
       c.incident_type, NULL, NULL, c.policy_id,
       NULL, NULL, NULL, NULL, NULL, NULL, NULL
  FROM agent_action_checks c
UNION ALL
SELECT 'llm.call', l.id, l.org_id, l.agent_id, NULL,
       l.created_at, 'model_call', NULL,
       NULL, ARRAY(SELECT DISTINCT (r.m)[1] FROM regexp_matches(upper(coalesce(l.reason, '') || ' ' || coalesce(l.flags::text, '')), '\m(ASI(0[1-9]|10))\M', 'g') AS r(m)),
       NULL, NULL, l.latency_ms, NULL,
       NULL, NULL, l.model, l.status, l.prompt_tokens, l.completion_tokens, NULL
  FROM gateway_calls l
UNION ALL
SELECT 'a2a.message', m.id, m.org_id, m.from_agent_id, m.chain_id,
       m.created_at, m.message_type, NULL,
       NULL, CASE WHEN m.status <> 'accepted' THEN ARRAY['ASI07']::text[] ELSE ARRAY[]::text[] END,
       NULL, NULL, NULL, NULL,
       NULL, NULL, NULL, m.status, NULL, NULL, m.to_agent_id
  FROM a2a_messages m
UNION ALL
SELECT 'delegation.hop', h.id, h.org_id, h.from_agent_id, h.chain_id,
       h.created_at, 'delegate', NULL,
       NULL, ARRAY[]::text[],
       NULL, NULL, NULL, NULL,
       NULL, NULL, NULL, CASE WHEN h.verified THEN 'verified' ELSE 'unverified' END, NULL, NULL, h.to_agent_id
  FROM delegation_hops h
UNION ALL
SELECT 'incident.created', i.id, i.org_id, i.agent_id, i.chain_id,
       i.created_at, NULL, NULL,
       NULL, ARRAY[]::text[],
       i.incident_type, i.severity, NULL, NULL,
       NULL, i.resolved, NULL, NULL, NULL, NULL, NULL
  FROM agent_incidents i""",
]


def upgrade():
    for statement in STATEMENTS:
        op.execute(statement)


def downgrade():
    op.execute("DROP VIEW IF EXISTS agent_events_v")
