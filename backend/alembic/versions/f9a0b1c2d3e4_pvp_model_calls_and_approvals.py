"""PVP: LLM gateway calls are PVP actions; approved calls run once

Revision ID: f9a0b1c2d3e4
Revises: e8f9a0b1c2d3

A call through the LLM gateway is now a PVP action (action_type
"model_call", tool "llm.<model>", executed_by "llm_gateway"), decided by the
orchestrator like any other action. gateway_calls keeps the numbers of the
LLM charts and links to its action and delegation chain; agent_events_v
shows a model call once, as llm.call (with its chain), not also as
action.recorded.

An approval is spent once: when the agent repeats the approved call, the
check it gets names the approval (agent_action_approvals.redeemed_at,
redeemed_check_id; app/pvp/approvals.py).
"""
import sqlalchemy as sa
from alembic import op

revision = "f9a0b1c2d3e4"
down_revision = "e8f9a0b1c2d3"
branch_labels = None
depends_on = None

VIEW = r"""CREATE VIEW agent_events_v AS
SELECT 'action.recorded'::text AS event_type, a.id AS source_id, a.org_id, a.agent_id, a.chain_id,
       a.created_at AS ts, a.action_type::varchar AS action_type, a.tool_name::varchar AS tool_name,
       a.policy_check_result::varchar AS decision, ARRAY(SELECT DISTINCT (r.m)[1] FROM regexp_matches(upper(coalesce(a.reason, '')), '\m(ASI(0[1-9]|10))\M', 'g') AS r(m)) AS guards,
       NULL::varchar AS incident_type, NULL::varchar AS severity, a.duration_ms, a.policy_id,
       (a.check_id IS NOT NULL) AS has_check, NULL::boolean AS resolved,
       NULL::varchar AS model, NULL::varchar AS status, NULL::integer AS prompt_tokens,
       NULL::integer AS completion_tokens, NULL::integer AS to_agent_id
  FROM agent_actions a
 WHERE a.action_type IS DISTINCT FROM 'model_call'
UNION ALL
SELECT 'action.checked', c.id, c.org_id, c.agent_id, c.chain_id,
       c.created_at, c.action_type, c.tool_name,
       c.decision, ARRAY(SELECT DISTINCT (r.m)[1] FROM regexp_matches(upper(coalesce(c.reason, '')), '\m(ASI(0[1-9]|10))\M', 'g') AS r(m)),
       c.incident_type, NULL, NULL, c.policy_id,
       NULL, NULL, NULL, NULL, NULL, NULL, NULL
  FROM agent_action_checks c
UNION ALL
SELECT 'llm.call', l.id, l.org_id, l.agent_id, l.chain_id,
       l.created_at, 'model_call', NULL,
       NULL, ARRAY(SELECT DISTINCT (r.m)[1] FROM regexp_matches(upper(coalesce(l.reason, '') || ' ' || coalesce(l.flags::text, '')), '\m(ASI(0[1-9]|10))\M', 'g') AS r(m)),
       NULL, NULL, l.latency_ms, NULL,
       NULL, NULL, l.model, l.status, l.prompt_tokens, l.completion_tokens, NULL
  FROM gateway_calls l
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
  FROM agent_incidents i"""

# the view as e8f9a0b1c2d3 left it, for downgrade
OLD_VIEW = r"""CREATE VIEW agent_events_v AS
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
  FROM agent_incidents i"""


def upgrade():
    op.add_column("gateway_calls", sa.Column("action_id", sa.Integer(),
                                             sa.ForeignKey("agent_actions.id", ondelete="SET NULL"), nullable=True))
    op.add_column("gateway_calls", sa.Column("chain_id", sa.Integer(),
                                             sa.ForeignKey("delegation_chains.id", ondelete="SET NULL"),
                                             nullable=True))
    op.create_index("ix_gateway_calls_action_id", "gateway_calls", ["action_id"])
    op.execute("DROP VIEW IF EXISTS agent_events_v")
    op.execute(VIEW)
    op.add_column("agent_action_approvals", sa.Column("redeemed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("agent_action_approvals", sa.Column("redeemed_check_id", sa.Integer(),
                                                      sa.ForeignKey("agent_action_checks.id", ondelete="SET NULL"),
                                                      nullable=True))


def downgrade():
    op.drop_column("agent_action_approvals", "redeemed_check_id")
    op.drop_column("agent_action_approvals", "redeemed_at")
    op.execute("DROP VIEW IF EXISTS agent_events_v")
    op.execute(OLD_VIEW)
    op.drop_index("ix_gateway_calls_action_id", table_name="gateway_calls")
    op.drop_column("gateway_calls", "chain_id")
    op.drop_column("gateway_calls", "action_id")
