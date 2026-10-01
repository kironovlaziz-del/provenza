"""agent observability: agent_events_v (metadata-only view over actions, checks, incidents)

Revision ID: d7660f3a8a3d
Revises: 052d753e576c
"""
from alembic import op

revision = "d7660f3a8a3d"
down_revision = "052d753e576c"
branch_labels = None
depends_on = None

VIEW_SQL = r"""
CREATE OR REPLACE VIEW agent_events_v AS
SELECT 'action.recorded'::text AS event_type, a.id AS source_id, a.org_id, a.agent_id, a.chain_id,
       a.created_at AS ts, a.action_type, a.tool_name, a.policy_check_result AS decision,
       ARRAY(SELECT DISTINCT (r.m)[1] FROM regexp_matches(coalesce(a.reason, ''), '\m(ASI(0[1-9]|10))\M', 'g') AS r(m)) AS guards,
       NULL::varchar AS incident_type, NULL::varchar AS severity, a.duration_ms, a.policy_id,
       (a.check_id IS NOT NULL) AS has_check, NULL::boolean AS resolved
  FROM agent_actions a
UNION ALL
SELECT 'action.checked'::text, c.id, c.org_id, c.agent_id, c.chain_id,
       c.created_at, c.action_type, c.tool_name, c.decision,
       ARRAY(SELECT DISTINCT (r.m)[1] FROM regexp_matches(coalesce(c.reason, ''), '\m(ASI(0[1-9]|10))\M', 'g') AS r(m)),
       c.incident_type, NULL::varchar, NULL::integer, c.policy_id,
       NULL::boolean, NULL::boolean
  FROM agent_action_checks c
UNION ALL
SELECT 'incident.created'::text, i.id, i.org_id, i.agent_id, i.chain_id,
       i.created_at, NULL, NULL, NULL,
       ARRAY[]::text[],
       i.incident_type, i.severity, NULL::integer, NULL::integer,
       NULL::boolean, i.resolved
  FROM agent_incidents i
"""


def upgrade():
    op.execute(VIEW_SQL)


def downgrade():
    op.execute("DROP VIEW IF EXISTS agent_events_v")
