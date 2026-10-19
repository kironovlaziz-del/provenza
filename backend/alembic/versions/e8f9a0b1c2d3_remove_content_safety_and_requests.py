"""Remove the content-safety features and the request pipeline

Revision ID: e8f9a0b1c2d3
Revises: d7e8f9a0b1c2

Provenza is an AI and agent governance control plane; the Prompt Firewall,
PII masking, blocked terms, the intent guardrail, the injection / code /
memory / agent-message guards, the Playground, the Usage log with its queue,
approvals and overrides, and the Policy Center are removed. Their tables are
dropped WITH THEIR DATA, as decided; take a backup first if you may want it.

Also:
  * agent_events_v is recreated without agent-to-agent messages;
  * the links to the dropped tables go: ai_incidents.request_id,
    gateway_calls.ai_request_id, ai_use_cases.approved_policy_version_id;
  * delegation chains lose their prompt-injection taint (tainted_at,
    taint_details): nothing sets or enforces it any more;
  * the LLM gateway keeps no prompt and no output scanning switch:
    gateway_settings.blocked_terms / scan_output go;
  * queue_settings / queue_sweeps become retention_settings / retention_runs,
    keeping only the retention of agent telemetry;
  * the policy hierarchy loses its "content" and "requests" sections; a
    level whose YAML mentioned them gets its YAML rebuilt from the document;
  * notification channels stop listing "request_blocked" and
    "approval_pending": nothing sends them any more.

There is no way back: downgrade refuses.
"""
from alembic import op

revision = "e8f9a0b1c2d3"
down_revision = "d7e8f9a0b1c2"
branch_labels = None
depends_on = None

# children before parents
DROPPED_TABLES = [
    "ai_actions", "ai_approvals", "ai_overrides", "ai_responses", "ai_requests",
    "blocked_terms", "blocked_term_categories", "ai_policy_versions", "ai_policies",
    "pii_rules", "pii_settings", "guardrail_settings",
    "injection_detections", "injection_settings", "code_exec_detections", "code_exec_settings",
    "memory_entries", "memory_settings", "a2a_messages", "a2a_channels", "a2a_settings",
]

VIEW = r"""CREATE VIEW agent_events_v AS
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
    # the view reads a2a_messages: rebuilt first, without it
    op.execute("DROP VIEW IF EXISTS agent_events_v")
    op.execute(VIEW)

    op.drop_column("ai_incidents", "request_id")
    op.drop_column("gateway_calls", "ai_request_id")
    op.drop_column("ai_use_cases", "approved_policy_version_id")
    op.drop_column("delegation_chains", "tainted_at")
    op.drop_column("delegation_chains", "taint_details")
    for table in DROPPED_TABLES:
        op.execute(f'DROP TABLE IF EXISTS "{table}"')

    op.drop_column("gateway_settings", "blocked_terms")
    op.drop_column("gateway_settings", "scan_output")

    # queue settings -> retention settings
    for col in ("queue_ttl_seconds", "approval_ttl_hours", "raw_prompt_retention_days"):
        op.drop_column("queue_settings", col)
    for col in ("expired_queued", "expired_approvals", "failed_stuck", "purged_prompts"):
        op.drop_column("queue_sweeps", col)
    op.rename_table("queue_settings", "retention_settings")
    op.rename_table("queue_sweeps", "retention_runs")
    for old, new in (
        ("queue_settings_id_seq", "retention_settings_id_seq"),
        ("queue_sweeps_id_seq", "retention_runs_id_seq"),
    ):
        op.execute(f"ALTER SEQUENCE {old} RENAME TO {new}")
    for old, new in (
        ("queue_settings_pkey", "retention_settings_pkey"),
        ("ix_queue_settings_id", "ix_retention_settings_id"),
        ("queue_settings_org_id_key", "retention_settings_org_id_key"),
        ("queue_sweeps_pkey", "retention_runs_pkey"),
        ("ix_queue_sweeps_id", "ix_retention_runs_id"),
        ("ix_queue_sweeps_org_id", "ix_retention_runs_org_id"),
        ("ix_queue_sweeps_ran_at", "ix_retention_runs_ran_at"),
    ):
        op.execute(f"ALTER INDEX {old} RENAME TO {new}")
    for table, old, new in (
        ("retention_settings", "queue_settings_org_id_fkey", "retention_settings_org_id_fkey"),
        ("retention_settings", "queue_settings_updated_by_fkey", "retention_settings_updated_by_fkey"),
        ("retention_runs", "queue_sweeps_org_id_fkey", "retention_runs_org_id_fkey"),
    ):
        op.execute(f"ALTER TABLE {table} RENAME CONSTRAINT {old} TO {new}")

    # policy documents: the removed sections go; the YAML the admin typed is
    # kept unless it mentioned them (it is rebuilt from the document then)
    op.execute(r"""
        UPDATE policy_layers
           SET document = document - 'content' - 'requests', source_yaml = NULL
         WHERE document ? 'content' OR document ? 'requests'
            OR source_yaml ~ '(^|\n)\s*(content|requests)\s*:'
    """)

    # notification channels: nothing sends "request_blocked" (the Prompt
    # Firewall) or "approval_pending" (usage-request approvals) any more
    op.execute("""
        UPDATE notification_channels
           SET events_json = COALESCE((SELECT jsonb_agg(e)
                                         FROM jsonb_array_elements(events_json) AS e
                                        WHERE e #>> '{}' NOT IN ('request_blocked', 'approval_pending')),
                                      '[]'::jsonb)
         WHERE events_json ?| array['request_blocked', 'approval_pending']
    """)


def downgrade():
    raise RuntimeError("e8f9a0b1c2d3 dropped the tables of the removed features with their data; "
                       "restore a backup taken before the upgrade instead of downgrading")
