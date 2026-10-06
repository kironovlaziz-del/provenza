"""blocked terms in one place: scopes, word matching, block or monitor, categories

Revision ID: b5e7a9c1d3f6
Revises: a3d5f7b9c1e4

Existing terms move here and keep applying where they applied:
  * gateway settings      -> scope "agents" (every agent's gateway calls)
  * policy hierarchy      -> scope org / team / agent of its level; the
                             level's document loses content.blocked_terms
  * policy versions       -> scope "policy": the terms of each policy's
                             latest approved version and of every version a
                             use case is linked to
They are matched "anywhere" (substring), as before; switch them to "whole
word" on the Blocked terms page. Old policy versions keep their rules as
history; their terms no longer apply from there.
"""
import json

import sqlalchemy as sa
from alembic import op

revision = "b5e7a9c1d3f6"
down_revision = "a3d5f7b9c1e4"
branch_labels = None
depends_on = None


def _key(term):
    from app.core.term_match import term_key

    return term_key(term)


def upgrade():
    op.create_table(
        "blocked_term_categories",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_blocked_term_categories_org_id", "blocked_term_categories", ["org_id"])
    op.create_index("uq_blocked_term_categories_name", "blocked_term_categories", ["org_id", "name"], unique=True)
    op.create_table(
        "blocked_terms",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("term", sa.String(200), nullable=False),
        sa.Column("key", sa.String(400), nullable=False),
        sa.Column("match", sa.String(10), nullable=False, server_default="word"),
        sa.Column("action", sa.String(10), nullable=False, server_default="block"),
        sa.Column("scope", sa.String(10), nullable=False, server_default="org"),
        sa.Column("team_id", sa.Integer(), sa.ForeignKey("teams.id", ondelete="SET NULL")),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="SET NULL")),
        sa.Column("policy_id", sa.Integer(), sa.ForeignKey("ai_policies.id", ondelete="SET NULL")),
        sa.Column("category_id", sa.Integer(), sa.ForeignKey("blocked_term_categories.id", ondelete="SET NULL")),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("note", sa.Text()),
        sa.Column("hits", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_hit_at", sa.DateTime(timezone=True)),
        sa.Column("source", sa.String(40)),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("scope IN ('org', 'agents', 'team', 'agent', 'policy')", name="ck_blocked_terms_scope"),
        sa.CheckConstraint("deleted_at IS NOT NULL OR ((scope = 'team') = (team_id IS NOT NULL) AND (scope = 'agent') = "
                           "(agent_id IS NOT NULL) AND (scope = 'policy') = (policy_id IS NOT NULL))",
                           name="ck_blocked_terms_target"),
        sa.CheckConstraint("match IN ('word', 'substring')", name="ck_blocked_terms_match"),
        sa.CheckConstraint("action IN ('block', 'monitor')", name="ck_blocked_terms_action"),
    )
    op.create_index("ix_blocked_terms_org_id", "blocked_terms", ["org_id"])
    op.create_index("uq_blocked_terms_live", "blocked_terms",
                    ["org_id", "scope", sa.text("coalesce(team_id, agent_id, policy_id, 0)"), "key"], unique=True,
                    postgresql_where=sa.text("deleted_at IS NULL"))

    conn = op.get_bind()
    seen = set()

    def add(org_id, scope, target, term, source):
        term = " ".join(str(term or "").replace("\x00", "").split())[:200]
        key = _key(term)
        if not 2 <= len(key) <= 400 or (org_id, scope, target or 0, key) in seen:
            return
        seen.add((org_id, scope, target or 0, key))
        conn.execute(sa.text(
            "INSERT INTO blocked_terms (org_id, term, key, match, action, scope, team_id, agent_id, policy_id, source) "
            "VALUES (:org, :term, :key, 'substring', 'block', :scope, :team, :agent, :policy, :source)"),
            {"org": org_id, "term": term, "key": key, "scope": scope, "source": source[:40],
             "team": target if scope == "team" else None, "agent": target if scope == "agent" else None,
             "policy": target if scope == "policy" else None})

    # gateway settings -> every agent
    for org_id, terms in conn.execute(sa.text("SELECT org_id, blocked_terms FROM gateway_settings")).all():
        for t in (terms if isinstance(terms, list) else json.loads(terms or "[]")) or []:
            add(org_id, "agents", None, t, "gateway")
    conn.execute(sa.text("UPDATE gateway_settings SET blocked_terms = '[]'::jsonb"))

    # policy hierarchy levels
    rows = conn.execute(sa.text(
        "SELECT id, org_id, scope, team_id, agent_id, document FROM policy_layers "
        "WHERE document -> 'content' ? 'blocked_terms'")).all()
    for layer_id, org_id, scope, team_id, agent_id, doc in rows:
        doc = doc if isinstance(doc, dict) else json.loads(doc)
        for t in (doc.get("content") or {}).get("blocked_terms") or []:
            add(org_id, scope, team_id or agent_id, t, f"layer:{scope}:{layer_id}")
        content = {k: v for k, v in (doc.get("content") or {}).items() if k != "blocked_terms"}
        if content:
            doc["content"] = content
        else:
            doc.pop("content", None)
        # the YAML the admin wrote still names them: shown from the document from now on
        conn.execute(sa.text("UPDATE policy_layers SET document = CAST(:doc AS jsonb), source_yaml = NULL "
                             "WHERE id = :id"), {"doc": json.dumps(doc), "id": layer_id})

    # policy versions: the latest approved one of each policy, and every one a use case is linked to
    rows = conn.execute(sa.text(
        "SELECT p.org_id, p.id, v.rules_json FROM ai_policy_versions v JOIN ai_policies p ON p.id = v.policy_id "
        "WHERE v.rules_json ? 'blocked_terms' AND v.approved_at IS NOT NULL AND ("
        "  v.id IN (SELECT approved_policy_version_id FROM ai_use_cases WHERE approved_policy_version_id IS NOT NULL)"
        "  OR v.version = (SELECT max(v2.version) FROM ai_policy_versions v2"
        "                  WHERE v2.policy_id = v.policy_id AND v2.approved_at IS NOT NULL))")).all()
    for org_id, policy_id, rules in rows:
        rules = rules if isinstance(rules, dict) else json.loads(rules)
        for t in rules.get("blocked_terms") or []:
            add(org_id, "policy", policy_id, t, f"policy:{policy_id}")


def downgrade():
    # terms added here are not written back into the places they came from
    op.drop_index("uq_blocked_terms_live", table_name="blocked_terms")
    op.drop_index("ix_blocked_terms_org_id", table_name="blocked_terms")
    op.drop_table("blocked_terms")
    op.drop_index("uq_blocked_term_categories_name", table_name="blocked_term_categories")
    op.drop_index("ix_blocked_term_categories_org_id", table_name="blocked_term_categories")
    op.drop_table("blocked_term_categories")
