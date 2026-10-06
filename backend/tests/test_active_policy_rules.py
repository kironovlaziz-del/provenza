"""
Tests for _active_policy_rules (app/api/providers.py): merging rules across
ALL active policies of an org: approval is required if the latest APPROVED
version of any active policy requires it. (Blocked terms of policies moved
to the Blocked terms page - see tests/test_blocked_terms.py.)

These drive the helper directly against the test DB via small fixtures.
"""

import pytest

from app.api.providers import _active_policy_rules
from app.models.ai_policy import AIPolicy, AIPolicyVersion

pytestmark = pytest.mark.asyncio


async def _make_policy(db, org_id, status, versions, approver_id):
    """versions = list of (version_no, rules_json, approved) tuples."""
    policy = AIPolicy(org_id=org_id, name=f"p-{status}-{id(versions)}", status=status)
    db.add(policy)
    await db.flush()
    for vno, rules, approved in versions:
        db.add(AIPolicyVersion(
            policy_id=policy.id, version=vno, rules_json=rules,
            approved_by=(approver_id if approved else None),
        ))
    await db.flush()
    return policy


async def test_no_active_policies_returns_empty(db_session, org_and_users):
    org_id = org_and_users["org"].id
    admin_id = org_and_users["admin"].id
    rules = await _active_policy_rules(db_session, org_id)
    assert rules == {}


async def test_unapproved_latest_version_is_ignored(db_session, org_and_users):
    org_id = org_and_users["org"].id
    admin_id = org_and_users["admin"].id
    # v1 approved (blocked), v2 NOT approved -> falls back to v1
    # (this is exactly the situation that caused the live bug)
    await _make_policy(db_session, org_id, "active", [
        (1, {"effect": "require_approval"}, True),
        (2, {"effect": "allow"}, False),
    ], admin_id)
    rules = await _active_policy_rules(db_session, org_id)
    assert rules.get("effect") == "require_approval"  # v2 unapproved, ignored


async def test_archived_policy_does_not_apply(db_session, org_and_users):
    org_id = org_and_users["org"].id
    admin_id = org_and_users["admin"].id
    await _make_policy(db_session, org_id, "archived", [(1, {"effect": "require_approval"}, True)], admin_id)
    rules = await _active_policy_rules(db_session, org_id)
    assert rules == {}


async def test_require_approval_if_any_policy_requires(db_session, org_and_users):
    org_id = org_and_users["org"].id
    admin_id = org_and_users["admin"].id
    await _make_policy(db_session, org_id, "active", [(1, {}, True)], admin_id)
    await _make_policy(db_session, org_id, "active", [(1, {"effect": "require_approval"}, True)], admin_id)
    rules = await _active_policy_rules(db_session, org_id)
    assert rules == {"effect": "require_approval"}
