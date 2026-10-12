"""All kinds of agent incidents are listable and filterable, and reviewers can
mark them handled (the unified Incidents page)."""

import pytest

from app.models.agent_action import AgentIncident
from tests.conftest import auth_headers

I = "/api/v1/agents/incidents"


async def _seed(db, org_id):
    db.add_all([
        AgentIncident(org_id=org_id, incident_type="action_mismatch", severity="critical", details={"via": "egress_proxy"}),
        AgentIncident(org_id=org_id, incident_type="capability_escalation", severity="high", details={}),
        AgentIncident(org_id=org_id, incident_type="capability_escalation", severity="high", details={}, resolved=True),
    ])
    await db.flush()


@pytest.mark.asyncio
async def test_every_type_is_listed_with_counts(client, db_session, org_and_users, admin_token):
    await _seed(db_session, org_and_users["org"].id)
    types = (await client.get(f"{I}/types", headers=auth_headers(admin_token))).json()
    assert types == [{"incident_type": "action_mismatch", "total": 1, "unresolved": 1},
                     {"incident_type": "capability_escalation", "total": 2, "unresolved": 1}]
    crit = (await client.get(f"{I}/", params={"severity": "critical"}, headers=auth_headers(admin_token))).json()
    assert [i["incident_type"] for i in crit["items"]] == ["action_mismatch"]


@pytest.mark.asyncio
async def test_reviewers_resolve_and_reopen(client, db_session, org_and_users, admin_token, approver_token):
    await _seed(db_session, org_and_users["org"].id)
    [inc] = (await client.get(f"{I}/", params={"incident_type": "action_mismatch"},
                              headers=auth_headers(admin_token))).json()["items"]
    r = await client.post(f"{I}/{inc['id']}/resolve", json={"note": "proxy misconfigured"},
                          headers=auth_headers(approver_token))
    assert r.status_code == 200 and r.json()["resolved"] is True
    open_ = (await client.get(f"{I}/", params={"unresolved_only": True}, headers=auth_headers(admin_token))).json()
    assert inc["id"] not in [i["id"] for i in open_["items"]]
    r = await client.post(f"{I}/{inc['id']}/resolve", json={"resolved": False}, headers=auth_headers(admin_token))
    assert r.json()["resolved"] is False
    assert (await client.post(f"{I}/999999/resolve", json={}, headers=auth_headers(admin_token))).status_code == 404
