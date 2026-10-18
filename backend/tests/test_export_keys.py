"""Export keys: a read-only credential a SIEM uses for the egress event feed
(X-Export-Key), made and revoked by an organization's administrator."""

from tests.conftest import _create_org_with_admin_and_approver, _login, auth_headers

KEYS = "/api/v1/export-keys/"
EVENTS = "/api/v1/egress-sensor/events"


async def _key(client, token, name="siem") -> dict:
    r = await client.post(KEYS, json={"name": name}, headers=auth_headers(token))
    assert r.status_code == 201, r.text
    return r.json()


async def _violation(client, token, comm: str) -> None:
    r = await client.post("/api/v1/egress-sensor/sensors", json={"name": f"s-{comm}"}, headers=auth_headers(token))
    sensor = r.json()
    r = await client.post("/api/v1/egress-sensor/workloads",
                          json={"name": f"wl-{comm}", "mode": "observe", "dns": "off", "cgroup_patterns": []},
                          headers=auth_headers(token))
    wl = r.json()
    r = await client.post("/api/v1/egress-sensor/violations",
                          json={"events": [{"workload_id": wl["id"], "action": "blocked", "kind": "connect", "comm": comm}]},
                          headers={"X-Sensor-Key": sensor["api_key"]})
    assert r.status_code == 200, r.text


async def test_key_is_shown_once_and_reads_the_feed(client, admin_token):
    created = await _key(client, admin_token)
    assert created["api_key"].startswith("pvx_")
    assert created["key_prefix"] == created["api_key"][:12]
    listed = (await client.get(KEYS, headers=auth_headers(admin_token))).json()
    assert [k["id"] for k in listed] == [created["id"]]
    assert "api_key" not in listed[0]

    await _violation(client, admin_token, "via-key")
    r = await client.get(EVENTS, headers={"X-Export-Key": created["api_key"]})
    assert r.status_code == 200, r.text
    assert any(e["comm"] == "via-key" for e in r.json()["events"])
    listed = (await client.get(KEYS, headers=auth_headers(admin_token))).json()
    assert listed[0]["last_used_at"] is not None


async def test_revoked_or_unknown_key_is_refused(client, admin_token):
    created = await _key(client, admin_token)
    r = await client.post(f"{KEYS}{created['id']}/revoke", headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["revoked_at"] is not None
    for key in (created["api_key"], "pvx_not-a-key"):
        r = await client.get(EVENTS, headers={"X-Export-Key": key})
        assert r.status_code == 401
        assert r.json()["detail"] == "export_key.invalid"
    # revoked, not deleted: still listed
    assert len((await client.get(KEYS, headers=auth_headers(admin_token))).json()) == 1


async def test_a_key_reads_its_own_organization_only(client, admin_token, db_session):
    await _violation(client, admin_token, "org-a")
    other = await _create_org_with_admin_and_approver(
        db_session, org_slug="export-other",
        admin_email="admin@export-other.example.com", approver_email="approver@export-other.example.com",
    )
    other_token = await _login(client, "export-other", other["admin"].email, other["password"])
    key = await _key(client, other_token)
    r = await client.get(f"{EVENTS}?limit=2000", headers={"X-Export-Key": key["api_key"]})
    assert r.status_code == 200
    assert not any(e["comm"] == "org-a" for e in r.json()["events"])
    # and its admin cannot revoke the first organization's keys
    mine = await _key(client, admin_token)
    r = await client.post(f"{KEYS}{mine['id']}/revoke", headers=auth_headers(other_token))
    assert r.status_code == 404


async def test_only_admins_manage_keys(client, approver_token):
    assert (await client.get(KEYS, headers=auth_headers(approver_token))).status_code == 403
    assert (await client.post(KEYS, json={"name": "x"}, headers=auth_headers(approver_token))).status_code == 403
