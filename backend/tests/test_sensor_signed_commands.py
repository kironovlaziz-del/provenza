"""
Commands to a sensor that an administrator signed, and the egress proxy
binaries a sensor lets out of a proxy host (docs/pvp/edge.md, section 5).
The sensor checks both against the signed manifest it verified itself
(sensor/internal/trust); here: the server makes the statement, takes only a
command its administrator signed with a passkey-certified session, delivers
the proof, puts the proxy binaries in the manifest and serves the release
chain to sensors.
"""

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from app.models.egress_sensor import EgressSensorCommand
from app.pvp import signed_policy
from app.services.egress_sensor_commands import SIGNED_COMMAND_LIFE, sensor_command_statement
from app.services.signing_sessions import proof_holds
from tests import signer
from tests.conftest import auth_headers

ROOT = Path(__file__).resolve().parents[2]
V = json.loads((ROOT / "sdk" / "testdata" / "sensor-command-vectors.json").read_text(encoding="utf-8"))
S = "/api/v1/egress-sensor"
R = "/api/v1/policy-releases"
BIN = "1f" * 32


@pytest.fixture(autouse=True)
def _fresh_cache():
    signed_policy.forget()
    yield
    signed_policy.forget()


async def _sensor(client, token, name="signed-sensor"):
    r = await client.post(f"{S}/sensors", json={"name": name}, headers=auth_headers(token))
    assert r.status_code == 201, r.text
    return r.json()


async def _signed(client, token, sensor_id, kind="restart"):
    s = await signer.signer(client, token)
    r = await client.post(f"{S}/sensors/{sensor_id}/commands/statement", json={"kind": kind},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    st = r.json()["statement"]
    return st, s.sign(st)


def test_the_vectors_are_what_the_server_signs():
    for who in ("admin", "approver"):
        p = V[who]
        assert proof_holds(p), who
        st = p["statement"]
        assert st == sensor_command_statement(SimpleNamespace(org_id=st["org_id"], id=st["user_id"]),
                                              SimpleNamespace(id=st["session_id"]), st["sensor_id"], st["kind"],
                                              st["nonce"], st["issued_at"])
    assert V["manifest"]["signers"][str(V["admin"]["statement"]["user_id"])]["role"] == "admin"
    assert V["manifest"]["signers"][str(V["approver"]["statement"]["user_id"])]["role"] == "approver"


@pytest.mark.asyncio
async def test_an_administrator_signs_a_command_and_the_sensor_gets_the_proof(client, admin_token):
    sensor = await _sensor(client, admin_token)
    st, sig = await _signed(client, admin_token, sensor["id"])
    assert st["type"] == "provenza.sensor.command" and st["sensor_id"] == sensor["id"] and st["kind"] == "restart"
    assert st["expires_at"] - st["issued_at"] == SIGNED_COMMAND_LIFE and re.match(r"^[\w-]{16,64}$", st["nonce"])

    r = await client.post(f"{S}/sensors/{sensor['id']}/commands",
                          json={"kind": "restart", "statement": st, "signature": sig}, headers=auth_headers(admin_token))
    assert r.status_code == 201, r.text
    assert r.json()["signed_by"] == st["user_id"]

    r = await client.post(f"{S}/heartbeat", json={"hostname": "h"}, headers={"X-Sensor-Key": sensor["api_key"]})
    cmd = r.json()["commands"][0]
    assert cmd["proof"]["statement"] == st and cmd["proof"]["signature"] == sig
    assert proof_holds(cmd["proof"])
    assert cmd["proof"]["certificate"]["statement"]["public_key"] == cmd["proof"]["session_public_key"]
    # the organization's key still signs it too, for a sensor without a pin
    assert cmd["payload"]["kind"] == "restart" and cmd["signature"]

    # the same signed command cannot be queued twice
    r = await client.post(f"{S}/sensors/{sensor['id']}/commands",
                          json={"kind": "restart", "statement": st, "signature": sig}, headers=auth_headers(admin_token))
    assert r.status_code == 422 and r.json()["detail"] == "egress_command.replayed"


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [
    lambda st: st.update(kind="detach"),
    lambda st: st.update(sensor_id=st["sensor_id"] + 1),
    lambda st: st.update(expires_at=st["expires_at"] + 3600),
    lambda st: st.update(user_id=st["user_id"] + 1),
])
async def test_a_changed_statement_is_refused(client, admin_token, change):
    sensor = await _sensor(client, admin_token)
    st, sig = await _signed(client, admin_token, sensor["id"])
    change(st)
    r = await client.post(f"{S}/sensors/{sensor['id']}/commands",
                          json={"kind": "restart", "statement": st, "signature": sig}, headers=auth_headers(admin_token))
    assert r.status_code == 422, r.text
    assert r.json()["detail"] == "session.statement_mismatch"


@pytest.mark.asyncio
async def test_a_bad_signature_or_kind_is_refused(client, admin_token):
    sensor = await _sensor(client, admin_token)
    st, sig = await _signed(client, admin_token, sensor["id"], kind="dump-state")
    r = await client.post(f"{S}/sensors/{sensor['id']}/commands",
                          json={"kind": "restart", "statement": st, "signature": sig}, headers=auth_headers(admin_token))
    assert r.status_code == 422 and r.json()["detail"] == "session.statement_mismatch"
    other = signer.Signer("", None, Ed25519PrivateKey.generate(), "", "")
    r = await client.post(f"{S}/sensors/{sensor['id']}/commands",
                          json={"kind": "dump-state", "statement": st, "signature": other.sign(st)},
                          headers=auth_headers(admin_token))
    assert r.status_code == 403 and r.json()["detail"] == "session.bad_signature"
    r = await client.post(f"{S}/sensors/{sensor['id']}/commands",
                          json={"kind": "dump-state", "statement": dict(st, nonce="x"), "signature": sig},
                          headers=auth_headers(admin_token))
    assert r.status_code == 422 and r.json()["detail"] == "egress_command.not_signed"


@pytest.mark.asyncio
async def test_without_a_signature_only_the_servers_key_signs(client, admin_token, db_session):
    sensor = await _sensor(client, admin_token)
    r = await client.post(f"{S}/sensors/{sensor['id']}/commands", json={"kind": "dump-state"},
                          headers=auth_headers(admin_token))
    assert r.status_code == 201, r.text
    assert r.json()["signed_by"] is None
    row = (await db_session.execute(select(EgressSensorCommand).where(
        EgressSensorCommand.id == r.json()["id"]))).scalar_one()
    assert row.proof is None
    r = await client.post(f"{S}/heartbeat", json={"hostname": "h"}, headers={"X-Sensor-Key": sensor["api_key"]})
    assert r.json()["commands"][0]["proof"] is None


@pytest.mark.asyncio
async def test_only_an_administrator_gets_a_statement(client, admin_token, approver_token):
    sensor = await _sensor(client, admin_token)
    r = await client.post(f"{S}/sensors/{sensor['id']}/commands/statement", json={"kind": "restart"},
                          headers=auth_headers(approver_token))
    assert r.status_code == 403
    # an administrator whose session no passkey certified cannot sign
    r = await client.post(f"{S}/sensors/{sensor['id']}/commands/statement", json={"kind": "restart"},
                          headers=auth_headers(admin_token))
    assert r.status_code == 403 and r.json()["detail"] in ("session.not_certified", "session.not_signing")
    r = await client.post(f"{S}/sensors/{sensor['id']}/commands/statement", json={"kind": "update-signing-key"},
                          headers=auth_headers(admin_token))
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_the_proxy_binaries_are_in_the_manifest_and_sensors_get_the_chain(client, admin_token):
    sensor = await _sensor(client, admin_token)
    key = {"X-Sensor-Key": sensor["api_key"]}
    assert (await client.get(f"{S}/policy-release", headers=key)).json() == {"current": None, "chain": []}

    cfg = (await client.get(f"{R}/state", headers=auth_headers(admin_token))).json()["settings"]
    assert cfg["proxy_binaries"] == []
    for bad in (["abc"], ["G" * 64], ["ab" * 32] * 21):
        r = await client.put(f"{R}/settings", json={**cfg, "proxy_binaries": bad}, headers=auth_headers(admin_token))
        assert r.status_code == 422, bad
    assert cfg["proxy_configs"] == []
    r = await client.put(f"{R}/settings", json={**cfg, "proxy_configs": ["xyz"]}, headers=auth_headers(admin_token))
    assert r.status_code == 422 and r.json()["detail"]["context"]["field"] == "proxy_configs"
    r = await client.put(f"{R}/settings", json={**cfg, "proxy_binaries": [BIN.upper(), BIN, "ab" * 32],
                                                "proxy_configs": ["cd" * 32]}, headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    assert r.json()["proxy_binaries"] == ["1f" * 32, "ab" * 32] and r.json()["proxy_configs"] == ["cd" * 32]
    # a PUT without them keeps them
    keep = {k: v for k, v in r.json().items() if k not in ("proxy_binaries", "proxy_configs")}
    r = await client.put(f"{R}/settings", json=keep, headers=auth_headers(admin_token))
    assert r.json()["proxy_configs"] == ["cd" * 32]

    await signer.signer(client, admin_token)
    draft = (await client.post(f"{R}/prepare", headers=auth_headers(admin_token))).json()["draft"]
    assert any(c["section"] == "manifest.proxy_binaries" for c in draft["changes"])
    assert any(c["section"] == "manifest.proxy_configs" for c in draft["changes"])
    s = await signer.signer(client, admin_token)
    ch = (await client.post(f"{R}/{draft['id']}/challenge", headers=auth_headers(admin_token))).json()
    r = await client.post(f"{R}/{draft['id']}/sign", json={"statement": ch["statement"],
                                                           "assertion": s.device.get(ch["challenge"])},
                          headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text

    got = (await client.get(f"{S}/policy-release?after=0", headers=key)).json()
    assert got["current"] == draft["number"] and len(got["chain"]) == 1
    manifest = got["chain"][0]["manifest"]
    assert manifest["proxy_binaries"] == ["1f" * 32, "ab" * 32] and manifest["proxy_configs"] == ["cd" * 32]
    assert str(sensor["id"]) in manifest["egress_sensors"]
    assert (await client.get(f"{S}/policy-release?after={draft['number']}", headers=key)).json()["chain"] == []
    assert (await client.get(f"{S}/policy-release")).status_code == 401


@pytest.mark.asyncio
async def test_no_proxy_binaries_leave_the_manifest_as_it_was(db_session, org_and_users):
    """A release made before proxy binaries existed shows no change for them."""
    from app.pvp import policy_bundle as pb

    org = org_and_users["org"].id
    assert "proxy_binaries" not in await pb.manifest_content(db_session, org, 1)
    assert "proxy_binaries" not in await pb.manifest_content(db_session, org, 1, [])
    assert (await pb.manifest_content(db_session, org, 1, ["ab" * 32]))["proxy_binaries"] == ["ab" * 32]
    assert "proxy_configs" not in await pb.manifest_content(db_session, org, 1, ["ab" * 32], [])
    assert (await pb.manifest_content(db_session, org, 1, None, ["cd" * 32]))["proxy_configs"] == ["cd" * 32]


@pytest.mark.asyncio
async def test_the_heartbeat_reports_what_the_sensor_verified(client, admin_token):
    sensor = await _sensor(client, admin_token)
    key = {"X-Sensor-Key": sensor["api_key"]}
    r = await client.post(f"{S}/heartbeat", json={
        "hostname": "proxy-1",
        "signed_policy": {"pin": "pinned", "release": 3},
        "proxy_runs": [{"cgroup": "provenza-run/provenza-proxy-0011223344556677", "state": "verified",
                        "processes": 1, "sha256": BIN},
                       {"cgroup": "provenza-run/provenza-proxy-8899aabbccddeeff", "state": "held",
                        "processes": 1, "reason": "process 7 runs 00ff, not a pinned egress proxy binary"}]},
        headers=key)
    assert r.status_code == 200, r.text
    got = (await client.get(f"{S}/sensors/{sensor['id']}", headers=auth_headers(admin_token))).json()
    assert got["trust"]["signed_policy"] == {"pin": "pinned", "release": 3}
    assert [x["state"] for x in got["trust"]["proxy_runs"]] == ["verified", "held"]
    # a sensor without a pin reports nothing of it
    await client.post(f"{S}/heartbeat", json={"hostname": "proxy-1"}, headers=key)
    got = (await client.get(f"{S}/sensors/{sensor['id']}", headers=auth_headers(admin_token))).json()
    assert got["trust"] is None


def test_the_sensor_carries_the_proxys_trust_package():
    """sensor/internal/{trust,canon} are copies of proxy/internal/{trust,canon}
    (the sensor's own commands are in trust/command.go): they must not drift."""
    for pkg in ("trust", "canon"):
        proxy = ROOT / "proxy" / "internal" / pkg
        sensor = ROOT / "sensor" / "internal" / pkg
        names = {p.name for p in proxy.glob("*.go")}
        assert names <= {p.name for p in sensor.glob("*.go")}, pkg
        for name in names:
            a = (proxy / name).read_text(encoding="utf-8").replace("provenza/proxy/internal/", "provenza/X/internal/")
            b = (sensor / name).read_text(encoding="utf-8").replace("provenza/sensor/internal/", "provenza/X/internal/")
            assert a == b, f"{pkg}/{name} differs between the proxy and the sensor"


@pytest.mark.asyncio
async def test_workloads_are_in_the_signed_bundle(client, admin_token, db_session, org_and_users):
    """A sensor that follows the signed policy holds each workload to its signed
    version (sensor/internal/daemon/signedwl.go): the bundle carries them."""
    from app.pvp import policy_bundle as pb

    body = {"name": "payer", "cgroup_patterns": ["system.slice/payer.service"],
            "egress_allow": [{"dest": "10.0.0.0/24", "ports": [8443, 443], "protocols": ["tcp"]}],
            "ingress_allow": [], "dns": "off", "mode": "enforce"}
    w = (await client.post(f"{S}/workloads", json=body, headers=auth_headers(admin_token))).json()
    gone = (await client.post(f"{S}/workloads", json={**body, "name": "gone"}, headers=auth_headers(admin_token))).json()
    assert (await client.delete(f"{S}/workloads/{gone['id']}", headers=auth_headers(admin_token))).status_code in (200, 204)

    section = (await pb.bundle_content(db_session, org_and_users["org"].id))["egress_workloads"]
    assert set(section) == {str(w["id"])}
    assert section[str(w["id"])] == {
        "name": "payer", "agent_id": None, "cgroup_patterns": ["system.slice/payer.service"], "run_as_users": [],
        "egress_allow": [{"dest": "10.0.0.0/24", "ports": [443, 8443], "protocols": ["tcp"]}], "ingress_allow": [],
        "dns": "off", "mode": "enforce", "isolated": False, "enabled": True}

    await signer.signer(client, admin_token)
    draft = (await client.post(f"{R}/prepare", headers=auth_headers(admin_token))).json()["draft"]
    assert any(c["section"] == "egress_workloads" and c["key"] == str(w["id"]) for c in draft["changes"])
