# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
RFC 3161 witnesses for the audit log (app/services/audit_witness.py): the
TSA is tested before it is saved, checkpoints get verified tokens, a TSA
that fails keeps nothing, and the tokens cannot be changed afterwards.
"""

import base64
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.core import rfc3161
from app.core.config import settings
from app.models.audit_log import AuditCheckpoint, AuditCheckpointTimestamp, AuditTsaSettings
from app.services import audit_witness
from tests.conftest import auth_headers
from tests.tsa_helpers import FakeTSA

A = "/api/v1/audit-logs"
VECTOR = json.loads((Path(__file__).parent / "data" / "freetsa_vector.json").read_text())


class TsaServer:
    def __init__(self, tsa: FakeTSA):
        self.tsa, self.down = tsa, False
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                if outer.down or self.headers.get("Content-Type") != "application/timestamp-query":
                    self.send_response(503)
                    self.end_headers()
                    return
                out = outer.tsa.respond(body)
                self.send_response(200)
                self.send_header("Content-Type", "application/timestamp-reply")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/tsr"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def tsa(monkeypatch):
    monkeypatch.setattr(settings, "OUTBOUND_PRIVATE_ALLOWLIST", "127.0.0.1")
    server = TsaServer(FakeTSA())
    yield server
    server.close()


async def _configure(client, token, tsa, **over):
    body = {"url": tsa.url, "trust_pem": tsa.tsa.ca_pem, **over}
    return await client.put(f"{A}/tsa", json=body, headers=auth_headers(token))


def test_a_real_tsa_token_verifies_offline():
    """A token FreeTSA issued (tests/data/freetsa_vector.json): real-world DER."""
    digest = hashlib.sha256(VECTOR["data"].encode()).digest()
    tok = rfc3161.verify_token(base64.b64decode(VECTOR["token_b64"]), digest, rfc3161.load_anchors(VECTOR["ca_pem"]),
                               nonce=VECTOR["nonce"])
    assert tok.gen_time.isoformat() == VECTOR["gen_time"] and tok.serial == VECTOR["serial"]
    assert "freetsa.org" in tok.tsa_subject
    with pytest.raises(rfc3161.TimestampError):
        rfc3161.verify_token(base64.b64decode(VECTOR["token_b64"]), hashlib.sha256(b"other").digest(),
                             rfc3161.load_anchors(VECTOR["ca_pem"]))


@pytest.mark.asyncio
async def test_configuring_a_tsa_tests_it_first(client, admin_token, approver_token, tsa, db_session):
    assert (await _configure(client, approver_token, tsa)).status_code == 403
    r = await _configure(client, admin_token, tsa, trust_pem="-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----")
    assert r.status_code == 422
    r = await _configure(client, admin_token, tsa, trust_pem=FakeTSA().ca_pem)       # another CA
    assert r.status_code == 422 and r.json()["detail"]["code"] == "tsa.untrusted"
    tsa.down = True
    r = await _configure(client, admin_token, tsa)
    assert r.status_code == 422 and r.json()["detail"]["code"] == "tsa.http_error"
    assert (await db_session.execute(select(AuditTsaSettings))).scalars().all() == []    # nothing stored
    tsa.down = False
    asked = len(tsa.tsa.requests)
    r = await _configure(client, admin_token, tsa)
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] and r.json()["trust_subjects"] == ["CN=Test TSA Root"]
    assert len(tsa.tsa.requests) == asked + 1          # asked once before saving
    assert (await client.get(f"{A}/tsa", headers=auth_headers(approver_token))).json()["url"] == tsa.url


@pytest.mark.asyncio
async def test_checkpoints_get_verified_tokens(client, admin_token, tsa, db_session):
    assert (await _configure(client, admin_token, tsa)).status_code == 200
    cp = (await client.post(f"{A}/checkpoints", headers=auth_headers(admin_token))).json()
    r = await client.post(f"{A}/tsa/stamp", headers=auth_headers(admin_token))
    assert r.json()["stamped"] >= 1 and r.json()["failed"] == 0
    assert (await client.post(f"{A}/tsa/stamp", headers=auth_headers(admin_token))).json()["stamped"] == 0

    listed = (await client.get(f"{A}/checkpoints", headers=auth_headers(admin_token))).json()
    mine = next(c for c in listed if c["tree_size"] == cp["tree_size"])
    assert len(mine["timestamps"]) == 1
    stamp = mine["timestamps"][0]
    # what an auditor does with the export: the token is for exactly this statement
    tok = rfc3161.verify_token(base64.b64decode(stamp["token"]), hashlib.sha256(mine["statement"].encode()).digest(),
                               rfc3161.load_anchors(tsa.tsa.ca_pem))
    assert tok.gen_time.isoformat() == stamp["gen_time"]

    # and they travel with the consistency proof
    await client.post(f"{A}/checkpoints", headers=auth_headers(admin_token))
    doc = (await client.get(f"{A}/consistency", params={"from_size": cp["tree_size"]},
                            headers=auth_headers(admin_token))).json()
    assert len(doc["old"]["timestamps"]) == 1

    # append-only: a token cannot be changed or removed
    with pytest.raises(DBAPIError):
        async with db_session.begin_nested():
            await db_session.execute(text("UPDATE audit_checkpoint_timestamps SET serial = 'x'"))


@pytest.mark.asyncio
async def test_a_failing_tsa_keeps_nothing_and_says_why(client, admin_token, tsa, db_session):
    assert (await _configure(client, admin_token, tsa)).status_code == 200
    await client.post(f"{A}/checkpoints", headers=auth_headers(admin_token))
    tsa.down = True
    r = await client.post(f"{A}/tsa/stamp", headers=auth_headers(admin_token))
    assert r.json() == {"stamped": 0, "failed": 1}
    st = (await client.get(f"{A}/tsa", headers=auth_headers(admin_token))).json()
    assert st["last_error"].startswith("tsa.http_error")
    assert (await db_session.execute(select(AuditCheckpointTimestamp))).scalars().all() == []
    tsa.down = False
    assert (await client.post(f"{A}/tsa/stamp", headers=auth_headers(admin_token))).json()["stamped"] >= 1
    assert (await client.get(f"{A}/tsa", headers=auth_headers(admin_token))).json()["last_error"] is None


def test_what_is_stamped_is_the_statement():
    assert audit_witness.digest_of('{"a":1}') == hashlib.sha256(b'{"a":1}').digest()


ROOT = Path(__file__).resolve().parents[2]


def _tool():
    import importlib.util

    spec = importlib.util.spec_from_file_location("provenza_audit_tool_tsa", ROOT / "tools" / "provenza_audit.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_offline_copy_is_the_servers():
    """tools/rfc3161.py ships with the standalone verifier; it must not drift."""
    assert (ROOT / "tools" / "rfc3161.py").read_bytes() == (ROOT / "backend" / "app" / "core" / "rfc3161.py").read_bytes()


@pytest.mark.asyncio
async def test_the_offline_verifier_checks_the_time_stamps(client, admin_token, tsa, tmp_path, capsys):
    assert (await _configure(client, admin_token, tsa)).status_code == 200
    first = (await client.post(f"{A}/checkpoints", headers=auth_headers(admin_token))).json()
    await client.post(f"{A}/tsa/stamp", headers=auth_headers(admin_token))
    cp = next(c for c in (await client.get(f"{A}/checkpoints", headers=auth_headers(admin_token))).json()
              if c["tree_size"] == first["tree_size"])
    (tmp_path / "cp.json").write_text(json.dumps(cp))
    (tmp_path / "tsa.pem").write_text(tsa.tsa.ca_pem)
    (tmp_path / "other.pem").write_text(FakeTSA().ca_pem)
    tool = _tool()
    assert tool.main(["checkpoint", str(tmp_path / "cp.json"), "--tsa-ca", str(tmp_path / "tsa.pem")]) == 0
    assert "time-stamped" in capsys.readouterr().out
    assert tool.main(["checkpoint", str(tmp_path / "cp.json"), "--tsa-ca", str(tmp_path / "other.pem")]) == 1
    assert "tsa.untrusted" in capsys.readouterr().out

    # later: the log grew; the auditor's saved copy is pinned, its time-stamp checked too
    await client.put(f"{A}/tsa", json={"url": tsa.url, "trust_pem": tsa.tsa.ca_pem}, headers=auth_headers(admin_token))
    await client.post(f"{A}/checkpoints", headers=auth_headers(admin_token))
    doc = (await client.get(f"{A}/consistency", params={"from_size": cp["tree_size"]},
                            headers=auth_headers(admin_token))).json()
    (tmp_path / "cons.json").write_text(json.dumps(doc))
    assert tool.main(["consistency", str(tmp_path / "cons.json"), "--pinned", str(tmp_path / "cp.json"),
                      "--tsa-ca", str(tmp_path / "tsa.pem")]) == 0
    out = capsys.readouterr().out
    assert "extends" in out and "time-stamped" in out

    # a checkpoint without its time-stamp does not pass when one is required
    bare = {**cp, "timestamps": []}
    (tmp_path / "bare.json").write_text(json.dumps(bare))
    assert tool.main(["checkpoint", str(tmp_path / "bare.json"), "--tsa-ca", str(tmp_path / "tsa.pem")]) == 1


@pytest.mark.asyncio
async def test_switching_off_keeps_the_trust_anchor(client, admin_token, tsa):
    assert (await _configure(client, admin_token, tsa)).status_code == 200
    r = await client.put(f"{A}/tsa", json={"enabled": False, "url": tsa.url}, headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["enabled"] is False and r.json()["trust_subjects"] == ["CN=Test TSA Root"]
    assert (await client.post(f"{A}/tsa/stamp", headers=auth_headers(admin_token))).json()["stamped"] == 0
