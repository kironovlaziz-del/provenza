# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Discovery must not become a way to capture directory credentials.

An ingestion key is a machine credential that ships to employee devices.
Whoever holds one must not be able to plant an "Active Directory" server,
or move a real one to a cleartext port, and then wait for an admin to
type the service-account password into the connect wizard.
"""

import ssl
import sys
import types

import pytest
from sqlalchemy import select

from app.core.security import generate_api_key, hash_api_key
from app.models.discovered_service import DiscoveredService
from app.models.ingestion_source import IngestionSource
from app.models.service_connection import ServiceConnection
from tests.conftest import auth_headers

R = "/api/v1/discovery"


async def _source(db, org_id, source_type):
    key = generate_api_key()
    db.add(IngestionSource(org_id=org_id, name=f"{source_type}-1", source_type=source_type,
                           api_key_hash=hash_api_key(key), enabled=True))
    await db.flush()
    return {"X-Ingestion-Key": key}


def _report(host="dc1.corp.local", port=636, service_type="active_directory"):
    return {"services": [{"service_type": service_type, "host": host, "port": port, "discovered_via": "ldap_probe"}]}


async def test_browser_extension_key_cannot_report_services(client, db_session, org_and_users):
    headers = await _source(db_session, org_and_users["org"].id, "browser_extension")
    resp = await client.post(f"{R}/report", json=_report(), headers=headers)
    assert resp.status_code == 403
    assert resp.json()["detail"] == "ingestion.scope_denied"


async def test_endpoint_key_can_report(client, db_session, org_and_users):
    headers = await _source(db_session, org_and_users["org"].id, "endpoint")
    resp = await client.post(f"{R}/report", json=_report(), headers=headers)
    assert resp.status_code == 200 and resp.json()["new_services"] == 1


async def test_a_report_never_moves_a_known_service_to_another_port(client, db_session, org_and_users):
    headers = await _source(db_session, org_and_users["org"].id, "endpoint")
    await client.post(f"{R}/report", json=_report(port=636), headers=headers)
    await client.post(f"{R}/report", json=_report(port=389), headers=headers)

    svc = (await db_session.execute(select(DiscoveredService).where(
        DiscoveredService.org_id == org_and_users["org"].id))).scalar_one()
    await db_session.refresh(svc)
    assert svc.port == 636
    assert svc.details["reported_port"] == 389
    assert svc.details["reported_by"] == "endpoint-1"


# ---- connect: confirmed target, TLS only --------------------------------------------

class _FakeLdap:
    """Minimal ldap3 stand-in recording how the bind was made."""

    def __init__(self):
        self.calls = []
        mod = types.ModuleType("ldap3")
        mod.ALL, mod.SUBTREE = "ALL", "SUBTREE"
        mod.AUTO_BIND_NO_TLS, mod.AUTO_BIND_TLS_BEFORE_BIND = "NO_TLS", "TLS_BEFORE_BIND"
        rec = self.calls

        class Tls:
            def __init__(self, validate=None, ca_certs_data=None, **kw):
                self.validate, self.ca_certs_data = validate, ca_certs_data

        class Server:
            def __init__(self, host, port=None, use_ssl=False, tls=None, **kw):
                self.host, self.port, self.use_ssl, self.tls, self.info = host, port, use_ssl, tls, None

        class Connection:
            def __init__(self, server, user=None, password=None, auto_bind=None, **kw):
                rec.append({"host": server.host, "port": server.port, "use_ssl": server.use_ssl,
                            "validate": server.tls.validate, "ca": server.tls.ca_certs_data,
                            "auto_bind": auto_bind, "password": password})
                self.entries = []

            def search(self, **kw):
                pass

            def unbind(self):
                pass

        mod.Tls, mod.Server, mod.Connection = Tls, Server, Connection
        exc = types.ModuleType("ldap3.core.exceptions")
        exc.LDAPException = type("LDAPException", (Exception,), {})
        core = types.ModuleType("ldap3.core")
        self.modules = {"ldap3": mod, "ldap3.core": core, "ldap3.core.exceptions": exc}


@pytest.fixture
def ldap(monkeypatch):
    fake = _FakeLdap()
    for name, m in fake.modules.items():
        monkeypatch.setitem(sys.modules, name, m)
    return fake


async def _service(db, org_id, port):
    svc = DiscoveredService(org_id=org_id, service_type="active_directory", host="dc1.corp.local", port=port,
                            discovered_via="ldap_probe", connect_status="discovered")
    db.add(svc)
    await db.flush()
    return svc


CREDS = {"bind_dn": "CN=svc,DC=corp,DC=local", "password": "s3cret"}


async def test_connect_requires_the_admin_to_confirm_the_target(client, db_session, org_and_users, admin_token, ldap):
    svc = await _service(db_session, org_and_users["org"].id, 636)
    resp = await client.post(f"{R}/{svc.id}/connect", json=CREDS, headers=auth_headers(admin_token))
    assert resp.status_code == 422
    assert resp.json()["detail"] == "discovery.confirm_target_required"
    assert ldap.calls == []


async def test_connect_refuses_when_the_target_changed(client, db_session, org_and_users, admin_token, ldap):
    svc = await _service(db_session, org_and_users["org"].id, 636)
    body = {**CREDS, "expected_host": "dc1.corp.local", "expected_port": 389}
    resp = await client.post(f"{R}/{svc.id}/connect", json=body, headers=auth_headers(admin_token))
    assert resp.status_code == 409
    assert resp.json()["detail"] == "discovery.target_changed"
    assert ldap.calls == []


@pytest.mark.parametrize("port, use_ssl, auto_bind",
                         [(636, True, "NO_TLS"), (3269, True, "NO_TLS"), (389, False, "TLS_BEFORE_BIND")])
async def test_bind_is_always_over_validated_tls(client, db_session, org_and_users, admin_token, ldap,
                                                 port, use_ssl, auto_bind):
    svc = await _service(db_session, org_and_users["org"].id, port)
    body = {**CREDS, "expected_host": "dc1.corp.local", "expected_port": port,
            "tls_ca_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}
    resp = await client.post(f"{R}/{svc.id}/connect", json=body, headers=auth_headers(admin_token))
    assert resp.status_code == 200, resp.text
    assert resp.json()["connect_status"] == "connected"

    call = ldap.calls[0]
    assert call["use_ssl"] is use_ssl and call["auto_bind"] == auto_bind
    assert call["validate"] == ssl.CERT_REQUIRED
    assert call["ca"].startswith("-----BEGIN CERTIFICATE-----")

    conn = (await db_session.execute(select(ServiceConnection).where(
        ServiceConnection.discovered_service_id == svc.id))).scalar_one()
    assert conn.info["tls"] == ("ldaps" if use_ssl else "starttls")


@pytest.mark.parametrize("host", ["ldap://dc1.corp.local", "dc1.corp.local:389", "dc1/x", "user@dc1"])
async def test_reported_host_must_be_bare(client, db_session, org_and_users, host):
    # ldap3 would read a scheme or port out of the host and override the TLS mode.
    headers = await _source(db_session, org_and_users["org"].id, "endpoint")
    resp = await client.post(f"{R}/report", json=_report(host=host), headers=headers)
    assert resp.status_code == 422


def test_ldap_endpoint_refuses_a_host_that_carries_a_scheme(ldap):
    from app.services.discovery_connect_handlers import ServiceConnectError, _ldap_endpoint
    with pytest.raises(ServiceConnectError):
        _ldap_endpoint("ldap://dc1.corp.local", 636, None)
