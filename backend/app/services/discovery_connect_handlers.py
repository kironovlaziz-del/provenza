"""
Connect handlers for discovered services.

Each handler is called ONLY from DiscoveryService.connect_service, which
runs only on an explicit admin action with supplied credentials - there
is no automatic/anonymous connection anywhere. A handler either returns
(connected_ref_type, connected_ref_id) on success or raises
ServiceConnectError with a message shown to the admin.

ldap3 is imported lazily inside the LDAP handler so that a deployment
without it (or without any intent to connect AD) never fails to import
this module or the discovery service.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_secret, decrypt_secret
from app.models.discovered_service import DiscoveredService
from app.models.service_connection import ServiceConnection
from app.schemas.discovery import ServiceConnectRequest


class ServiceConnectError(Exception):
    """Raised when a connect attempt fails (bad credentials, unreachable,
    misconfigured). Surfaced to the admin as connect_error - never
    swallowed."""


# ---------------------------------------------------------------------------
# LDAP / Active Directory
# ---------------------------------------------------------------------------

async def connect_ldap(
    db: AsyncSession,
    org_id: int,
    svc: DiscoveredService,
    creds: ServiceConnectRequest,
    connected_by: int,
) -> Tuple[str, int]:
    """
    Verify an LDAP/AD bind with the admin-supplied read-only credentials,
    do ONE read (server info + a bounded user count), then persist the
    connection with the bind password encrypted at rest.

    Requires bind_dn + password. base_dn is optional (auto-detected from
    the server's defaultNamingContext when omitted, which AD exposes).
    """
    if not creds.bind_dn or not creds.password:
        raise ServiceConnectError(
            "LDAP/AD requires a bind DN and password (a read-only service account)."
        )

    try:
        # Lazy import: ldap3 is only needed when actually connecting AD.
        from ldap3 import Server, Connection, ALL, SUBTREE
        from ldap3.core.exceptions import LDAPException
    except ImportError:
        raise ServiceConnectError(
            "LDAP support is not installed on the server (pip install ldap3)."
        )

    host = svc.host
    port = svc.port or 389
    use_ssl = port == 636

    # ldap3 does blocking network I/O; this whole handler is awaited from
    # an async context, but the calls here are synchronous. They are
    # short (single bind + one search, both under the socket timeout), so
    # running them inline is acceptable rather than pushing to a thread
    # pool. If this ever grows to periodic sync, move it to a worker.
    try:
        server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL, connect_timeout=8)
        conn = Connection(
            server,
            user=creds.bind_dn,
            password=creds.password,
            auto_bind=True,
            receive_timeout=10,
        )
    except LDAPException as exc:
        raise ServiceConnectError("LDAP bind failed: " + str(exc)[:300])
    except Exception as exc:  # noqa: BLE001 - socket errors, DNS, etc.
        raise ServiceConnectError("Could not reach the LDAP server: " + str(exc)[:300])

    info: dict = {}
    try:
        # base_dn: use what the admin gave, else the server's default
        # naming context (AD advertises this in the root DSE).
        base_dn = creds.base_dn
        if not base_dn:
            contexts = getattr(server.info, "naming_contexts", None) if server.info else None
            if contexts:
                base_dn = str(contexts[0])
        info["base_dn"] = base_dn

        if server.info and getattr(server.info, "other", None):
            # AD exposes dnsHostName / defaultNamingContext in root DSE.
            dns_host = server.info.other.get("dnsHostName")
            if dns_host:
                info["dns_host_name"] = str(dns_host[0]) if isinstance(dns_host, list) else str(dns_host)

        # One bounded read: count person objects, capped so a huge
        # directory can't turn "connect" into a multi-minute scan.
        if base_dn:
            conn.search(
                search_base=base_dn,
                search_filter="(objectClass=person)",
                search_scope=SUBTREE,
                attributes=["cn"],
                size_limit=1000,
                paged_size=1000,
            )
            count = len(conn.entries)
            info["person_count"] = count
            info["person_count_capped"] = count >= 1000
    except Exception as exc:  # noqa: BLE001 - a failed info read shouldn't undo a good bind
        info["read_warning"] = str(exc)[:200]
    finally:
        try:
            conn.unbind()
        except Exception:
            pass

    # Persist (or update) the connection with the password encrypted.
    result = await db.execute(
        select(ServiceConnection).where(
            ServiceConnection.discovered_service_id == svc.id,
            ServiceConnection.org_id == org_id,
        )
    )
    existing = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)

    if existing:
        existing.bind_dn = creds.bind_dn
        existing.base_dn = info.get("base_dn")
        existing.username = creds.username
        existing.bind_password_encrypted = encrypt_secret(creds.password, org_id=existing.org_id)
        existing.info = info
        existing.last_verified_at = now
        existing.last_error = None
        conn_row = existing
    else:
        conn_row = ServiceConnection(
            org_id=org_id,
            discovered_service_id=svc.id,
            service_type=svc.service_type,
            host=host,
            port=port,
            bind_dn=creds.bind_dn,
            base_dn=info.get("base_dn"),
            username=creds.username,
            bind_password_encrypted=encrypt_secret(creds.password, org_id=org_id),
            info=info,
            last_verified_at=now,
            created_by=connected_by,
        )
        db.add(conn_row)

    await db.flush()  # get conn_row.id without committing (caller owns the txn)
    return "service_connection", conn_row.id


# ---------------------------------------------------------------------------
# DNS - reachability check only, no credentials stored
# ---------------------------------------------------------------------------

async def connect_dns(
    db: AsyncSession,
    org_id: int,
    svc: DiscoveredService,
    creds: ServiceConnectRequest,
    connected_by: int,
) -> Tuple[str, int]:
    """
    A recursive DNS resolver has nothing to authenticate against, so
    "connecting" it just verifies it's actually reachable and answering,
    then records a credential-less ServiceConnection so the UI can show
    it as connected. No secrets involved.
    """
    host = svc.host
    port = svc.port or 53

    # Minimal DNS query (a standard A-record lookup for a well-known
    # name) sent straight to this server over UDP, using only the
    # standard library - if it answers, it's a working resolver.
    if not _dns_probe(host, port):
        raise ServiceConnectError(
            "The DNS server did not respond to a test query on port " + str(port) + "."
        )

    result = await db.execute(
        select(ServiceConnection).where(
            ServiceConnection.discovered_service_id == svc.id,
            ServiceConnection.org_id == org_id,
        )
    )
    existing = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)
    info = {"reachable": True, "checked_via": "udp_dns_query"}

    if existing:
        existing.info = info
        existing.last_verified_at = now
        existing.last_error = None
        conn_row = existing
    else:
        conn_row = ServiceConnection(
            org_id=org_id,
            discovered_service_id=svc.id,
            service_type=svc.service_type,
            host=host,
            port=port,
            info=info,
            last_verified_at=now,
            created_by=connected_by,
        )
        db.add(conn_row)

    await db.flush()
    return "service_connection", conn_row.id


def _dns_probe(host: str, port: int) -> bool:
    """Send a minimal DNS A-query for "example.com" straight to host:port
    over UDP and return True if any well-formed response comes back.
    Pure stdlib - no dnspython needed for a liveness check."""
    # DNS query packet: header + question for example.com A IN.
    query = bytes([
        0x12, 0x34,             # transaction id
        0x01, 0x00,             # flags: standard query, recursion desired
        0x00, 0x01,             # QDCOUNT = 1
        0x00, 0x00,             # ANCOUNT
        0x00, 0x00,             # NSCOUNT
        0x00, 0x00,             # ARCOUNT
    ])
    # QNAME: 7"example" 3"com" 0
    for label in (b"example", b"com"):
        query += bytes([len(label)]) + label
    query += bytes([0x00])          # end of name
    query += bytes([0x00, 0x01])    # QTYPE = A
    query += bytes([0x00, 0x01])    # QCLASS = IN

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(5)
        sock.sendto(query, (host, port))
        data, _ = sock.recvfrom(512)
        # A valid response echoes our transaction id and has QR bit set.
        return len(data) >= 4 and data[0] == 0x12 and data[1] == 0x34 and (data[2] & 0x80) != 0
    except Exception:
        return False
    finally:
        sock.close()


# Registry consumed by DiscoveryService. active_directory and ldap share
# the LDAP handler; dns uses the reachability handler.
CONNECT_HANDLERS = {
    "active_directory": connect_ldap,
    "ldap": connect_ldap,
    "dns": connect_dns,
}


# ---------------------------------------------------------------------------
# Re-verification of an already-stored connection
# ---------------------------------------------------------------------------

async def verify_connection(conn) -> bool:
    """
    Re-check an existing ServiceConnection using its STORED credentials
    (not freshly supplied ones) and update last_verified_at / last_error
    in place. Returns True on success, False on failure. Never raises -
    a failure is a recorded state, not an exception, because this runs
    unattended (Celery beat) as well as on the manual "Re-verify" button.

    Does NOT commit - the caller owns the transaction.
    """
    now = datetime.now(timezone.utc)

    try:
        if conn.service_type in ("active_directory", "ldap"):
            ok, err = _verify_ldap(conn)
        elif conn.service_type == "dns":
            ok = _dns_probe(conn.host, conn.port or 53)
            err = None if ok else "DNS server did not respond to a test query."
        else:
            ok, err = False, "Unsupported service type for verification."
    except Exception as exc:  # noqa: BLE001 - unattended; record, don't crash the sweep
        ok, err = False, str(exc)[:300]

    conn.last_verified_at = now
    conn.last_error = None if ok else err
    return ok


def _verify_ldap(conn) -> Tuple[bool, str]:
    """Attempt an LDAP bind with the stored (decrypted) bind password."""
    if not conn.bind_dn or not conn.bind_password_encrypted:
        return False, "No stored bind credentials."
    try:
        from ldap3 import Server, Connection, ALL
        from ldap3.core.exceptions import LDAPException
    except ImportError:
        return False, "LDAP support is not installed on the server."

    try:
        password = decrypt_secret(conn.bind_password_encrypted)
    except Exception:
        return False, "Stored credentials could not be decrypted."

    port = conn.port or 389
    use_ssl = port == 636
    try:
        server = Server(conn.host, port=port, use_ssl=use_ssl, get_info=ALL, connect_timeout=8)
        c = Connection(
            server, user=conn.bind_dn, password=password, auto_bind=True, receive_timeout=10
        )
        c.unbind()
        return True, ""
    except LDAPException as exc:
        return False, "LDAP bind failed: " + str(exc)[:250]
    except Exception as exc:  # noqa: BLE001
        return False, "Could not reach the LDAP server: " + str(exc)[:250]
