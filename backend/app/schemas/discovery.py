import ipaddress
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")


def is_bare_host(v: str) -> bool:
    """A DNS name or a literal IPv4/IPv6 address - nothing else."""
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return bool(_HOSTNAME.match(v or ""))


# ---- Discovery ingestion (from the sniffer/agent discovery layer) ----

class DiscoveredServiceIn(BaseModel):
    service_type: str = Field(max_length=50)
    # A bare hostname or IP. No scheme or port: libraries such as ldap3 read
    # "ldap://host:389" out of the host string and would override the TLS
    # mode and port chosen by the server.
    host: str = Field(max_length=253)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    discovered_via: str
    details: Optional[Dict[str, Any]] = None

    @field_validator("host")
    @classmethod
    def _bare_host(cls, v: str) -> str:
        if not is_bare_host(v):
            raise ValueError("host must be a bare hostname or IP address (no scheme, port or path)")
        return v


class DiscoveryReportRequest(BaseModel):
    services: List[DiscoveredServiceIn]


class DiscoveryReportResponse(BaseModel):
    received: int
    new_services: int
    updated_services: int


# ---- Listing / display ----

class DiscoveredServiceOut(BaseModel):
    id: int
    org_id: int
    service_type: str
    host: str
    port: Optional[int]
    discovered_via: str
    details: Optional[Dict[str, Any]]
    connect_status: str
    connect_error: Optional[str]
    connected_ref_type: Optional[str]
    connected_ref_id: Optional[int]
    first_seen_at: datetime
    last_seen_at: datetime
    connected_at: Optional[datetime]

    class Config:
        from_attributes = True


# ---- Connect wizard (admin supplies real credentials, explicitly) ----

class ServiceConnectRequest(BaseModel):
    """
    Credentials an admin explicitly provides to connect ONE discovered
    service. Which fields matter depends on service_type - e.g. LDAP/AD
    needs bind_dn + password, a firewall API needs api_token. All
    optional at the schema level; the service-specific connect handler
    validates what it actually requires.
    """
    username: Optional[str] = None
    password: Optional[str] = None
    bind_dn: Optional[str] = None
    base_dn: Optional[str] = None
    api_token: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None
    # The host and port the admin saw in the wizard; required for services
    # that receive credentials (see DiscoveryService.connect_service).
    expected_host: Optional[str] = None
    expected_port: Optional[int] = None
    # LDAP/AD: PEM of the CA that issued the directory's certificate, when it
    # is an in-house CA the server does not already trust. TLS is mandatory.
    tls_ca_pem: Optional[str] = Field(default=None, max_length=20000)


class ServiceIgnoreRequest(BaseModel):
    reason: Optional[str] = None


class ServiceConnectionOut(BaseModel):
    """
    Details of a live credentialed connection to a discovered service.
    Deliberately EXCLUDES bind_password_encrypted - the secret is never
    exposed through the API, only that a connection exists and whether it
    last verified successfully.
    """
    id: int
    org_id: int
    discovered_service_id: int
    service_type: str
    host: str
    port: Optional[int]
    bind_dn: Optional[str]
    base_dn: Optional[str]
    username: Optional[str]
    info: Optional[Dict[str, Any]]
    last_verified_at: Optional[datetime]
    last_error: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True
