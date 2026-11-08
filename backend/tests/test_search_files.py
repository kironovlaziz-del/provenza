"""robots.txt and sitemap.xml: closed unless the operator opens them."""

import xml.etree.ElementTree as ET

import pytest

from app.core.config import settings

NS = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}


def locs(xml: str) -> list:
    """The addresses a sitemap lists, parsed - compared whole, never as substrings."""
    return [e.text for e in ET.fromstring(xml).findall("s:url/s:loc", NS)]


@pytest.mark.asyncio
async def test_closed_by_default(client, monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_SEARCH_INDEXING", False)
    monkeypatch.setattr(settings, "PUBLIC_BASE_URL", "https://demo.example.com")
    r = await client.get("/robots.txt")
    assert r.status_code == 200 and r.text == "User-agent: *\nDisallow: /\n"
    assert (await client.get("/sitemap.xml")).status_code == 404


@pytest.mark.asyncio
async def test_open_needs_a_public_address(client, monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_SEARCH_INDEXING", True)
    monkeypatch.setattr(settings, "PUBLIC_BASE_URL", "")
    assert (await client.get("/robots.txt")).text == "User-agent: *\nDisallow: /\n"
    assert (await client.get("/sitemap.xml")).status_code == 404


@pytest.mark.asyncio
async def test_open(client, monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_SEARCH_INDEXING", True)
    monkeypatch.setattr(settings, "PUBLIC_BASE_URL", "https://demo.example.com/")
    robots = (await client.get("/robots.txt")).text
    assert "Allow: /login$" in robots and "Disallow: /\n" in robots
    assert "Sitemap: https://demo.example.com/sitemap.xml\n" in robots.splitlines(keepends=True)
    r = await client.get("/sitemap.xml")
    assert r.status_code == 200 and "xml" in r.headers["content-type"]
    assert locs(r.text) == ["https://demo.example.com/", "https://demo.example.com/login"]


@pytest.mark.asyncio
async def test_host_header_never_reaches_the_sitemap(client, monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_SEARCH_INDEXING", True)
    monkeypatch.setattr(settings, "PUBLIC_BASE_URL", "https://demo.example.com")
    r = await client.get("/sitemap.xml", headers={"Host": "evil.example.net", "X-Forwarded-Host": "evil.example.net"})
    assert locs(r.text) == ["https://demo.example.com/", "https://demo.example.com/login"]
