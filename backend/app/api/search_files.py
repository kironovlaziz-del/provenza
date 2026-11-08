# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
robots.txt and sitemap.xml, for a Provenza that is meant to be found by search
engines (a public demo, a project site).

Closed by default: an installation keeps every crawler out unless its operator
sets ALLOW_SEARCH_INDEXING=true. The sitemap exists only then, and it names
only addresses built from PUBLIC_BASE_URL - never from the request's Host
header, which a client controls.

  GET /robots.txt
  GET /sitemap.xml
"""

from fastapi import APIRouter, Response, status

from app.core.config import settings

router = APIRouter()

# What a crawler can usefully see on a Provenza without signing in. The rest of
# the web UI needs an account, the API is not for crawlers.
PUBLIC_PATHS = ("/", "/login")

_CLOSED = "User-agent: *\nDisallow: /\n"
_CACHE = "public, max-age=3600"


def _base() -> str:
    return (settings.PUBLIC_BASE_URL or "").strip().rstrip("/")


def _open() -> bool:
    return bool(settings.ALLOW_SEARCH_INDEXING) and _base().startswith(("https://", "http://"))


def robots_txt() -> str:
    if not _open():
        return _CLOSED
    return (
        "User-agent: *\n"
        "Allow: /$\n"
        "Allow: /login$\n"
        "Disallow: /\n"
        f"\nSitemap: {_base()}/sitemap.xml\n"
    )


def sitemap_xml() -> str:
    urls = "".join(f"<url><loc>{_base()}{p}</loc></url>" for p in PUBLIC_PATHS)
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + urls + "</urlset>")


@router.get("/robots.txt", include_in_schema=False)
async def robots() -> Response:
    return Response(robots_txt(), media_type="text/plain; charset=utf-8", headers={"Cache-Control": _CACHE})


@router.get("/sitemap.xml", include_in_schema=False)
async def sitemap() -> Response:
    if not _open():
        return Response(status_code=status.HTTP_404_NOT_FOUND)
    return Response(sitemap_xml(), media_type="application/xml; charset=utf-8", headers={"Cache-Control": _CACHE})
