# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
HTTP to a Provenza server, sync and async (httpx).

Failure classes matter here, because connected mode fails closed:

  network error, timeout, HTTP 5xx    -> ProvenzaUnavailable (the server could
                                         not decide; nothing is executed)
  HTTP 4xx                            -> ProvenzaRequestError (the server did
                                         decide: the request is wrong)

Redirects are not followed: an agent key is never re-sent to wherever a
redirect points. The agent key travels only as X-Agent-Key.
"""

from typing import Any, Dict, Optional

import httpx

from provenza.errors import ProvenzaRequestError, ProvenzaUnavailable

API = "/api/v1"
USER_AGENT = "provenza-python"


def _detail(resp: httpx.Response) -> Any:
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:300]
    return body.get("detail", body) if isinstance(body, dict) else body


def _result(path: str, resp: httpx.Response) -> Any:
    if resp.status_code >= 500:
        raise ProvenzaUnavailable(f"{path}: HTTP {resp.status_code}")
    if resp.status_code >= 400:
        raise ProvenzaRequestError(resp.status_code, _detail(resp), path)
    if not resp.content:
        return None
    try:
        return resp.json()
    except ValueError as exc:
        raise ProvenzaUnavailable(f"{path}: the server answered with something that is not JSON") from exc


class Client:
    def __init__(self, server_url: str, api_key: Optional[str] = None, *, timeout: float = 10.0,
                 transport: Optional[httpx.BaseTransport] = None,
                 async_transport: Optional[httpx.AsyncBaseTransport] = None):
        if not server_url.startswith(("https://", "http://")):
            raise ValueError("server_url must start with https:// (or http:// for a local server)")
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._transport, self._async_transport = transport, async_transport
        self._sync: Optional[httpx.Client] = None
        self._async: Optional[httpx.AsyncClient] = None

    def _headers(self, authenticated: bool) -> Dict[str, str]:
        h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if authenticated:
            if not self.api_key:
                raise ProvenzaRequestError(401, "this agent has no API key", "")
            h["X-Agent-Key"] = self.api_key
        return h

    @property
    def sync(self) -> httpx.Client:
        if self._sync is None:
            self._sync = httpx.Client(base_url=self.server_url + API, timeout=self.timeout, follow_redirects=False,
                                      transport=self._transport)
        return self._sync

    @property
    def aio(self) -> httpx.AsyncClient:
        if self._async is None:
            self._async = httpx.AsyncClient(base_url=self.server_url + API, timeout=self.timeout,
                                            follow_redirects=False, transport=self._async_transport)
        return self._async

    def post(self, path: str, body: Dict[str, Any], *, authenticated: bool = True) -> Any:
        try:
            resp = self.sync.post(path, json=body, headers=self._headers(authenticated))
        except httpx.HTTPError as exc:
            raise ProvenzaUnavailable(f"{path}: {type(exc).__name__}: {exc}") from exc
        return _result(path, resp)

    async def apost(self, path: str, body: Dict[str, Any], *, authenticated: bool = True) -> Any:
        try:
            resp = await self.aio.post(path, json=body, headers=self._headers(authenticated))
        except httpx.HTTPError as exc:
            raise ProvenzaUnavailable(f"{path}: {type(exc).__name__}: {exc}") from exc
        return _result(path, resp)

    def get(self, path: str, *, authenticated: bool = True) -> Any:
        try:
            resp = self.sync.get(path, headers=self._headers(authenticated))
        except httpx.HTTPError as exc:
            raise ProvenzaUnavailable(f"{path}: {type(exc).__name__}: {exc}") from exc
        return _result(path, resp)

    def close(self) -> None:
        if self._sync is not None:
            self._sync.close()
            self._sync = None

    async def aclose(self) -> None:
        if self._async is not None:
            await self._async.aclose()
            self._async = None
