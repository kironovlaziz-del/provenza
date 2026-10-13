# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The tool's side of signed permits: run only what Provenza allowed.

An allowed check gives the agent a permit - a JWS signed by the
organization's permit key, for one tool, one input, a few minutes. The agent
sends it with the call; the tool verifies it here and refuses without it:

    from provenza.permit import PermitVerifier, PermitMiddleware

    verifier = PermitVerifier("https://provenza.example.com", org="acme")
    app = PermitMiddleware(app, verifier, tool="crm.update")     # any ASGI app

    # or by hand, in any framework
    permit = verifier.verify(request.headers["Provenza-Permit"], tool="crm.update", input=payload)

The agent side:

    chk = agent.check("crm.update", payload)
    httpx.post(url, json=payload, headers=chk.permit_headers)
    agent.record(chk, output)

What is checked: the signature against the organization's JWKS (public, no
account needed; refetched when an unknown key id appears, after a rotation),
the issuer, the tool (aud), the SHA-256 of the canonical input (the JSON body
the tool received must be the input the agent checked), the expiry. Then the
permit is redeemed with Provenza, so it is used once across every replica of
the tool; with redeem=False only this process remembers what it has seen.
Anything that cannot be verified is refused: the verifier fails closed.
"""

import asyncio
import base64
import json
import threading
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple, Union

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from provenza.crypto import content_hash
from provenza.errors import ProvenzaError

HEADER = "Provenza-Permit"
TYP = "provenza-permit+jwt"
MAX_TOKEN_BYTES = 4096


class PermitError(ProvenzaError, PermissionError):
    """The permit is missing, invalid, for something else, expired or used.
    `code` is stable: permit.missing, permit.invalid, permit.mismatch,
    permit.expired, permit.redeemed, permit.unverifiable."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code


@dataclass(frozen=True)
class Permit:
    """A verified permit: who may do what, until when."""
    permit_id: str
    agent_id: int
    tool: str
    action_type: Optional[str]
    chain_id: Optional[int]
    input_sha256: str
    expires_at: int
    issuer: str
    redeemed: bool


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _split(token: Any) -> Tuple[Dict[str, Any], Dict[str, Any], bytes, bytes]:
    if not isinstance(token, str) or not token:
        raise PermitError("permit.missing", f"no {HEADER}")
    if len(token) > MAX_TOKEN_BYTES or token.count(".") != 2:
        raise PermitError("permit.invalid", "not a permit")
    h, c, s = token.split(".")
    try:
        header, claims, signature = json.loads(_unb64(h)), json.loads(_unb64(c)), _unb64(s)
    except ValueError as exc:
        raise PermitError("permit.invalid", "not a permit") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict) or header.get("alg") != "EdDSA" \
            or header.get("typ") != TYP or not isinstance(header.get("kid"), str):
        raise PermitError("permit.invalid", "not a Provenza permit")
    return header, claims, signature, f"{h}.{c}".encode("ascii")


class PermitVerifier:
    """Verifies permits of one organization. Thread-safe; share one per process."""

    def __init__(self, server_url: str, org: str, *, redeem: bool = True, jwks_ttl: float = 300,
                 leeway: int = 30, timeout: float = 5.0, transport: Optional[httpx.BaseTransport] = None,
                 async_transport: Optional[httpx.AsyncBaseTransport] = None):
        base = server_url.rstrip("/")
        if not base.endswith("/api/v1"):
            base += "/api/v1"
        self.org, self.issuer = org, f"provenza:org:{org}"
        self.jwks_url = f"{base}/pvp/permits/{org}/jwks.json"
        self.redeem_url = f"{base}/pvp/permits/redeem"
        self.redeem, self.jwks_ttl, self.leeway, self.timeout = redeem, jwks_ttl, leeway, timeout
        self._transport, self._async_transport = transport, async_transport
        self._keys: Dict[str, Ed25519PublicKey] = {}
        self._fetched = 0.0
        self._seen: Dict[str, int] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------ JWKS

    def _load(self, doc: Any) -> None:
        keys = {}
        for k in (doc or {}).get("keys", []) if isinstance(doc, dict) else []:
            if isinstance(k, dict) and k.get("kty") == "OKP" and k.get("crv") == "Ed25519" and k.get("kid"):
                try:
                    keys[k["kid"]] = Ed25519PublicKey.from_public_bytes(_unb64(k["x"]))
                except (KeyError, ValueError):
                    continue
        with self._lock:
            self._keys, self._fetched = keys, time.monotonic()

    def _stale(self, kid: str) -> bool:
        return kid not in self._keys or time.monotonic() - self._fetched > self.jwks_ttl

    def _fetch(self) -> None:
        try:
            with httpx.Client(timeout=self.timeout, transport=self._transport) as c:
                r = c.get(self.jwks_url)
                r.raise_for_status()
                self._load(r.json())
        except (httpx.HTTPError, ValueError) as exc:
            raise PermitError("permit.unverifiable", f"could not fetch the JWKS: {exc}") from exc

    async def _afetch(self) -> None:
        try:
            async with httpx.AsyncClient(timeout=self.timeout, transport=self._async_transport) as c:
                r = await c.get(self.jwks_url)
                r.raise_for_status()
                self._load(r.json())
        except (httpx.HTTPError, ValueError) as exc:
            raise PermitError("permit.unverifiable", f"could not fetch the JWKS: {exc}") from exc

    # ------------------------------------------------------------ checks

    def _claims(self, header, claims, signature, signing_input, tool: str, input_sha256: str) -> Permit:
        key = self._keys.get(header["kid"])
        if key is None:
            raise PermitError("permit.invalid", "signed by a key this organization does not publish")
        try:
            key.verify(signature, signing_input)
        except InvalidSignature as exc:
            raise PermitError("permit.invalid", "bad signature") from exc
        now = time.time()
        exp, nbf = claims.get("exp"), claims.get("nbf")
        if claims.get("iss") != self.issuer:
            raise PermitError("permit.invalid", "issued for another organization")
        if not isinstance(exp, int) or not isinstance(nbf, int) or now < nbf - self.leeway:
            raise PermitError("permit.invalid", "bad validity")
        if now > exp + self.leeway:
            raise PermitError("permit.expired")
        if claims.get("aud") != tool:
            raise PermitError("permit.mismatch", f"issued for {claims.get('aud')!r}, not {tool!r}")
        if claims.get("ish") != input_sha256:
            raise PermitError("permit.mismatch", "issued for another input")
        sub = str(claims.get("sub", ""))
        if not sub.startswith("agent:") or not sub[6:].isdigit() or not isinstance(claims.get("jti"), str):
            raise PermitError("permit.invalid", "bad subject")
        return Permit(permit_id=claims["jti"], agent_id=int(sub[6:]), tool=tool, action_type=claims.get("act"),
                      chain_id=claims.get("chain"), input_sha256=input_sha256, expires_at=exp,
                      issuer=self.issuer, redeemed=False)

    def _once(self, permit: Permit) -> None:
        now = int(time.time())
        with self._lock:
            for jti in [j for j, exp in self._seen.items() if exp + self.leeway < now]:
                del self._seen[jti]
            if permit.permit_id in self._seen:
                raise PermitError("permit.redeemed", "already used here")
            self._seen[permit.permit_id] = permit.expires_at

    def _redeemed(self, r: httpx.Response, permit: Permit) -> Permit:
        if r.status_code == 200:
            return Permit(**{**permit.__dict__, "redeemed": True})   # once, server-wide
        try:
            code = r.json().get("detail")
        except ValueError:
            code = None
        if isinstance(code, dict):
            code = code.get("code")
        if r.status_code >= 500 or not isinstance(code, str) or not code.startswith("permit."):
            raise PermitError("permit.unverifiable", f"redeem failed: HTTP {r.status_code}")
        raise PermitError(code)

    def _body(self, token: str, permit: Permit) -> Dict[str, Any]:
        return {"permit": token, "tool": permit.tool, "input_sha256": permit.input_sha256}

    def verify(self, token: Optional[str], *, tool: str, input: Any = None,
               input_sha256: Optional[str] = None) -> Permit:
        """The permit, if it allows exactly this call; else PermitError. Give
        the input as received (its canonical hash is compared) or its hash."""
        header, claims, signature, signing_input = _split(token)
        if self._stale(header["kid"]):
            self._fetch()
        permit = self._claims(header, claims, signature, signing_input, tool,
                              input_sha256 or content_hash({} if input is None else input))
        if not self.redeem:
            self._once(permit)
            return permit
        try:
            with httpx.Client(timeout=self.timeout, transport=self._transport) as c:
                r = c.post(self.redeem_url, json=self._body(token, permit))
        except httpx.HTTPError as exc:
            raise PermitError("permit.unverifiable", f"could not redeem: {exc}") from exc
        return self._redeemed(r, permit)

    async def averify(self, token: Optional[str], *, tool: str, input: Any = None,
                      input_sha256: Optional[str] = None) -> Permit:
        """verify() for async code."""
        header, claims, signature, signing_input = _split(token)
        if self._stale(header["kid"]):
            await self._afetch()
        permit = self._claims(header, claims, signature, signing_input, tool,
                              input_sha256 or content_hash({} if input is None else input))
        if not self.redeem:
            self._once(permit)
            return permit
        try:
            async with httpx.AsyncClient(timeout=self.timeout, transport=self._async_transport) as c:
                r = await c.post(self.redeem_url, json=self._body(token, permit))
        except httpx.HTTPError as exc:
            raise PermitError("permit.unverifiable", f"could not redeem: {exc}") from exc
        return self._redeemed(r, permit)


ToolOf = Union[str, Callable[[Dict[str, Any]], Optional[str]]]


class PermitMiddleware:
    """ASGI middleware: an HTTP request runs only with a valid permit for
    `tool` and the request's JSON body as the input. `tool` is a name, or a
    function of the ASGI scope returning the name (None = not a governed
    route, passed through). The verified Permit is in scope["state"]["permit"]
    (request.state.permit in Starlette / FastAPI). A refusal is a 403 JSON
    {"error": code}; 503 when the permit cannot be verified right now."""

    def __init__(self, app: Callable[..., Awaitable[None]], verifier: PermitVerifier, *, tool: ToolOf,
                 max_body: int = 8 * 1024 * 1024):
        self.app, self.verifier, self.tool, self.max_body = app, verifier, tool, max_body

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        tool = self.tool(scope) if callable(self.tool) else self.tool
        if tool is None:
            return await self.app(scope, receive, send)
        chunks, size, more = [], 0, True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > self.max_body:
                return await _refuse(send, 413, "permit.body_too_large")
            chunks.append(chunk)
            more = message.get("more_body", False)
        body = b"".join(chunks)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        try:
            data = json.loads(body) if body.strip() else {}
        except ValueError:
            return await _refuse(send, 400, "permit.body_not_json")
        try:
            permit = await self.verifier.averify(headers.get(HEADER.lower()), tool=tool, input=data)
        except PermitError as exc:
            return await _refuse(send, 503 if exc.code == "permit.unverifiable" else 403, exc.code)
        scope.setdefault("state", {})["permit"] = permit
        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        return await self.app(scope, replay, send)


async def _refuse(send, status: int, code: str) -> None:
    body = json.dumps({"error": code}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


def require_permit(verifier: PermitVerifier, tool: str):
    """For a plain function: called with permit="<token>" and the input as
    keyword arguments, it runs only with a valid permit for those arguments.

        @require_permit(verifier, "db.read")
        def read(query: str, limit: int = 10): ...

        read(permit=chk.permit, query="select 1", limit=5)
    """
    def wrap(fn):
        import functools

        if asyncio.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def arun(*, permit: Optional[str] = None, **kwargs):
                await verifier.averify(permit, tool=tool, input=kwargs)
                return await fn(**kwargs)
            return arun

        @functools.wraps(fn)
        def run(*, permit: Optional[str] = None, **kwargs):
            verifier.verify(permit, tool=tool, input=kwargs)
            return fn(**kwargs)
        return run
    return wrap
