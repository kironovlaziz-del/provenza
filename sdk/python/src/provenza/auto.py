# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Auto-instrumentation: govern every direct call this process makes to an AI
provider, without changing the code that makes it.

    import provenza.auto
    provenza.auto.instrument(agent)            # httpx (sync + async) and requests

Covers whatever sits on httpx or requests - the OpenAI, Anthropic, Mistral,
Cohere and Gemini SDKs, LangChain's provider clients, plain HTTP. A request
whose host is an AI provider in the organization's AI domain catalog (Shadow
AI; GET /pvp/egress-catalog) becomes an "egress" action, decided by the
server:

    blocked in the catalog          -> refused, incident ai_domain_blocked
    allowed / not classified yet    -> sent, unless a policy refuses it;
                                       recorded either way

What is recorded: host, method, path (no query string), the SHA-256 and size
of the body - never the prompt itself - and the response's status and size.

A refusal is an HTTP answer, not an exception: 403 with an OpenAI-style error
body and "x-should-retry: false", so provider SDKs raise their usual
permission error with Provenza's reason and do not retry. With the server
unreachable the request is not sent (fail-closed): 503, also not retried.
Every other host is untouched, and so are calls to Provenza itself (its
gateways are the governed route for AI traffic anyway).

The same caveat as the rest of the SDK: this runs inside the agent's
process. A program that uses another HTTP stack, or undoes the patch, is not
covered - the egress proxy (next stage) is what covers that.
"""

import hashlib
import json
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.parse import urlsplit

from provenza.errors import ProvenzaDenied, ProvenzaRequestError, ProvenzaUnavailable

ACTION_TYPE = "egress"
PREFIX = "egress."
# used in standalone mode (no server to ask), and if the server's catalog cannot be fetched at startup
DEFAULT_DOMAINS = (
    "openai.com", "anthropic.com", "claude.ai", "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
    "openai.azure.com", "bedrock-runtime.amazonaws.com", "mistral.ai", "cohere.com", "cohere.ai", "deepseek.com",
    "x.ai", "groq.com", "openrouter.ai", "together.xyz", "fireworks.ai", "perplexity.ai", "replicate.com",
    "huggingface.co", "stability.ai", "elevenlabs.io",
)

_state: Optional["Instrumentation"] = None
_originals: Dict[str, Callable] = {}
_patch_lock = threading.Lock()


def _match(host: str, domains: Iterable[str]) -> Optional[str]:
    """The most specific catalog domain covering host (exact or a dot-bounded suffix)."""
    host = host.lower().rstrip(".")
    best = None
    for d in domains:
        if host == d or host.endswith("." + d):
            if best is None or len(d) > len(best):
                best = d
    return best


class Instrumentation:
    def __init__(self, agent, refresh_seconds: float = 300.0):
        self.agent = agent
        self.refresh_seconds = refresh_seconds
        server = agent.server_url
        self.server_host = urlsplit(server).hostname.lower() if server else None
        self.domains: Dict[str, str] = {d: "unknown" for d in DEFAULT_DOMAINS}
        self._fetched_at = 0.0
        self._lock = threading.Lock()
        self.refresh(initial=True)

    def refresh(self, initial: bool = False) -> None:
        if self.agent.mode != "connected":
            return
        try:
            catalog = self.agent._connected().get("/pvp/egress-catalog")
        except (ProvenzaUnavailable, ProvenzaRequestError):
            if initial:
                self._fetched_at = time.monotonic()   # keep the defaults; try again later
            return
        domains = {d["domain"].lower(): d.get("status", "unknown") for d in catalog.get("domains") or []
                   if isinstance(d, dict) and d.get("domain")}
        with self._lock:
            self.domains = domains or self.domains
            self._fetched_at = time.monotonic()

    def _maybe_refresh(self) -> None:
        if time.monotonic() - self._fetched_at > self.refresh_seconds:
            self._fetched_at = time.monotonic()   # one refresh at a time
            threading.Thread(target=self.refresh, name="provenza-catalog", daemon=True).start()

    def governs(self, host: Optional[str]) -> bool:
        if not host:
            return False
        host = host.lower()
        if host == self.server_host:
            return False
        self._maybe_refresh()
        with self._lock:
            return _match(host, self.domains) is not None

    @staticmethod
    def describe(method: str, url: str, body: Optional[bytes]) -> Dict[str, Any]:
        parts = urlsplit(url)
        return {"host": (parts.hostname or "").lower(), "method": method.upper(), "path": parts.path or "/",
                "body_sha256": hashlib.sha256(body).hexdigest() if body is not None else None,
                "body_bytes": len(body) if body is not None else None}


def _status_of(response: Any) -> Dict[str, Any]:
    size = response.headers.get("content-length")
    return {"status": response.status_code, "bytes": int(size) if size and size.isdigit() else None}


def _refusal_body(exc: Exception) -> bytes:
    if isinstance(exc, ProvenzaDenied):
        message, code = f"Refused by Provenza: {exc.reason}", "provenza_denied"
    else:
        message, code = f"Provenza is unreachable; the request was not sent ({exc})", "provenza_unavailable"
    return json.dumps({"error": {"message": message, "type": code, "code": code}}).encode()


def _refusal_status(exc: Exception) -> int:
    return 403 if isinstance(exc, ProvenzaDenied) else 503


_REFUSAL_HEADERS = {"content-type": "application/json", "x-should-retry": "false", "x-provenza-refused": "1"}


# --- httpx ------------------------------------------------------------------------

def _httpx_body(request) -> Optional[bytes]:
    try:
        return request.content           # raises for an unread streaming body
    except Exception:  # noqa: BLE001
        return None


def _patch_httpx() -> None:
    import httpx

    orig_send, orig_asend = httpx.Client.send, httpx.AsyncClient.send
    _originals["httpx.Client.send"], _originals["httpx.AsyncClient.send"] = orig_send, orig_asend

    def send(self, request, *args, **kwargs):
        inst = _state
        if inst is None or not inst.governs(request.url.host):
            return orig_send(self, request, *args, **kwargs)
        inp = inst.describe(request.method, str(request.url), _httpx_body(request))
        try:
            return inst.agent.call(PREFIX + inp["host"], inp, lambda: orig_send(self, request, *args, **kwargs),
                                   action_type=ACTION_TYPE, output_of=_status_of)
        except (ProvenzaDenied, ProvenzaUnavailable) as exc:
            return httpx.Response(_refusal_status(exc), headers=_REFUSAL_HEADERS, content=_refusal_body(exc),
                                  request=request)

    async def asend(self, request, *args, **kwargs):
        inst = _state
        if inst is None or not inst.governs(request.url.host):
            return await orig_asend(self, request, *args, **kwargs)
        inp = inst.describe(request.method, str(request.url), _httpx_body(request))
        try:
            return await inst.agent.acall(PREFIX + inp["host"], inp,
                                          lambda: orig_asend(self, request, *args, **kwargs),
                                          action_type=ACTION_TYPE, output_of=_status_of)
        except (ProvenzaDenied, ProvenzaUnavailable) as exc:
            return httpx.Response(_refusal_status(exc), headers=_REFUSAL_HEADERS, content=_refusal_body(exc),
                                  request=request)

    httpx.Client.send, httpx.AsyncClient.send = send, asend


def _unpatch_httpx() -> None:
    import httpx

    httpx.Client.send = _originals.pop("httpx.Client.send")
    httpx.AsyncClient.send = _originals.pop("httpx.AsyncClient.send")


# --- requests ---------------------------------------------------------------------

def _patch_requests() -> None:
    import requests

    orig_send = requests.Session.send
    _originals["requests.Session.send"] = orig_send

    def send(self, request, **kwargs):
        inst = _state
        host = urlsplit(request.url).hostname
        if inst is None or not inst.governs(host):
            return orig_send(self, request, **kwargs)
        body = request.body.encode() if isinstance(request.body, str) else \
            request.body if isinstance(request.body, bytes) else None
        inp = inst.describe(request.method, request.url, body)
        try:
            return inst.agent.call(PREFIX + inp["host"], inp, lambda: orig_send(self, request, **kwargs),
                                   action_type=ACTION_TYPE, output_of=_status_of)
        except (ProvenzaDenied, ProvenzaUnavailable) as exc:
            resp = requests.Response()
            resp.status_code, resp._content, resp.url, resp.request = (_refusal_status(exc), _refusal_body(exc),
                                                                       request.url, request)
            resp.headers.update(_REFUSAL_HEADERS)
            return resp

    requests.Session.send = send


def _unpatch_requests() -> None:
    import requests

    requests.Session.send = _originals.pop("requests.Session.send")


_PATCHES = {"httpx": (_patch_httpx, _unpatch_httpx), "requests": (_patch_requests, _unpatch_requests)}


# --- API --------------------------------------------------------------------------

def instrument(agent, libraries: Iterable[str] = ("httpx", "requests"), *,
               refresh_seconds: float = 300.0) -> Instrumentation:
    """Start governing this process's direct calls to AI providers. A library
    that is not installed is skipped. Calling it again switches the agent."""
    global _state
    with _patch_lock:
        inst = Instrumentation(agent, refresh_seconds)
        for lib in libraries:
            if lib not in _PATCHES:
                raise ValueError(f"unknown library {lib!r}: one of {sorted(_PATCHES)}")
            already = any(k.startswith(lib + ".") for k in _originals)
            if already:
                continue
            try:
                _PATCHES[lib][0]()
            except ImportError:
                continue
        _state = inst
        return inst


def uninstrument() -> None:
    """Put every patched library back as it was."""
    global _state
    with _patch_lock:
        for lib, (_, unpatch) in _PATCHES.items():
            if any(k.startswith(lib + ".") for k in _originals):
                unpatch()
        _state = None


def instrumented() -> List[str]:
    return sorted({k.split(".")[0] for k in _originals})
