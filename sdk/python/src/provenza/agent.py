# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Agent - the SDK's entry point.

    from provenza import Agent

    agent = Agent("billing-bot")                    # PROVENZA_URL / PROVENZA_TOKEN from the environment

    @agent.tool(name="db.read")
    def read(query: str) -> dict: ...

Every call of a tool becomes a PVP action (docs/pvp/spec.md):

  connected   check on the server (rights, policies, Tool Registry, injection,
              behaviour, breaker) -> the tool runs only if allowed -> the
              result is recorded, signed with the agent's key under the
              single-use check_id. Denied and pending calls raise and are
              recorded too. The server unreachable: the call does NOT run
              (fail-closed) unless fail_open=True.
  standalone  no server: the call runs (within allowed_tools if given) and
              is written to the local signed audit log.

What this is, said plainly: the SDK runs inside the agent's process, so it
is the agent's honest record and cooperative enforcement - code in that
process could call a tool around it. Enforcement that does not depend on the
agent is Provenza's gateways (LLM, MCP, A2A) and, next, the egress proxy.
"""

import asyncio
import contextlib
import contextvars
import functools
import inspect
import json
import os
import secrets
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional, TypeVar

from provenza import identity as ids
from provenza import proxy as egress_proxy
from provenza.audit_log import AuditLog
from provenza.client import Client
from provenza.crypto import Keys, canonical, content_hash
from provenza.permit import HEADER as PERMIT_HEADER
from provenza.errors import (ProvenzaApprovalRequired, ProvenzaConfigError, ProvenzaDenied, ProvenzaRequestError,
                             ProvenzaUnavailable)

F = TypeVar("F", bound=Callable[..., Any])
_chain: contextvars.ContextVar = contextvars.ContextVar("provenza_chain_id", default=None)
RECORD_RETRIES = (0.2, 1.0)   # seconds before the 2nd and 3rd attempt; the check lives 5 minutes


class ProvenzaWarning(UserWarning):
    """Something went wrong after a tool already ran (it could not be
    recorded on the server); the gap is in the local audit log."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    action_type: str = "tool_call"
    version: Optional[str] = None
    digest: Optional[str] = None


@dataclass(frozen=True)
class Check:
    """The server's verdict for one proposed call, bound to it."""
    check_id: str
    decision: str            # allowed | denied | pending_approval
    reason: str
    tool: str
    action_type: str
    input: Dict[str, Any] = field(repr=False)
    chain_id: Optional[int] = None
    incident_type: Optional[str] = None
    policy_id: Optional[int] = None
    # allowed: the signed permit the tool verifies (provenza.permit)
    permit: Optional[str] = field(default=None, repr=False)

    @property
    def allowed(self) -> bool:
        return self.decision == "allowed"

    @property
    def permit_headers(self) -> Dict[str, str]:
        """For a tool behind provenza.permit: the header it verifies. Send the
        checked input as the request's JSON body."""
        return {PERMIT_HEADER: self.permit} if self.permit else {}

    @property
    def proxy_headers(self) -> Dict[str, str]:
        """For a proxy check: the header the egress proxy redeems."""
        return {egress_proxy.HEADER: self.check_id}


def _json_value(value: Any, what: str) -> Any:
    """Normalized to plain JSON (tuples become lists); refuses what has no
    JSON form, and NaN / Infinity, before anything is sent or run."""
    try:
        return json.loads(canonical(value))
    except (TypeError, ValueError) as exc:
        raise TypeError(f"{what} must be JSON-serializable (no NaN / Infinity): {exc}") from exc


def _arguments(fn: Callable, args: tuple, kwargs: dict) -> Dict[str, Any]:
    params = list(inspect.signature(fn).parameters)
    bound = inspect.signature(fn).bind(*args, **kwargs)
    bound.apply_defaults()
    data = {k: v for k, v in bound.arguments.items() if not (params and k == params[0] and k in ("self", "cls"))}
    return _json_value(data, "tool arguments")


def _output(result: Any) -> Optional[Dict[str, Any]]:
    if result is None:
        return None
    try:
        value = json.loads(canonical(result))
    except (TypeError, ValueError):
        return {"repr": repr(result)[:2000]}   # what is recorded (hashed) for a non-JSON result
    return value if isinstance(value, dict) else {"result": value}


class _Recorder:
    """record_mode="background" for sync tools: one daemon thread sends the
    records in order. A failure becomes a gap in the local audit log, as in
    sync mode. Drained by close() and at interpreter exit; a process that is
    killed loses what is still queued - the price of not waiting."""

    def __init__(self, send: Callable[..., Any]):
        import atexit
        import queue
        import threading

        self._send, self._queue = send, queue.Queue()
        self._thread = threading.Thread(target=self._work, name="provenza-recorder", daemon=True)
        self._thread.start()
        atexit.register(self.drain)

    def _work(self) -> None:
        while True:
            job = self._queue.get()
            try:
                if job is not None:
                    self._send(*job)
            finally:
                self._queue.task_done()

    def put(self, *job: Any) -> None:
        self._queue.put(job)

    def drain(self, timeout: float = 30.0) -> bool:
        """Wait until everything queued was sent (or became a gap)."""
        import threading

        done = threading.Event()
        threading.Thread(target=lambda: (self._queue.join(), done.set()), daemon=True).start()
        return done.wait(timeout)


class Agent:
    def __init__(self, name: Optional[str] = None, *, server_url: Optional[str] = None,
                 enrollment_token: Optional[str] = None, identity_path: Optional[str] = None,
                 key_store: str = "file", mode: Optional[str] = None, hybrid: bool = False,
                 allowed_tools: Optional[Iterable[str]] = None, audit_log: Optional[str] = None,
                 fail_open: bool = False, record_mode: str = "sync", timeout: float = 10.0, transport=None,
                 async_transport=None):
        self.name = name or os.environ.get("PROVENZA_AGENT_NAME") or "agent"
        server_url = server_url or os.environ.get("PROVENZA_URL")
        token = enrollment_token or os.environ.get("PROVENZA_TOKEN")
        self.mode = mode or os.environ.get("PROVENZA_MODE") or ("connected" if server_url else "standalone")
        if self.mode not in ("connected", "standalone"):
            raise ProvenzaConfigError("mode must be 'connected' or 'standalone'")
        self.identity_path = Path(identity_path or os.environ.get("PROVENZA_IDENTITY") or ids.default_path(self.name))
        self.fail_open = fail_open
        if record_mode not in ("sync", "background"):
            raise ProvenzaConfigError("record_mode must be 'sync' or 'background'")
        self.record_mode = record_mode
        self._recorder: Optional[_Recorder] = None
        self._pending: set = set()   # background record tasks of async tools
        self.allowed_tools = frozenset(allowed_tools) if allowed_tools is not None else None
        self._client: Optional[Client] = None
        self.identity = self._load_identity(server_url, token, key_store, hybrid, timeout, transport, async_transport)
        self.audit_log = AuditLog(Path(audit_log) if audit_log else self.identity_path.with_suffix(".audit.jsonl"),
                                  self.identity.keys, self.name)

    # ------------------------------------------------------------------ setup

    def _load_identity(self, server_url, token, key_store, hybrid, timeout, transport, async_transport):
        try:
            identity = ids.load(self.identity_path)
        except FileNotFoundError:
            identity = None
        if self.mode == "standalone":
            if identity is None:
                identity = ids.Identity(keys=Keys.generate(hybrid), name=self.name)
                ids.save(identity, self.identity_path, key_store)
            return identity

        server = (server_url or (identity.server if identity else None) or "").rstrip("/")
        if not server:
            raise ProvenzaConfigError("connected mode needs server_url (or PROVENZA_URL)")
        if identity is not None and identity.server and identity.server.rstrip("/") != server:
            # never present this agent's key to a server it was not enrolled with
            raise ProvenzaConfigError(f"{self.identity_path} belongs to {identity.server}, not {server}")
        if identity is None or identity.agent_id is None:
            if not token:
                raise ProvenzaConfigError("this agent is not enrolled: pass enrollment_token (or PROVENZA_TOKEN), "
                                          "issued in Provenza under Agents -> New agent")
            client = Client(server, timeout=timeout, transport=transport, async_transport=async_transport)
            identity = ids.enroll(client, token, name=self.name, hybrid=hybrid)
            ids.save(identity, self.identity_path, key_store)
        self._client = Client(server, identity.api_key, timeout=timeout, transport=transport,
                              async_transport=async_transport)
        return identity

    @property
    def agent_id(self) -> Optional[int]:
        return self.identity.agent_id

    @property
    def server_url(self) -> Optional[str]:
        return self._client.server_url if self._client is not None else None

    def credentials(self) -> Dict[str, str]:
        """(base server URL, agent key) for clients that talk to Provenza's
        gateways themselves (integrations.openai / integrations.mcp)."""
        client = self._connected()
        if not client.api_key:
            raise ProvenzaConfigError("this agent has no API key")
        return {"server_url": client.server_url, "api_key": client.api_key}

    @property
    def fingerprint(self) -> str:
        """Give this to whoever verifies the agent's signatures."""
        return self.identity.fingerprint

    @contextlib.contextmanager
    def chain(self, chain_id: Optional[int]):
        """Tool calls inside act within this delegation chain."""
        token = _chain.set(chain_id)
        try:
            yield
        finally:
            _chain.reset(token)

    # ------------------------------------------------------------------ protocol

    def _check_body(self, tool: ToolSpec, input: Dict[str, Any], chain_id: Optional[int]) -> Dict[str, Any]:
        body = {"agent_id": self.agent_id, "chain_id": chain_id, "action_type": tool.action_type,
                "tool_name": tool.name, "input": input}
        if tool.version:
            body["tool_version"] = tool.version
        if tool.digest:
            body["tool_digest"] = tool.digest
        # signed, with a single-use nonce and the time: the server refuses a
        # check the agent did not sign, so a stolen API key alone gets nothing
        nonce, issued_at = secrets.token_hex(16), int(time.time())
        payload = {"type": "action.request", "agent_id": self.agent_id, "chain_id": chain_id,
                   "action_type": tool.action_type, "tool_name": tool.name, "input_sha256": content_hash(input),
                   "tool_version": tool.version, "tool_digest": tool.digest, "nonce": nonce, "issued_at": issued_at}
        sig, pq = self.identity.keys.sign(payload)
        body.update({"nonce": nonce, "issued_at": issued_at, "signature": sig})
        if pq:
            body["pq_signature"] = pq
        return body

    @staticmethod
    def _check_of(res: Dict[str, Any], tool: ToolSpec, input: Dict[str, Any], chain_id: Optional[int]) -> Check:
        return Check(check_id=res["check_id"], decision=res["decision"], reason=res.get("reason") or "",
                     tool=tool.name, action_type=tool.action_type, input=input, chain_id=chain_id,
                     incident_type=res.get("incident_type"), policy_id=res.get("policy_id"),
                     permit=res.get("permit"))

    def _record_body(self, chk: Check, output: Optional[Dict[str, Any]], duration_ms: Optional[int]) -> Dict[str, Any]:
        payload = {"check_id": chk.check_id, "agent_id": self.agent_id, "chain_id": chk.chain_id,
                   "action_type": chk.action_type, "tool_name": chk.tool,
                   "input_sha256": content_hash(chk.input), "output_sha256": content_hash(output)}
        sig, pq = self.identity.keys.sign(payload)
        return {"agent_id": self.agent_id, "chain_id": chk.chain_id, "action_type": chk.action_type,
                "tool_name": chk.tool, "input": chk.input, "output": output, "duration_ms": duration_ms,
                "check_id": chk.check_id, "signature": sig, "pq_signature": pq}

    def _connected(self) -> Client:
        if self._client is None:
            raise ProvenzaConfigError("this needs connected mode")
        return self._client

    def check(self, tool: str, input: Dict[str, Any], *, action_type: str = "tool_call",
              chain_id: Optional[int] = None) -> Check:
        """Ask before doing something that is not a decorated tool."""
        spec, inp = ToolSpec(tool, action_type), _json_value(input, "input")
        cid = chain_id if chain_id is not None else _chain.get()
        res = self._connected().post("/agents/actions/check", self._check_body(spec, inp, cid))
        return self._check_of(res, spec, inp, cid)

    async def acheck(self, tool: str, input: Dict[str, Any], *, action_type: str = "tool_call",
                     chain_id: Optional[int] = None) -> Check:
        spec, inp = ToolSpec(tool, action_type), _json_value(input, "input")
        cid = chain_id if chain_id is not None else _chain.get()
        res = await self._connected().apost("/agents/actions/check", self._check_body(spec, inp, cid))
        return self._check_of(res, spec, inp, cid)

    def proxy_check(self, route: str, method: str, path: str, *, query=None, body=None,
                    chain_id: Optional[int] = None) -> Check:
        """Check a request to send through the egress proxy (SDK mode). Send it
        with check.proxy_headers; the proxy records it - do not record() it."""
        return self.check(egress_proxy.tool_name(route), egress_proxy.descriptor(
            route, method, path, query=query, body=body), action_type=egress_proxy.ACTION_TYPE, chain_id=chain_id)

    async def aproxy_check(self, route: str, method: str, path: str, *, query=None, body=None,
                           chain_id: Optional[int] = None) -> Check:
        return await self.acheck(egress_proxy.tool_name(route), egress_proxy.descriptor(
            route, method, path, query=query, body=body), action_type=egress_proxy.ACTION_TYPE, chain_id=chain_id)

    def record(self, check: Check, output: Any = None, duration_ms: Optional[int] = None) -> Dict[str, Any]:
        """Record what was done under a check (once). Retries a server that
        is down; a 409 on a retry means an earlier attempt got through."""
        body = self._record_body(check, _output(output) if not isinstance(output, dict) else
                                 _json_value(output, "output"), duration_ms)
        for attempt, pause in enumerate((0.0, *RECORD_RETRIES)):
            if pause:
                time.sleep(pause)
            try:
                return self._connected().post("/agents/actions/record", body)
            except ProvenzaUnavailable:
                if attempt == len(RECORD_RETRIES):
                    raise
            except ProvenzaRequestError as exc:
                if exc.status == 409 and attempt > 0:
                    return {"id": None, "check_id": check.check_id, "note": "recorded by an earlier attempt"}
                raise
        raise AssertionError("unreachable")  # pragma: no cover

    async def arecord(self, check: Check, output: Any = None, duration_ms: Optional[int] = None) -> Dict[str, Any]:
        body = self._record_body(check, _output(output) if not isinstance(output, dict) else
                                 _json_value(output, "output"), duration_ms)
        for attempt, pause in enumerate((0.0, *RECORD_RETRIES)):
            if pause:
                await asyncio.sleep(pause)
            try:
                return await self._connected().apost("/agents/actions/record", body)
            except ProvenzaUnavailable:
                if attempt == len(RECORD_RETRIES):
                    raise
            except ProvenzaRequestError as exc:
                if exc.status == 409 and attempt > 0:
                    return {"id": None, "check_id": check.check_id, "note": "recorded by an earlier attempt"}
                raise
        raise AssertionError("unreachable")  # pragma: no cover

    def delegate(self, to_agent_id: int, task: str, capabilities: Iterable[str] = (), *,
                 tools: Optional[Iterable[str]] = None, expires_in: Optional[int] = None,
                 chain_id: Optional[int] = None) -> Dict[str, Any]:
        """Hand a task and a subset of this agent's rights to another agent
        (signed, single-use nonce). Returns the server's answer with chain_id."""
        return self._connected().post(f"/agents/{self.agent_id}/delegate",
                                      self._delegation_body(to_agent_id, task, capabilities, tools, expires_in, chain_id))

    async def adelegate(self, to_agent_id: int, task: str, capabilities: Iterable[str] = (), *,
                        tools: Optional[Iterable[str]] = None, expires_in: Optional[int] = None,
                        chain_id: Optional[int] = None) -> Dict[str, Any]:
        return await self._connected().apost(f"/agents/{self.agent_id}/delegate",
                                             self._delegation_body(to_agent_id, task, capabilities, tools, expires_in,
                                                                   chain_id))

    def _delegation_body(self, to_agent_id, task, capabilities, tools, expires_in, chain_id) -> Dict[str, Any]:
        caps = list(capabilities)
        tools = list(tools) if tools is not None else None
        cid = chain_id if chain_id is not None else _chain.get()
        payload = {"from_agent_id": self.agent_id, "to_agent_id": to_agent_id, "task": task,
                   "delegated_capabilities": sorted(caps), "chain_id": cid, "nonce": secrets.token_hex(16),
                   "issued_at": int(time.time()), "expires_in": expires_in}
        if tools is not None:
            payload["delegated_tools"] = sorted(set(tools))
        sig, pq = self.identity.keys.sign(payload)
        body = {k: payload[k] for k in ("to_agent_id", "task", "chain_id", "nonce", "issued_at", "expires_in")}
        body.update(delegated_capabilities=caps, delegated_tools=tools, signature=sig, pq_signature=pq)
        return body

    # ------------------------------------------------------------------ tools

    def tool(self, fn: Optional[F] = None, *, name: Optional[str] = None, action_type: str = "tool_call",
             version: Optional[str] = None, digest: Optional[str] = None):
        """Decorate a function (sync or async) so every call is governed."""
        def decorate(f: F) -> F:
            spec = ToolSpec(name or f.__name__, action_type, version, digest)
            if inspect.iscoroutinefunction(f):
                @functools.wraps(f)
                async def async_wrapper(*args, **kwargs):
                    return await self._arun(spec, f, args, kwargs)
                async_wrapper.provenza_tool = spec
                return async_wrapper  # type: ignore[return-value]

            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                return self._run(spec, f, args, kwargs)
            wrapper.provenza_tool = spec
            return wrapper  # type: ignore[return-value]

        return decorate(fn) if fn is not None else decorate

    def _local_refusal(self, spec: ToolSpec, inp: Dict[str, Any]) -> None:
        if self.allowed_tools is not None and spec.name not in self.allowed_tools:
            reason = "not in this agent's allowed_tools (standalone)"
            self.audit_log.append(status="denied", tool=spec.name, action_type=spec.action_type,
                                  input_sha256=content_hash(inp), reason=reason)
            raise ProvenzaDenied(spec.name, reason)

    def _local(self, spec: ToolSpec, inp, status: str, output, duration_ms: int, reason: str = "") -> None:
        self.audit_log.append(status=status, tool=spec.name, action_type=spec.action_type,
                              input_sha256=content_hash(inp), output_sha256=content_hash(output),
                              duration_ms=duration_ms, reason=reason)

    def _refused(self, spec: ToolSpec, chk: Check, action: Optional[Dict[str, Any]]) -> ProvenzaDenied:
        cls = ProvenzaApprovalRequired if chk.decision == "pending_approval" else ProvenzaDenied
        return cls(spec.name, chk.reason, chk.decision, chk.incident_type, chk.check_id,
                   (action or {}).get("id"))

    def _gap(self, spec: ToolSpec, chk: Check, output, duration_ms: int, exc: Exception) -> None:
        self.audit_log.append(status="unrecorded", tool=spec.name, action_type=spec.action_type,
                              check_id=chk.check_id, input_sha256=content_hash(chk.input),
                              output_sha256=content_hash(output), duration_ms=duration_ms,
                              reason=f"{type(exc).__name__}: {str(exc)[:200]}")
        warnings.warn(f"{spec.name} ran but could not be recorded on the server ({exc}); the gap is in "
                      f"{self.audit_log.path}", ProvenzaWarning, stacklevel=3)

    # the one governed path: everything above and every integration ends here

    def call(self, tool: str, arguments: Dict[str, Any], fn: Callable[[], Any], *,
             action_type: str = "tool_call", output_of: Optional[Callable[[Any], Any]] = None) -> Any:
        """Govern one call whose arguments you already have as a dict -
        check, run fn() only if allowed, record. What the integrations use.
        output_of(result) chooses what is recorded (default: the result)."""
        return self._govern(ToolSpec(tool, action_type), _json_value(arguments, "tool arguments"), fn, output_of)

    async def acall(self, tool: str, arguments: Dict[str, Any], fn: Callable[[], Any], *,
                    action_type: str = "tool_call", output_of: Optional[Callable[[Any], Any]] = None) -> Any:
        """call() for a coroutine: fn() returns an awaitable."""
        return await self._agovern(ToolSpec(tool, action_type), _json_value(arguments, "tool arguments"), fn,
                                   output_of)

    def _run(self, spec: ToolSpec, f: Callable, args: tuple, kwargs: dict) -> Any:
        return self._govern(spec, _arguments(f, args, kwargs), lambda: f(*args, **kwargs))

    async def _arun(self, spec: ToolSpec, f: Callable, args: tuple, kwargs: dict) -> Any:
        return await self._agovern(spec, _arguments(f, args, kwargs), lambda: f(*args, **kwargs))

    def _govern(self, spec: ToolSpec, inp: Dict[str, Any], fn: Callable[[], Any], output_of=None) -> Any:
        out = (lambda r: _output(output_of(r))) if output_of else _output
        if self.mode == "standalone":
            self._local_refusal(spec, inp)
            return self._timed_local(spec, fn, inp, "recorded", out)
        try:
            res = self._connected().post("/agents/actions/check", self._check_body(spec, inp, _chain.get()))
        except ProvenzaUnavailable:
            if not self.fail_open:
                raise
            warnings.warn(f"{spec.name}: Provenza unreachable, running unchecked (fail_open)", ProvenzaWarning,
                          stacklevel=4)
            return self._timed_local(spec, fn, inp, "unchecked", out)
        chk = self._check_of(res, spec, inp, _chain.get())
        if not chk.allowed:
            raise self._refused(spec, chk, self._try_record(spec, chk, None, None))
        started = time.monotonic()
        try:
            result = fn()
        except Exception as exc:
            self._record_after(spec, chk, {"error": type(exc).__name__}, int((time.monotonic() - started) * 1000))
            raise
        self._record_after(spec, chk, out(result), int((time.monotonic() - started) * 1000))
        return result

    def _record_after(self, spec, chk, output, duration_ms) -> None:
        if self.record_mode == "background":
            if self._recorder is None:
                self._recorder = _Recorder(self._try_record)
            self._recorder.put(spec, chk, output, duration_ms)
        else:
            self._try_record(spec, chk, output, duration_ms)

    async def _agovern(self, spec: ToolSpec, inp: Dict[str, Any], fn: Callable[[], Any], output_of=None) -> Any:
        out = (lambda r: _output(output_of(r))) if output_of else _output
        if self.mode == "standalone":
            self._local_refusal(spec, inp)
            started = time.monotonic()
            result = await fn()
            self._local(spec, inp, "recorded", out(result), int((time.monotonic() - started) * 1000))
            return result
        try:
            res = await self._connected().apost("/agents/actions/check", self._check_body(spec, inp, _chain.get()))
        except ProvenzaUnavailable:
            if not self.fail_open:
                raise
            warnings.warn(f"{spec.name}: Provenza unreachable, running unchecked (fail_open)", ProvenzaWarning,
                          stacklevel=4)
            started = time.monotonic()
            result = await fn()
            self._local(spec, inp, "unchecked", out(result), int((time.monotonic() - started) * 1000))
            return result
        chk = self._check_of(res, spec, inp, _chain.get())
        if not chk.allowed:
            raise self._refused(spec, chk, await self._atry_record(spec, chk, None, None))
        started = time.monotonic()
        try:
            result = await fn()
        except Exception as exc:
            await self._arecord_after(spec, chk, {"error": type(exc).__name__},
                                      int((time.monotonic() - started) * 1000))
            raise
        await self._arecord_after(spec, chk, out(result), int((time.monotonic() - started) * 1000))
        return result

    async def _arecord_after(self, spec, chk, output, duration_ms) -> None:
        if self.record_mode == "background":
            task = asyncio.get_running_loop().create_task(self._atry_record(spec, chk, output, duration_ms))
            self._pending.add(task)
            task.add_done_callback(self._pending.discard)
        else:
            await self._atry_record(spec, chk, output, duration_ms)

    def _timed_local(self, spec: ToolSpec, fn: Callable[[], Any], inp, status: str, out=_output) -> Any:
        started = time.monotonic()
        result = fn()
        self._local(spec, inp, status, out(result), int((time.monotonic() - started) * 1000))
        return result

    def _try_record(self, spec, chk, output, duration_ms) -> Optional[Dict[str, Any]]:
        try:
            return self.record(chk, output, duration_ms)
        except (ProvenzaUnavailable, ProvenzaRequestError) as exc:
            self._gap(spec, chk, output, duration_ms or 0, exc)
            return None

    async def _atry_record(self, spec, chk, output, duration_ms) -> Optional[Dict[str, Any]]:
        try:
            return await self.arecord(chk, output, duration_ms)
        except (ProvenzaUnavailable, ProvenzaRequestError) as exc:
            self._gap(spec, chk, output, duration_ms or 0, exc)
            return None

    # ------------------------------------------------------------------ lifecycle

    def flush(self, timeout: float = 30.0) -> bool:
        """Wait for background records of sync tools; True when all were sent
        (or written as gaps)."""
        return self._recorder.drain(timeout) if self._recorder is not None else True

    async def aflush(self) -> None:
        """Wait for background records of async tools."""
        if self._pending:
            await asyncio.gather(*list(self._pending), return_exceptions=True)

    def close(self) -> None:
        self.flush()
        if self._client is not None:
            self._client.close()

    async def aclose(self) -> None:
        await self.aflush()
        if self._client is not None:
            await self._client.aclose()

    def __enter__(self) -> "Agent":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    async def __aenter__(self) -> "Agent":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()
        self.close()
