# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Google A2A wire formats - pure functions, no I/O (used by app/pvp/a2a_gateway.py).

A2A 1.0 broke 0.3, and agents in the field speak both, so the gateway keeps
one canonical form - 1.0 - and converts at the edges:

                       0.3                               1.0
  methods      message/send, tasks/get,          SendMessage, GetTask,
               tasks/cancel                      CancelTask
  version      no A2A-Version header (empty      A2A-Version: 1.0
               = 0.3, per the 1.0 spec)
  parts        {"kind":"text","text"}            {"text"}
               {"kind":"file","file":{name,      {"raw"|"url", "filename",
                mimeType, bytes|uri}}             "mediaType"}
               {"kind":"data","data"}            {"data", "mediaType":"application/json"}
  roles        "user" / "agent"                  "ROLE_USER" / "ROLE_AGENT"
  task state   "completed", "input-required"..   "TASK_STATE_COMPLETED", ...
  send result  the Task / Message itself         {"task": ...} / {"message": ...}
  blocking     configuration.blocking            configuration.returnImmediately (inverse)
  card         url + protocolVersion             supportedInterfaces[{url, protocolBinding,
                                                 protocolVersion}]

Everything an agent sends is validated into the canonical form first; a
malformed message is an A2AError (-32602), never a half-understood forward.
"""

from typing import Any, Dict, List, Optional, Tuple

V1, V03 = "1.0", "0.3"
SUPPORTED = (V1, V03)

METHODS = {  # canonical (1.0) name -> 0.3 name
    "SendMessage": "message/send",
    "GetTask": "tasks/get",
    "CancelTask": "tasks/cancel",
}
UNSUPPORTED_METHODS = {  # known, deliberately not offered (UnsupportedOperationError)
    "SendStreamingMessage", "SubscribeToTask", "ListTasks", "GetExtendedAgentCard",
    "CreateTaskPushNotificationConfig", "GetTaskPushNotificationConfig", "ListTaskPushNotificationConfigs",
    "DeleteTaskPushNotificationConfig",
    "message/stream", "tasks/resubscribe", "agent/getAuthenticatedExtendedCard",
    "tasks/pushNotificationConfig/set", "tasks/pushNotificationConfig/get",
    "tasks/pushNotificationConfig/list", "tasks/pushNotificationConfig/delete",
}

# JSON-RPC error codes (A2A 1.0, section 5.4)
TASK_NOT_FOUND = -32001
TASK_NOT_CANCELABLE = -32002
PUSH_NOT_SUPPORTED = -32003
UNSUPPORTED_OPERATION = -32004
INVALID_AGENT_RESPONSE = -32006
VERSION_NOT_SUPPORTED = -32009
INVALID_PARAMS = -32602

ROLES = {"user": "ROLE_USER", "agent": "ROLE_AGENT"}
STATES = {
    "submitted": "TASK_STATE_SUBMITTED", "working": "TASK_STATE_WORKING", "completed": "TASK_STATE_COMPLETED",
    "failed": "TASK_STATE_FAILED", "canceled": "TASK_STATE_CANCELED", "input-required": "TASK_STATE_INPUT_REQUIRED",
    "rejected": "TASK_STATE_REJECTED", "auth-required": "TASK_STATE_AUTH_REQUIRED", "unknown": "TASK_STATE_UNSPECIFIED",
}
_ROLES_BACK = {v: k for k, v in ROLES.items()}
_STATES_BACK = {v: k for k, v in STATES.items()}

MAX_ID = 200
MAX_PARTS = 100


class A2AError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code, self.message, self.data = code, message, data


def version_of(header: Optional[str]) -> Optional[str]:
    """Major.Minor of an A2A-Version value; empty = 0.3. None = unsupported."""
    value = (header or "").strip()
    if not value:
        return V03
    parts = value.split(".")
    if len(parts) < 2 or not all(p.isdigit() for p in parts[:2]):
        return None
    major_minor = f"{int(parts[0])}.{int(parts[1])}"
    return major_minor if major_minor in SUPPORTED else None


def canonical_method(method: str, version: str) -> Optional[str]:
    """The 1.0 name of a method, if it belongs to that version."""
    if version == V1:
        return method if method in METHODS else None
    back = {v: k for k, v in METHODS.items()}
    return back.get(method)


def wire_method(canonical: str, version: str) -> str:
    return canonical if version == V1 else METHODS[canonical]


# --- validation helpers -----------------------------------------------------------

def _id(value: Any, field: str, required: bool = False) -> Optional[str]:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_ID:
        raise A2AError(INVALID_PARAMS, f"{field} must be a string of 1..{MAX_ID} characters")
    return value


def _obj(value: Any, field: str) -> Optional[dict]:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise A2AError(INVALID_PARAMS, f"{field} must be an object")
    return value


def _str_list(value: Any, field: str) -> Optional[List[str]]:
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value) or len(value) > MAX_PARTS:
        raise A2AError(INVALID_PARAMS, f"{field} must be a list of strings")
    return value


def _put(out: dict, key: str, value: Any) -> None:
    if value is not None:
        out[key] = value


# --- parts ------------------------------------------------------------------------

def part_from_v03(p: Any) -> dict:
    if not isinstance(p, dict):
        raise A2AError(INVALID_PARAMS, "a part must be an object")
    kind = p.get("kind")
    out: dict = {}
    if kind == "text" and isinstance(p.get("text"), str):
        out["text"] = p["text"]
    elif kind == "file" and isinstance(p.get("file"), dict):
        f = p["file"]
        if isinstance(f.get("bytes"), str):
            out["raw"] = f["bytes"]
        elif isinstance(f.get("uri"), str):
            out["url"] = f["uri"]
        else:
            raise A2AError(INVALID_PARAMS, "a file part needs bytes or uri")
        _put(out, "filename", f.get("name"))
        _put(out, "mediaType", f.get("mimeType"))
    elif kind == "data" and "data" in p:
        out["data"], out["mediaType"] = p["data"], "application/json"
    else:
        raise A2AError(INVALID_PARAMS, "unknown part kind")
    _put(out, "metadata", _obj(p.get("metadata"), "part.metadata"))
    return out


def part_to_v03(p: dict) -> dict:
    meta = {"metadata": p["metadata"]} if "metadata" in p else {}
    if "text" in p:
        return {"kind": "text", "text": p["text"], **meta}
    if "data" in p:
        return {"kind": "data", "data": p["data"], **meta}
    f: dict = {"bytes": p["raw"]} if "raw" in p else {"uri": p.get("url")}
    _put(f, "name", p.get("filename"))
    _put(f, "mimeType", p.get("mediaType"))
    return {"kind": "file", "file": f, **meta}


def check_part(p: Any) -> dict:
    """A canonical (1.0) part: exactly one of text / raw / url / data."""
    if not isinstance(p, dict):
        raise A2AError(INVALID_PARAMS, "a part must be an object")
    present = [k for k in ("text", "raw", "url", "data") if k in p]
    if len(present) != 1:
        raise A2AError(INVALID_PARAMS, "a part holds exactly one of text, raw, url, data")
    kind = present[0]
    if kind in ("text", "raw", "url") and not isinstance(p[kind], str):
        raise A2AError(INVALID_PARAMS, f"part.{kind} must be a string")
    allowed = {kind, "metadata", "filename", "mediaType"}
    extra = set(p) - allowed
    if extra:
        raise A2AError(INVALID_PARAMS, f"unknown part fields: {sorted(extra)[:5]}")
    for k in ("filename", "mediaType"):
        if k in p and not isinstance(p[k], str):
            raise A2AError(INVALID_PARAMS, f"part.{k} must be a string")
    _obj(p.get("metadata"), "part.metadata")
    return p


# --- messages ---------------------------------------------------------------------

MESSAGE_FIELDS = {"messageId", "role", "parts", "contextId", "taskId", "metadata", "extensions", "referenceTaskIds"}


def message_from_wire(m: Any, version: str) -> dict:
    """A message an agent sent, in canonical form (validated)."""
    if not isinstance(m, dict):
        raise A2AError(INVALID_PARAMS, "message must be an object")
    m = dict(m)
    if version == V03:
        if m.pop("kind", "message") != "message":
            raise A2AError(INVALID_PARAMS, "message.kind must be 'message'")
        role = ROLES.get(m.get("role"))
        if role is None:
            raise A2AError(INVALID_PARAMS, "message.role must be 'user' or 'agent'")
        m["role"] = role
        if not isinstance(m.get("parts"), list):
            raise A2AError(INVALID_PARAMS, "message.parts must be a list")
        m["parts"] = [part_from_v03(p) for p in m["parts"]]
    extra = set(m) - MESSAGE_FIELDS
    if extra:
        raise A2AError(INVALID_PARAMS, f"unknown message fields: {sorted(extra)[:5]}")
    _id(m.get("messageId"), "message.messageId", required=True)
    if m.get("role") not in _ROLES_BACK:
        raise A2AError(INVALID_PARAMS, "message.role must be ROLE_USER or ROLE_AGENT")
    parts = m.get("parts")
    if not isinstance(parts, list) or not 1 <= len(parts) <= MAX_PARTS:
        raise A2AError(INVALID_PARAMS, f"message.parts must hold 1..{MAX_PARTS} parts")
    m["parts"] = [check_part(p) for p in parts]
    _id(m.get("contextId"), "message.contextId")
    _id(m.get("taskId"), "message.taskId")
    _obj(m.get("metadata"), "message.metadata")
    _str_list(m.get("extensions"), "message.extensions")
    for t in _str_list(m.get("referenceTaskIds"), "message.referenceTaskIds") or []:
        _id(t, "message.referenceTaskIds[]")
    return m


def message_to_wire(m: dict, version: str) -> dict:
    if version == V1:
        return m
    out = {**m, "kind": "message", "role": _ROLES_BACK.get(m.get("role"), "agent")}
    out["parts"] = [part_to_v03(p) for p in m.get("parts") or []]
    return out


def _message_from_peer(m: Any, version: str) -> dict:
    """A message a peer sent back: converted, loosely (it is scanned and
    recorded; the agent gets it in its own version)."""
    if not isinstance(m, dict):
        raise A2AError(INVALID_AGENT_RESPONSE, "the agent returned a malformed message")
    if version == V1:
        return m
    out = {k: v for k, v in m.items() if k != "kind"}
    out["role"] = ROLES.get(m.get("role"), "ROLE_AGENT")
    try:
        out["parts"] = [part_from_v03(p) for p in m.get("parts") or []]
    except A2AError as exc:
        raise A2AError(INVALID_AGENT_RESPONSE, f"the agent returned a malformed part: {exc.message}") from exc
    return out


# --- tasks ------------------------------------------------------------------------

def task_from_peer(t: Any, version: str) -> dict:
    if not isinstance(t, dict) or not isinstance(t.get("id"), str) or not 1 <= len(t["id"]) <= MAX_ID \
            or not isinstance(t.get("status"), dict):
        raise A2AError(INVALID_AGENT_RESPONSE, "the agent returned a malformed task")
    out = {k: v for k, v in t.items() if k != "kind"}
    status = dict(t["status"])
    if version == V03:
        status["state"] = STATES.get(status.get("state"), "TASK_STATE_UNSPECIFIED")
    if isinstance(status.get("message"), dict):
        status["message"] = _message_from_peer(status["message"], version)
    out["status"] = status
    if isinstance(t.get("history"), list):
        out["history"] = [_message_from_peer(m, version) for m in t["history"]]
    if isinstance(t.get("artifacts"), list):
        arts = []
        for a in t["artifacts"]:
            if not isinstance(a, dict):
                raise A2AError(INVALID_AGENT_RESPONSE, "the agent returned a malformed artifact")
            a = dict(a)
            if version == V03:
                a["parts"] = [part_from_v03(p) for p in a.get("parts") or []]
            arts.append(a)
        out["artifacts"] = arts
    return out


def task_to_wire(t: dict, version: str) -> dict:
    if version == V1:
        return t
    out = {**t, "kind": "task"}
    status = dict(t["status"])
    status["state"] = _STATES_BACK.get(status.get("state"), "unknown")
    if isinstance(status.get("message"), dict):
        status["message"] = message_to_wire(status["message"], V03)
    out["status"] = status
    if isinstance(t.get("history"), list):
        out["history"] = [message_to_wire(m, V03) for m in t["history"]]
    if isinstance(t.get("artifacts"), list):
        out["artifacts"] = [{**a, "parts": [part_to_v03(p) for p in a.get("parts") or []]} for a in t["artifacts"]]
    return out


# --- requests and results -----------------------------------------------------------

def send_params_from_wire(params: Any, version: str) -> dict:
    """SendMessage params in canonical form. Push-notification configs are
    refused: the peer would deliver to a URL Provenza never sees, outside
    output scanning and the audit trail."""
    if not isinstance(params, dict):
        raise A2AError(INVALID_PARAMS, "params must be an object")
    cfg = _obj(params.get("configuration"), "configuration") or {}
    if cfg.get("taskPushNotificationConfig") or cfg.get("pushNotificationConfig"):
        raise A2AError(PUSH_NOT_SUPPORTED, "Push notifications are not supported through Provenza")
    out: dict = {"message": message_from_wire(params.get("message"), version)}
    canon_cfg: dict = {}
    if "acceptedOutputModes" in cfg:
        canon_cfg["acceptedOutputModes"] = _str_list(cfg["acceptedOutputModes"], "configuration.acceptedOutputModes")
    if "historyLength" in cfg:
        if isinstance(cfg["historyLength"], bool) or not isinstance(cfg["historyLength"], int):
            raise A2AError(INVALID_PARAMS, "configuration.historyLength must be an integer")
        canon_cfg["historyLength"] = cfg["historyLength"]
    blocking = cfg.get("blocking") if version == V03 else None
    immediate = cfg.get("returnImmediately") if version == V1 else (None if blocking is None else not blocking)
    if immediate is not None:
        if not isinstance(immediate, bool):
            raise A2AError(INVALID_PARAMS, "configuration.returnImmediately must be a boolean")
        canon_cfg["returnImmediately"] = immediate
    if canon_cfg:
        out["configuration"] = canon_cfg
    _put(out, "metadata", _obj(params.get("metadata"), "metadata"))
    return out


def send_params_to_wire(p: dict, version: str) -> dict:
    out = {"message": message_to_wire(p["message"], version)}
    cfg = dict(p.get("configuration") or {})
    if version == V03 and "returnImmediately" in cfg:
        cfg["blocking"] = not cfg.pop("returnImmediately")
    if cfg:
        out["configuration"] = cfg
    _put(out, "metadata", p.get("metadata"))
    return out


def task_params_from_wire(params: Any, canonical: str) -> dict:
    """GetTask / CancelTask params (same shape in both versions)."""
    if not isinstance(params, dict):
        raise A2AError(INVALID_PARAMS, "params must be an object")
    out = {"id": _id(params.get("id"), "id", required=True)}
    if canonical == "GetTask" and "historyLength" in params:
        if isinstance(params["historyLength"], bool) or not isinstance(params["historyLength"], int):
            raise A2AError(INVALID_PARAMS, "historyLength must be an integer")
        out["historyLength"] = params["historyLength"]
    _put(out, "metadata", _obj(params.get("metadata"), "metadata"))
    return out


def result_from_peer(canonical: str, result: Any, version: str) -> Tuple[str, dict]:
    """("task" | "message", canonical object) of a peer's result."""
    if canonical != "SendMessage":
        return "task", task_from_peer(result, version)
    if not isinstance(result, dict):
        raise A2AError(INVALID_AGENT_RESPONSE, "the agent returned a malformed result")
    if version == V1:
        if isinstance(result.get("task"), dict):
            return "task", task_from_peer(result["task"], V1)
        if isinstance(result.get("message"), dict):
            return "message", _message_from_peer(result["message"], V1)
        raise A2AError(INVALID_AGENT_RESPONSE, "the agent returned neither a task nor a message")
    if result.get("kind") == "message":
        return "message", _message_from_peer(result, V03)
    return "task", task_from_peer(result, V03)


def result_to_wire(canonical: str, kind: str, obj: dict, version: str) -> dict:
    if kind == "message":
        wire = message_to_wire(obj, version)
    else:
        wire = task_to_wire(obj, version)
    if canonical == "SendMessage" and version == V1:
        return {kind: wire}
    return wire


# --- agent cards ------------------------------------------------------------------

def card_endpoint(card: Any) -> Tuple[str, str]:
    """(JSON-RPC endpoint URL, version) a card declares - 1.0 preferred."""
    if not isinstance(card, dict):
        raise A2AError(INVALID_AGENT_RESPONSE, "the agent card is not an object")
    for iface in card.get("supportedInterfaces") or []:
        if isinstance(iface, dict) and iface.get("protocolBinding") == "JSONRPC" and isinstance(iface.get("url"), str):
            v = version_of(str(iface.get("protocolVersion") or ""))
            if v == V1:
                return iface["url"], V1
    for iface in card.get("supportedInterfaces") or []:
        if isinstance(iface, dict) and iface.get("protocolBinding") == "JSONRPC" and isinstance(iface.get("url"), str) \
                and version_of(str(iface.get("protocolVersion") or "")) == V03:
            return iface["url"], V03
    legacy_v = version_of(str(card.get("protocolVersion") or ""))
    if isinstance(card.get("url"), str) and card.get("preferredTransport", "JSONRPC") == "JSONRPC" and legacy_v == V03:
        return card["url"], V03
    raise A2AError(INVALID_AGENT_RESPONSE, "the agent card declares no JSON-RPC interface of A2A 1.0 or 0.3")


def pinned_card(card: dict) -> dict:
    """What is pinned of a peer's card: everything but its signatures (which
    can be re-issued without the card changing)."""
    return {k: v for k, v in card.items() if k != "signatures"}


def served_card(card: dict, url: str, version: str) -> dict:
    """The card an agent is shown: the approved one, pointing at Provenza
    and asking for the agent's own key - never the peer's address or
    security schemes. Push and streaming are switched off (not offered)."""
    skills = [s for s in card.get("skills") or [] if isinstance(s, dict)]
    base = {
        "name": card.get("name") or "agent",
        "description": card.get("description") or "",
        "version": card.get("version") or "1",
        "capabilities": {"streaming": False, "pushNotifications": False, "extendedAgentCard": False},
        "defaultInputModes": card.get("defaultInputModes") or ["text/plain"],
        "defaultOutputModes": card.get("defaultOutputModes") or ["text/plain"],
        "skills": [{k: s[k] for k in ("id", "name", "description", "tags", "examples", "inputModes", "outputModes")
                    if k in s} for s in skills],
        "provider": {"organization": "Provenza gateway", "url": url},
    }
    if version == V1:
        return {**base,
                "supportedInterfaces": [{"url": url, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"},
                                        {"url": url, "protocolBinding": "JSONRPC", "protocolVersion": "0.3"}],
                # securityRequirements is optional and its JSON shape is not
                # pinned down by the 1.0 text: the one scheme declared is the rule
                "securitySchemes": {"agentKey": {"apiKeySecurityScheme": {
                    "location": "header", "name": "X-Agent-Key",
                    "description": "The calling agent's own Provenza key"}}}}
    return {**base, "url": url, "protocolVersion": "0.3.0", "preferredTransport": "JSONRPC",
            "securitySchemes": {"agentKey": {"type": "apiKey", "in": "header", "name": "X-Agent-Key"}},
            "security": [{"agentKey": []}]}
