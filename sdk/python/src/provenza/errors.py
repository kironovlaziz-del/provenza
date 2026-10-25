# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Exceptions raised by the SDK. Every one derives from ProvenzaError."""

from typing import Any, Optional


class ProvenzaError(Exception):
    """Base class of every SDK error."""


class ProvenzaConfigError(ProvenzaError):
    """The agent is not set up: no server and no identity, a missing
    enrollment token, an unreadable identity file, ..."""


class ProvenzaUnavailable(ProvenzaError):
    """The Provenza server could not be reached or failed (network error,
    timeout, 5xx). In connected mode the tool call was NOT made - the SDK
    fails closed unless the agent was created with fail_open=True."""


class ProvenzaRequestError(ProvenzaError):
    """The server refused the request itself (4xx): bad credentials, an
    unknown agent, a malformed body. `status` and `detail` are the server's."""

    def __init__(self, status: int, detail: Any, path: str = ""):
        super().__init__(f"{path}: HTTP {status}: {detail}")
        self.status, self.detail, self.path = status, detail, path


class ProvenzaDenied(ProvenzaError, PermissionError):
    """Provenza's verdict refused the call; the tool did not run. The
    attempt is recorded. A PermissionError, so code that already handles
    permission failures handles this too."""

    def __init__(self, tool: str, reason: str, decision: str = "denied", incident_type: Optional[str] = None,
                 check_id: Optional[str] = None, action_id: Optional[int] = None):
        super().__init__(f"{tool}: {decision}: {reason}")
        self.tool, self.reason, self.decision = tool, reason, decision
        self.incident_type, self.check_id, self.action_id = incident_type, check_id, action_id


class ProvenzaApprovalRequired(ProvenzaDenied):
    """The call needs a human approval first; it did not run. The pending
    action is recorded (action_id) for an approver to decide. Once approved,
    make exactly the same call again: it runs once (agent.wait_for_approval
    waits for the decision)."""
