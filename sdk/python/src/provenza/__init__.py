# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Provenza SDK - governed, signed and auditable actions for AI agents.

    from provenza import Agent

    agent = Agent("support-bot")        # PROVENZA_URL + PROVENZA_TOKEN, or standalone without them

    @agent.tool(name="zendesk.read")
    def open_tickets() -> list: ...

See README.md for modes, keys and integrations.
"""

from provenza.agent import Agent, Check, ProvenzaWarning, ToolSpec
from provenza.errors import (ProvenzaApprovalRequired, ProvenzaConfigError, ProvenzaDenied, ProvenzaError,
                             ProvenzaRequestError, ProvenzaUnavailable)

__version__ = "0.2.1"

__all__ = [
    "Agent", "Check", "ToolSpec", "ProvenzaWarning",
    "ProvenzaError", "ProvenzaConfigError", "ProvenzaUnavailable", "ProvenzaRequestError",
    "ProvenzaDenied", "ProvenzaApprovalRequired", "__version__",
]
