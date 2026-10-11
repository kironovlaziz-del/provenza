# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
PVP - Provenza Verification Protocol (docs/pvp/spec.md).

The one internal language of agent governance: every inbound protocol (REST,
MCP, Google A2A) is translated into PVP messages, the orchestrator understands
nothing else, and every outbound format (REST, MCP, A2A, TRACE) is produced
from PVP records.
"""

from app.pvp.model import PVP_VERSION  # noqa: F401
