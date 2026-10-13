# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The agent host's egress self-check: is this host confined to the Provenza
egress proxy? (Server side: app/services/egress_check.py.)

    result = agent.egress_selfcheck()     # {"verdict": "confined" | "open", ...}

The server names a few targets on the internet and a beacon on itself. This
host tries each directly - a TCP connect - and fetches the beacon over HTTP
(through any proxy the environment configures: a forward proxy is a way out
too). It reports what it reached, signed. "confined" means nothing was
reached and the server did not see the beacon. Run it at start-up and
periodically; with "Require confined egress" on, an agent acts only while its
latest check is "confined" and recent.
"""

import asyncio
import socket
from typing import Any, Dict, List, Tuple

import httpx


def split(target: str) -> Tuple[str, int]:
    host, _, port = target.rpartition(":")
    return host.strip("[]"), int(port)


def connect(target: str, timeout: float) -> bool:
    try:
        with socket.create_connection(split(target), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


async def aconnect(target: str, timeout: float) -> bool:
    try:
        host, port = split(target)
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, ValueError, asyncio.TimeoutError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True


def beacon(url: str, timeout: float) -> bool:
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as c:
            return c.get(url).status_code == 204
    except httpx.HTTPError:
        return False


async def abeacon(url: str, timeout: float) -> bool:
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as c:
            return (await c.get(url)).status_code == 204
    except httpx.HTTPError:
        return False


def payload(agent_id: int, check_id: int, results: List[Dict[str, Any]], beacon_reached: bool) -> Dict[str, Any]:
    """What the server verifies: the results sorted by target."""
    return {"type": "egress.report", "agent_id": agent_id, "check_id": check_id,
            "results": sorted(({"target": r["target"], "reachable": bool(r["reachable"])} for r in results),
                              key=lambda r: r["target"]),
            "beacon_reached": bool(beacon_reached)}
