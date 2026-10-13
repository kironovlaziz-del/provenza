# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""provenza.egress_check: what this host can reach directly, and the signed report."""

import socket

from provenza import egress_check


def test_connect_sees_what_listens():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        assert egress_check.connect(f"127.0.0.1:{port}", 1.0)
    finally:
        s.close()
    assert not egress_check.connect(f"127.0.0.1:{port}", 1.0)
    assert not egress_check.connect("not a target", 1.0)


def test_the_signed_payload_is_order_independent():
    a = egress_check.payload(7, 3, [{"target": "b:1", "reachable": 0}, {"target": "a:2", "reachable": 1}], False)
    b = egress_check.payload(7, 3, [{"target": "a:2", "reachable": True}, {"target": "b:1", "reachable": False}], False)
    assert a == b == {"type": "egress.report", "agent_id": 7, "check_id": 3, "beacon_reached": False,
                      "results": [{"target": "a:2", "reachable": True}, {"target": "b:1", "reachable": False}]}
