# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The SDK against an in-memory Provenza (httpx.MockTransport) that verifies
signatures for real. backend/tests/test_sdk_python.py runs the SDK against the
actual server.
"""

import json
import os
import stat

import httpx
import pytest

from provenza import (Agent, ProvenzaApprovalRequired, ProvenzaConfigError, ProvenzaDenied, ProvenzaUnavailable,
                      ProvenzaWarning)
from provenza import identity as ids
from provenza.audit_log import verify
from tests.conftest import SERVER

# ---------------------------------------------------------------------------
# identity
# ---------------------------------------------------------------------------

class TestIdentity:
    def test_enrolls_once_and_keeps_keys_private(self, agent, server, tmp_path):
        path = tmp_path / "id.json"
        assert agent.agent_id == 42 and server.public_key == agent.identity.keys.public_key
        if os.name == "posix":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
        again = Agent("billing-bot", server_url=SERVER, identity_path=str(path),
                      transport=httpx.MockTransport(server.handle))   # no token needed any more
        assert again.fingerprint == agent.fingerprint

    def test_cli_and_sdk_share_the_file_format(self, agent, tmp_path):
        data = json.loads((tmp_path / "id.json").read_text())
        assert {"server", "agent_id", "api_key", "private_key", "public_key", "pq_private_key", "pq_public_key",
                "key_fingerprint"} <= set(data)

    def test_identity_is_never_sent_to_another_server(self, agent, server, tmp_path):
        with pytest.raises(ProvenzaConfigError, match="belongs to"):
            Agent("billing-bot", server_url="https://evil.test", identity_path=str(tmp_path / "id.json"),
                  transport=httpx.MockTransport(server.handle))

    def test_connected_without_enrollment_needs_a_token(self, tmp_path):
        with pytest.raises(ProvenzaConfigError, match="not enrolled"):
            Agent("x", server_url=SERVER, identity_path=str(tmp_path / "none.json"))

    @pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
    def test_a_world_readable_identity_is_refused(self, agent, tmp_path):
        path = tmp_path / "id.json"
        os.chmod(path, 0o644)
        with pytest.raises(ProvenzaConfigError, match="readable by other users"):
            ids.load(path)


# ---------------------------------------------------------------------------
# governed tool calls
# ---------------------------------------------------------------------------

class TestTools:
    def test_allowed_call_runs_and_is_recorded_signed(self, agent, server):
        calls = []

        @agent.tool(name="db.read")
        def read(query: str, limit: int = 10):
            calls.append(query)
            return {"rows": 3}

        assert read("select 1") == {"rows": 3} and calls == ["select 1"]
        check = next(iter(server.checks.values()))
        assert check["tool_name"] == "db.read" and check["input"] == {"query": "select 1", "limit": 10}
        assert server.records[0]["output"] == {"rows": 3}   # the fake verified the signature

    def test_denied_call_does_not_run_and_the_attempt_is_recorded(self, agent, server):
        server.verdicts["stripe.charge"] = "denied"
        ran = []

        @agent.tool(name="stripe.charge")
        def charge(amount: int):
            ran.append(amount)

        with pytest.raises(ProvenzaDenied) as exc:
            charge(100)
        assert isinstance(exc.value, PermissionError) and exc.value.action_id == 1
        assert ran == [] and server.records[0]["output"] is None

    def test_pending_approval_raises_its_own_error(self, agent, server):
        server.verdicts["email.send"] = "pending_approval"

        @agent.tool(name="email.send")
        def send(to: str):
            raise AssertionError("must not run")

        with pytest.raises(ProvenzaApprovalRequired):
            send("a@b.c")

    def test_a_failing_tool_is_recorded_without_its_message(self, agent, server):
        @agent.tool(name="db.read")
        def read():
            raise ValueError("secret connection string")

        with pytest.raises(ValueError):
            read()
        assert server.records[0]["output"] == {"error": "ValueError"}

    def test_fail_closed_when_the_server_is_down(self, agent, server):
        server.down.add("/agents/actions/check")
        ran = []

        @agent.tool(name="db.read")
        def read():
            ran.append(1)

        with pytest.raises(ProvenzaUnavailable):
            read()
        assert ran == []

    def test_fail_open_runs_and_logs_locally(self, agent, server):
        agent.fail_open = True
        server.down.add("/agents/actions/check")

        @agent.tool(name="db.read")
        def read():
            return 1

        with pytest.warns(ProvenzaWarning):
            assert read() == 1
        assert list(agent.audit_log.entries())[-1]["status"] == "unchecked"

    def test_record_retries_and_a_lasting_failure_is_a_signed_gap(self, agent, server, monkeypatch):
        import provenza.agent as mod
        monkeypatch.setattr(mod, "RECORD_RETRIES", (0, 0))

        @agent.tool(name="db.read")
        def read():
            return {"ok": True}

        server.record_failures = 2
        assert read() == {"ok": True} and len(server.records) == 1    # third attempt got through
        server.record_failures = 3
        with pytest.warns(ProvenzaWarning, match="could not be recorded"):
            assert read() == {"ok": True}                             # the tool already ran: its result stands
        gap = list(agent.audit_log.entries())[-1]
        assert gap["status"] == "unrecorded" and gap["check_id"]
        assert verify(agent.audit_log.path, agent.identity.keys.public_key) == []

    def test_non_json_arguments_are_refused_before_anything_runs(self, agent, server):
        @agent.tool(name="db.read")
        def read(x):
            raise AssertionError("must not run")

        with pytest.raises(TypeError, match="JSON-serializable"):
            read(object())
        with pytest.raises(TypeError):
            read(float("nan"))
        assert server.checks == {}

    def test_chain_context(self, agent, server):
        @agent.tool(name="db.read")
        def read():
            return 1

        with agent.chain(9):
            read()
        read()
        chains = [c["chain_id"] for c in server.checks.values()]
        assert chains == [9, None]

    def test_delegation_is_signed(self, agent, server):
        out = agent.delegate(7, "summarize", ["read"], tools=["db.read", "db.read"], expires_in=600)
        assert out["verified"] is True     # the fake verified the payload signature

    async def test_async_tools(self, agent, server):
        server.verdicts["web.fetch"] = "denied"

        @agent.tool(name="db.read")
        async def read(q: str):
            return {"q": q}

        @agent.tool(name="web.fetch")
        async def fetch(url: str):
            raise AssertionError("must not run")

        assert await read("x") == {"q": "x"}
        with pytest.raises(ProvenzaDenied):
            await fetch("https://x")
        await agent.aclose()


# ---------------------------------------------------------------------------
# standalone and the local log
# ---------------------------------------------------------------------------

class TestStandalone:
    def test_runs_without_a_server_and_signs_its_log(self, tmp_path):
        a = Agent("solo", identity_path=str(tmp_path / "solo.json"), allowed_tools=["calc.add"])
        assert a.mode == "standalone" and a.agent_id is None

        @a.tool(name="calc.add")
        def add(x, y):
            return x + y

        @a.tool(name="shell.run")
        def run(cmd):
            raise AssertionError("must not run")

        assert add(1, 2) == 3
        with pytest.raises(ProvenzaDenied):
            run("rm -rf /")
        statuses = [e["status"] for e in a.audit_log.entries()]
        assert statuses == ["recorded", "denied"]
        assert "rm -rf" not in a.audit_log.path.read_text()        # hashes, never the content
        assert verify(a.audit_log.path, a.identity.keys.public_key) == []

    def test_tampering_with_the_log_is_found(self, tmp_path):
        a = Agent("solo", identity_path=str(tmp_path / "solo.json"))

        @a.tool(name="calc.add")
        def add(x, y):
            return x + y

        for i in range(3):
            add(i, i)
        lines = a.audit_log.path.read_text().splitlines()
        edited = json.loads(lines[1])
        edited["tool"] = "calc.sub"
        (tmp_path / "solo.audit.jsonl").write_text("\n".join([lines[0], json.dumps(edited), lines[2]]) + "\n")
        problems = verify(a.audit_log.path, a.identity.keys.public_key)
        assert any("line 2" in p for p in problems)
        (tmp_path / "solo.audit.jsonl").write_text("\n".join([lines[0], lines[2]]) + "\n")   # a line removed
        assert any("chain broken" in p for p in verify(a.audit_log.path, a.identity.keys.public_key))


# ---------------------------------------------------------------------------
# record_mode="background"
# ---------------------------------------------------------------------------

class TestBackgroundRecords:
    def _agent(self, server, tmp_path):
        Agent("bg", server_url=SERVER, enrollment_token="pvz_enr_" + "x" * 20, identity_path=str(tmp_path / "bg.json"),
              transport=httpx.MockTransport(server.handle)).close()   # enroll once
        return Agent("bg", server_url=SERVER, identity_path=str(tmp_path / "bg.json"), record_mode="background",
                     transport=httpx.MockTransport(server.handle), async_transport=httpx.MockTransport(server.handle))

    def test_sync_tools_return_first_and_records_follow(self, server, tmp_path):
        agent = self._agent(server, tmp_path)

        @agent.tool(name="db.read")
        def read(i: int):
            return {"i": i}

        assert [read(i) for i in range(5)] == [{"i": i} for i in range(5)]
        assert agent.flush(timeout=10)
        assert [r["output"] for r in server.records] == [{"i": i} for i in range(5)]   # in order
        agent.close()

    def test_a_refusal_is_still_recorded_before_raising(self, server, tmp_path):
        agent = self._agent(server, tmp_path)
        server.verdicts["stripe.charge"] = "denied"

        @agent.tool(name="stripe.charge")
        def charge(amount: int):
            raise AssertionError("must not run")

        with pytest.raises(ProvenzaDenied) as exc:
            charge(1)
        assert exc.value.action_id is not None    # known at once: not deferred
        agent.close()

    def test_a_failed_background_record_is_a_gap(self, server, tmp_path, monkeypatch):
        import provenza.agent as mod
        monkeypatch.setattr(mod, "RECORD_RETRIES", (0, 0))
        agent = self._agent(server, tmp_path)
        server.record_failures = 3

        @agent.tool(name="db.read")
        def read():
            return 1

        with pytest.warns(ProvenzaWarning):
            read()
            agent.flush(timeout=10)
        assert list(agent.audit_log.entries())[-1]["status"] == "unrecorded"
        agent.close()

    async def test_async_tools(self, server, tmp_path):
        agent = self._agent(server, tmp_path)

        @agent.tool(name="db.read")
        async def read(i: int):
            return {"i": i}

        for i in range(3):
            assert await read(i) == {"i": i}
        await agent.aflush()
        assert len(server.records) == 3
        await agent.adelegate(7, "summarize", ["read"])
        await agent.aclose()


class TestApprovals:
    def test_wait_for_approval_returns_the_decision(self, agent, server):
        server.decisions[7] = ["pending_approval", "pending_approval", "approved"]
        state = agent.wait_for_approval(7, timeout=10, interval=0.01)
        assert state["decision"] == "approved" and server.decisions[7] == ["approved"]

    def test_wait_for_approval_gives_up_at_the_timeout(self, agent, server):
        state = agent.wait_for_approval(8, timeout=0, interval=0.01)
        assert state["decision"] == "pending_approval"

    async def test_async_wait(self, agent, server):
        server.decisions[9] = ["pending_approval", "denied"]
        assert (await agent.await_for_approval(9, timeout=10, interval=0.01))["decision"] == "denied"
