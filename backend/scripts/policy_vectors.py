# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Generate sdk/testdata/policy-vectors.json: actions judged by a signed policy
bundle (app/pvp/bundle_eval.py). The enforcement points evaluate the same
bundle (proxy/internal/policy, Go) and must reach the same decision with the
same reason, word for word. The expected answers are the server's - never
edited by hand. From backend/:

    python scripts/policy_vectors.py            # write the file
    python scripts/policy_vectors.py --check    # exit 1 when it is out of date

backend/tests/test_policy_vectors.py runs --check.
"""

import copy
import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "sdk" / "testdata" / "policy-vectors.json"
NOW = 1_800_000_000

BUNDLE = {
    "type": "provenza.policy.bundle", "v": 1, "org_id": 1, "version": 7, "previous": None,
    "not_after": 1_900_000_000, "offline_seconds": 900,
    "agents": {
        "1": {"name": "payer", "status": "active", "team_id": 10, "capabilities": ["payments", "read"],
              "allowed_tools": ["db.drop", "db.read", "files.read", "kb.search", "llm.gpt-4o", "mail.send",
                                "payments.charge", "payments.refund", "proxy.stripe", "shell.run", "tickets.create"],
              "allowed_models": ["gpt-4o", "gpt-4o-mini"], "max_delegation_depth": 2},
        "2": {"name": "idle", "status": "suspended", "team_id": None, "capabilities": [], "allowed_tools": ["db.read"],
              "allowed_models": [], "max_delegation_depth": 1},
        "3": {"name": "plain", "status": "active", "team_id": None, "capabilities": ["read"],
              "allowed_tools": ["db.read", "db.write", "egress.api.openai.com", "egress.chat.example-ai.com",
                                "egress.api.example-ai.com", "egress.models.local", "unknown.tool"],
              "allowed_models": [], "max_delegation_depth": 0},
    },
    "agent_policies": {
        "21": {"agent_id": 1, "name": "no shell", "rules": {"deny_tools": ["shell.run"]}, "priority": 100,
               "enabled": True},
        "22": {"agent_id": None, "name": "mail rules", "rules": {"argument_rules": [
            {"tool": "mail.send", "arg": "to", "op": "domain_in", "value": ["corp.example"], "effect": "deny"},
            {"tool": "mail.send", "arg": "subject", "op": "max_length", "value": 20, "effect": "require_approval"},
        ]}, "priority": 90, "enabled": True},
        "23": {"agent_id": 1, "name": "off", "rules": {"deny_tools": ["db.read"]}, "priority": 80, "enabled": False},
        "24": {"agent_id": 3, "name": "read only", "rules": {"allow_only_tools": ["db.read", "unknown.tool"],
                                                           "typo_rule": ["db.read"]}, "priority": 50, "enabled": True},
        "25": {"agent_id": 1, "name": "files", "rules": [
            {"argument_rules": [{"tool": "files.*", "arg": "path", "op": "starts_with", "value": ["/sandbox/"]}]},
            {"argument_rules": [{"tool": "files.read", "arg": "opts.encoding", "op": "in", "value": ["utf-8", "ascii"],
                                 "effect": "require_approval"}]},
        ], "priority": 40, "enabled": True},
        "26": {"agent_id": 1, "name": "tickets", "rules": {"argument_rules": [
            {"tool": "tickets.create", "arg": "priority", "op": "max", "value": 3},
            {"tool": "tickets.create", "arg": "title", "op": "not_matches", "value": "(?i)\\b(urgent|asap)\\b",
             "effect": "require_approval"},
            {"tool": "tickets.create", "arg": "tags", "op": "not_in", "value": ["secret"]},
            {"tool": "tickets.create", "arg": "queue", "op": "matches", "value": "^[a-z]+$"},
            {"tool": "tickets.create", "arg": "count", "op": "min", "value": 1},
            {"tool": "tickets.create", "arg": "kind", "op": "equals", "value": "bug"},
        ]}, "priority": 30, "enabled": True},
        "27": {"agent_id": 1, "name": "no refunds by api", "rules": {"deny_action_types": ["api_request"]},
               "priority": 20, "enabled": True},
    },
    "policy_layers": {
        "org": {"tools": {"deny": ["*.drop"]}},
        "team:11": {"tools": {"require_approval": ["payments.*"]}, "limits": {"max_delegation_depth": 1}},
        "team:10": {"tools": {"allow": ["db.*", "files.*", "kb.*", "llm.*", "mail.*", "payments.*", "proxy.*",
                                        "shell.*", "tickets.*"]}, "models": {"allow": ["gpt-4o*"]}},
        "agent:1": {"models": {"allow": ["gpt-4o"]}},
    },
    "teams": {"10": {"name": "ops", "parent_id": 11}, "11": {"name": "root", "parent_id": None}},
    "tool_registry": {"mode": "enforce", "entries": {
        "db.read": {"kind": "tool", "status": "approved", "pinned_version": None, "pinned_digest": None,
                    "required_capabilities": ["read"]},
        "db.*": {"kind": "tool", "status": "approved", "pinned_version": None, "pinned_digest": None,
                 "required_capabilities": None},
        "db.write": {"kind": "tool", "status": "blocked", "pinned_version": None, "pinned_digest": None,
                     "required_capabilities": None},
        "payments.*": {"kind": "tool", "status": "approved", "pinned_version": None, "pinned_digest": None,
                       "required_capabilities": ["payments"]},
        "payments.refund": {"kind": "tool", "status": "approved", "pinned_version": None, "pinned_digest": None,
                            "required_capabilities": ["refunds"]},
        "files.read": {"kind": "tool", "status": "approved", "pinned_version": "1.2",
                       "pinned_digest": "ab" * 32, "required_capabilities": None},
        "kb.search": {"kind": "tool", "status": "drifted", "pinned_version": None, "pinned_digest": None,
                      "required_capabilities": None},
        "mail.*": {"kind": "tool", "status": "approved", "pinned_version": None, "pinned_digest": None,
                   "required_capabilities": None},
        "tickets.*": {"kind": "tool", "status": "approved", "pinned_version": None, "pinned_digest": None,
                      "required_capabilities": None},
        "shell.*": {"kind": "tool", "status": "approved", "pinned_version": None, "pinned_digest": None,
                    "required_capabilities": None},
    }},
    "identity": {"require_agent_key": True, "rotation_grace_minutes": 60, "require_pq_signatures": False,
                 "allow_direct_registration": False, "require_confined_egress": False,
                 "egress_check_max_age_hours": 24},
    "provider_policy": "any",
    "ai_domains": {"openai.com": "blocked", "example-ai.com": "blocked", "api.example-ai.com": "allowed"},
    "gateway": {"settings": {"enabled": True, "rpm_per_agent": 60, "max_tokens_cap": 4096}, "routes": {}},
    "mcp_servers": {}, "a2a_peers": {}, "http_tools": {},
    "egress_routes": {"5": {"slug": "stripe", "upstream_url": "https://api.stripe.com", "methods": ["GET", "POST"],
                            "path_prefixes": ["/v1/charges"], "credential_source": "local",
                            "auth_header": "Authorization", "max_body_bytes": 1024, "enabled": True}},
}
MANIFEST = {"type": "provenza.key.manifest", "v": 1, "org_id": 1, "version": 3, "previous": None, "quorum": 1,
            "signers": {}, "agents": {"1": "SHA256:agent-one", "2": "SHA256:agent-two", "3": "SHA256:agent-three"},
            "egress_proxies": {}, "egress_sensors": {}, "sensor_command_key": None}


def proxy_input(**over):
    d = {"route": "stripe", "method": "POST", "path": "/v1/charges", "query_sha256": None,
         "body_sha256": "cd" * 32, "body_bytes": 32}
    d.update(over)
    return d


def mail(**over):
    d = {"to": "ann@corp.example", "subject": "hello"}
    d.update(over)
    return d


def ticket(**over):
    d = {"priority": 2, "title": "printer", "tags": ["ops"], "queue": "it", "count": 1, "kind": "bug"}
    d.update(over)
    return d


def req(tool, inp=None, agent=1, action_type="tool_call", **extra):
    r = {"agent_id": agent, "action_type": action_type, "tool_name": tool, "input": {} if inp is None else inp}
    r.update(extra)
    return r


CASES = [
    ("allowed", {}, req("db.read", {"q": "select 1"})),
    ("not in the bundle", {}, req("db.read", agent=9)),
    ("key from the manifest", {}, req("db.read", key_fingerprint="SHA256:agent-one")),
    ("another key", {}, req("db.read", key_fingerprint="SHA256:someone-else")),
    ("no key for the agent", {}, req("db.read", key_fingerprint=None)),
    ("suspended", {}, req("db.read", agent=2)),
    ("expired", {"now": 1_900_000_001}, req("db.read")),
    ("tool not granted", {}, req("db.write", agent=1)),
    ("capability the registry requires", {}, req("payments.refund", {"amount": 1})),
    ("organization deny pattern", {}, req("db.drop")),
    ("team approval pattern", {}, req("payments.charge", {"amount": 5})),
    ("agent policy deny", {}, req("shell.run", {"cmd": "ls"})),
    ("disabled policy is ignored, unknown rule keys too", {}, req("db.read", agent=3)),
    ("allow only lets it through, the registry does not", {}, req("unknown.tool", agent=3)),
    ("allow only refuses", {}, req("db.write", agent=3)),
    ("blocked in the registry", {"policy_off": ["24"]}, req("db.write", agent=3)),
    ("not in the registry (enforce)", {"policy_off": ["24"]}, req("unknown.tool", agent=3)),
    ("not in the registry (monitor)", {"policy_off": ["24"], "registry_mode": "monitor"}, req("unknown.tool", agent=3)),
    ("registry off", {"policy_off": ["24"], "registry_mode": "off"}, req("db.write", agent=3)),
    ("drifted entry", {}, req("kb.search", {"q": "x"})),
    ("pinned: version and digest reported", {}, req("files.read", {"path": "/sandbox/a.txt", "opts": {"encoding": "utf-8"}},
                                                    tool_version="1.2", tool_digest="sha256:" + "AB" * 32)),
    ("pinned: other version", {}, req("files.read", {"path": "/sandbox/a.txt", "opts": {"encoding": "utf-8"}},
                                      tool_version="1.3", tool_digest="ab" * 32)),
    ("pinned: nothing reported", {}, req("files.read", {"path": "/sandbox/a.txt", "opts": {"encoding": "utf-8"}})),
    ("action type denied", {}, req("db.read", action_type="api_request")),
    ("domain_in ok", {}, req("mail.send", mail())),
    ("domain_in subdomain", {}, req("mail.send", mail(to="Bob <bob@eu.corp.example>"))),
    ("domain_in other", {}, req("mail.send", mail(to="eve@evil.example"))),
    ("domain_in every element of a list", {}, req("mail.send", mail(to=["a@corp.example", "b@evil.example"]))),
    ("max_length -> approval", {}, req("mail.send", mail(subject="a subject that is long"))),
    ("missing argument", {}, req("mail.send", {"subject": "hi"})),
    ("starts_with normalised path", {}, req("files.read", {"path": "/sandbox/../etc/passwd", "opts": {"encoding": "utf-8"}},
                                            tool_version="1.2", tool_digest="ab" * 32)),
    ("starts_with the prefix itself", {}, req("files.read", {"path": "/sandbox", "opts": {"encoding": "ascii"}},
                                              tool_version="1.2", tool_digest="ab" * 32)),
    ("nested argument missing -> approval", {}, req("files.read", {"path": "/sandbox/x"},
                                                    tool_version="1.2", tool_digest="ab" * 32)),
    ("ticket ok", {}, req("tickets.create", ticket())),
    ("max from a numeric string", {}, req("tickets.create", ticket(priority="2.5"))),
    ("max over", {}, req("tickets.create", ticket(priority=4))),
    ("max with a bool", {}, req("tickets.create", ticket(priority=True))),
    ("not_matches -> approval", {}, req("tickets.create", ticket(title="URGENT: printer"))),
    ("not_in", {}, req("tickets.create", ticket(tags=["ops", "secret"]))),
    ("matches", {}, req("tickets.create", ticket(queue="IT"))),
    ("min", {}, req("tickets.create", ticket(count=0))),
    ("equals", {}, req("tickets.create", ticket(kind="feature"))),
    ("equals: 1 is 1.0", {"patch_rule": ("26", 5, "value", 1)}, req("tickets.create", ticket(kind=1.0))),
    ("proxy request", {}, req("proxy.stripe", proxy_input(), action_type="proxy")),
    ("proxy method", {}, req("proxy.stripe", proxy_input(method="DELETE"), action_type="proxy")),
    ("proxy path outside", {}, req("proxy.stripe", proxy_input(path="/v1/customers"), action_type="proxy")),
    ("proxy dot segment", {}, req("proxy.stripe", proxy_input(path="/v1/charges/%2e%2e/x"), action_type="proxy")),
    ("proxy body", {}, req("proxy.stripe", proxy_input(body_bytes=2048), action_type="proxy")),
    ("proxy unknown route", {}, req("proxy.github", proxy_input(route="github"), action_type="proxy")),
    ("proxy descriptor", {}, req("proxy.stripe", {"route": "stripe", "method": "POST"}, action_type="proxy")),
    ("egress blocked", {}, req("egress.api.openai.com", {"host": "api.openai.com"}, agent=3, action_type="egress")),
    ("egress allowed sub-entry", {"policy_off": ["24"]}, req("egress.api.example-ai.com", {"host": "api.example-ai.com"}, agent=3,
                                         action_type="egress")),
    ("egress blocked parent", {}, req("egress.chat.example-ai.com", {"host": "chat.example-ai.com"}, agent=3,
                                      action_type="egress")),
    ("egress unknown host", {"policy_off": ["24"]}, req("egress.models.local", {"host": "models.local"}, agent=3, action_type="egress")),
    ("egress self-hosted only", {"provider_policy": "self_hosted", "policy_off": ["24"]},
     req("egress.api.example-ai.com", {"host": "api.example-ai.com"}, agent=3, action_type="egress")),
    ("egress names another host", {}, req("egress.models.local", {"host": "api.openai.com"}, agent=3,
                                          action_type="egress")),
    ("model call", {}, req("llm.gpt-4o", {"model": "gpt-4o"}, action_type="model_call")),
    ("model call: model not granted", {}, req("llm.o3", {"model": "o3"}, action_type="model_call")),
    ("model call: hierarchy narrows", {}, req("llm.gpt-4o-mini", {"model": "gpt-4o-mini"}, action_type="model_call")),
    ("deny beats approval", {"patch_layer": ("team:11", {"tools": {"require_approval": ["shell.*"]}})},
     req("shell.run", {"cmd": "ls"})),
]


def build():
    from app.pvp import bundle_eval
    from app.pvp.signed_policy import SignedPolicy

    out = []
    for name, opts, request in CASES:
        bundle = copy.deepcopy(BUNDLE)
        for pid in opts.get("policy_off", []):
            bundle["agent_policies"][pid]["enabled"] = False
        if "registry_mode" in opts:
            bundle["tool_registry"]["mode"] = opts["registry_mode"]
        if "provider_policy" in opts:
            bundle["provider_policy"] = opts["provider_policy"]
        if "patch_rule" in opts:
            pid, idx, key, value = opts["patch_rule"]
            bundle["agent_policies"][pid]["rules"]["argument_rules"][idx][key] = value
        if "patch_layer" in opts:
            bundle["policy_layers"][opts["patch_layer"][0]] = opts["patch_layer"][1]
        now = opts.get("now", NOW)
        policy = SignedPolicy(release_id=1, number=7, bundle=bundle, manifest=MANIFEST)
        kw = {"key_fingerprint": request["key_fingerprint"]} if "key_fingerprint" in request else {}
        d = bundle_eval.evaluate(policy, agent_id=request["agent_id"], action_type=request["action_type"],
                                 tool_name=request["tool_name"], input_data=request["input"],
                                 tool_version=request.get("tool_version"), tool_digest=request.get("tool_digest"),
                                 now=now, **kw)
        changes = {k: v for k, v in bundle.items() if v != BUNDLE.get(k)}
        out.append({"name": name, "now": now, "bundle": changes, "request": request,
                    "expect": {"decision": d.result, "reason": d.reason,
                               "required_capabilities": d.required_capabilities}})
    return {"comment": "actions judged by a signed policy bundle (backend/app/pvp/bundle_eval.py); generated by "
                       "backend/scripts/policy_vectors.py - every enforcement point must reach the same decision "
                       "with the same reason. A case's \"bundle\" replaces those sections of the base bundle; a "
                       "request without key_fingerprint is not checked against the manifest's key.",
            "release": 7, "base_bundle": BUNDLE, "manifest": MANIFEST, "cases": out}


def main() -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    text = json.dumps(build(), indent=1, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            print(f"{OUT} is out of date: run python scripts/policy_vectors.py")
            return 1
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT} ({len(CASES)} cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
