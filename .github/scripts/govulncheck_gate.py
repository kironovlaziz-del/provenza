#!/usr/bin/env python3
"""Reads `govulncheck -format json` on stdin and decides the CI result.

A vulnerability the module's code reaches (a finding whose trace names a
function) fails the job when a fixed version exists: the fix is an upgrade
away. One with no fix yet, or one only in an imported package that our code
never calls, is a warning: it is shown, it does not block unrelated PRs.
"""
import json
import sys


def _objects(text: str):
    decoder = json.JSONDecoder()
    i = 0
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            return
        obj, i = decoder.raw_decode(text, i)
        yield obj


def main() -> int:
    module = sys.argv[1] if len(sys.argv) > 1 else "."
    titles: dict[str, str] = {}
    seen: dict[tuple, dict] = {}
    for obj in _objects(sys.stdin.read()):
        if "osv" in obj:
            titles[obj["osv"]["id"]] = obj["osv"].get("summary") or ""
        finding = obj.get("finding")
        if not finding:
            continue
        trace = finding.get("trace") or [{}]
        called = bool(trace[0].get("function"))
        key = (finding["osv"], trace[0].get("module", ""))
        prev = seen.get(key)
        if prev is None or (called and not prev["called"]):
            seen[key] = {"called": called, "fixed": finding.get("fixed_version") or "",
                         "module": trace[0].get("module", ""), "version": trace[0].get("version", "")}
    failed = False
    for (osv, _), f in sorted(seen.items()):
        what = f"{osv} in {f['module']}@{f['version']}: {titles.get(osv, '')}".strip()
        if f["called"] and f["fixed"]:
            print(f"::error title=govulncheck {module}::{what} (fixed in {f['fixed']})")
            failed = True
        elif f["called"]:
            print(f"::warning title=govulncheck {module}::{what} (called; no fixed version yet)")
        else:
            print(f"::warning title=govulncheck {module}::{what} (imported, not called)")
    if not seen:
        print(f"govulncheck {module}: no known vulnerabilities")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
