#!/usr/bin/env python3
# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Run a verifier over Provenza's public audit-log test vectors
(sdk/testdata/audit-vectors.json, described in docs/audit-proofs.md): each
case is a document, the verifier's options, and the verdict it must reach.

    python tools/audit_vectors.py                       # tools/provenza_audit.py, next to this file
    python tools/audit_vectors.py --exec "./my-verifier"   # your own, with the same command line
    python tools/audit_vectors.py --list                # the cases and why each one passes or fails

With --exec, each case runs PROGRAM COMMAND FILE [options] - the command line
of tools/provenza_audit.py - and the exit status is the verdict
(0 = verified, 1 = not verified). Needs only Python; tools/provenza_audit.py
needs `cryptography` too.

Exit status: 0 = every case reached its verdict, 1 = at least one did not.
"""

import argparse
import contextlib
import importlib.util
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT = os.path.join(HERE, "..", "sdk", "testdata", "audit-vectors.json")


def argv_for(case, workdir):
    """The verifier's command line for one case; documents and keys are written to workdir."""
    def put(name, content):
        path = os.path.join(workdir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content if isinstance(content, str) else json.dumps(content, indent=1))
        return path

    args = case["args"]
    argv = [case["command"], put("document.json", case["document"])]
    for fp in args.get("fingerprint", []):
        argv += ["--fingerprint", fp]
    if "pinned" in args:
        argv += ["--pinned", put("pinned.json", args["pinned"])]
    if "tsa_ca" in args:
        argv += ["--tsa-ca", put("tsa-ca.pem", args["tsa_ca"])]
    if "rekor_key" in args:
        argv += ["--rekor-key", put("rekor-log.pem", args["rekor_key"])]
    if args.get("require_rekor"):
        argv.append("--require-rekor")
    for fp in args.get("publishing_key", []):
        argv += ["--publishing-key", fp]
    return argv


def _tool():
    spec = importlib.util.spec_from_file_location("provenza_audit_vectors_tool", os.path.join(HERE, "provenza_audit.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_case(case, program=None, tool=None):
    """(verdict, output): verdict is "verified", "not_verified" or "error"."""
    with tempfile.TemporaryDirectory() as workdir:
        argv = argv_for(case, workdir)
        if program:
            proc = subprocess.run([*shlex.split(program), *argv], capture_output=True, text=True, timeout=120)
            code, out = proc.returncode, proc.stdout + proc.stderr
        else:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                try:
                    code = tool.main(argv)
                except SystemExit as e:
                    code = e.code if isinstance(e.code, int) else 2
            out = buf.getvalue()
    return {0: "verified", 1: "not_verified"}.get(code, "error"), out


def check(vectors, program=None, verbose=False):
    """Run every case; returns the failures as (name, expected, got, output)."""
    tool = None if program else _tool()
    failures = []
    for case in vectors["cases"]:
        got, out = run_case(case, program, tool)
        reason_ok = program is not None or case["expect"] == "verified" or case.get("reason") is None \
            or case["reason"] in out
        good = got == case["expect"] and reason_ok
        if not good:
            failures.append((case["name"], case["expect"], got, out))
        if verbose or not good:
            print(f"{'ok  ' if good else 'FAIL'}  {case['name']:<42} expected {case['expect']:<13} got {got}")
            if not good:
                print("      " + out.strip().replace("\n", "\n      "))
    return failures


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("vectors", nargs="?", default=DEFAULT, help="the vectors file (default: sdk/testdata/audit-vectors.json)")
    p.add_argument("--exec", dest="program", help="run this verifier instead of tools/provenza_audit.py")
    p.add_argument("--list", action="store_true", help="list the cases and why each one passes or fails")
    p.add_argument("-v", "--verbose", action="store_true", help="print every case, not only the failures")
    args = p.parse_args(argv)
    with open(args.vectors, encoding="utf-8") as f:
        vectors = json.load(f)
    if args.list:
        for c in vectors["cases"]:
            print(f"{c['name']:<42} {c['expect']:<13} {c['why']}")
        return 0
    failures = check(vectors, args.program, args.verbose)
    n = len(vectors["cases"])
    print(f"{n - len(failures)} of {n} cases reached their verdict")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
