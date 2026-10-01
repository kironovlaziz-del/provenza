# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Code-execution detector - OWASP Agentic Top 10, ASI05 (unexpected code execution).

An agent that can reach a shell, an interpreter or a database can be steered
(by a prompt injection, a poisoned document, its own hallucination) into
running something nobody intended. This module looks at the *arguments* of a
tool call for the shapes of such code. Pure functions, no database.

Every finding has a severity:

    critical  reverse shells, pipe-to-shell downloads, disk wipes, fork bombs,
              Log4Shell lookups, OS commands from SQL, serialized objects
    high      eval/exec and process spawning in code, SQL injection shapes,
              template injection, sensitive system files, path traversal
    medium    shell chaining / network tools / privilege escalation inside a
              command (only for code tools or command-like arguments)

Scope: "any" patterns are checked in every string argument; "command"
patterns only where a command is expected - arguments of a code tool, or
keys such as cmd / command / script - so that a ";" or "|" in an e-mail body
is not a finding. Path traversal is checked in path-like keys only.

Bounded regexes, at most MAX_TEXT characters per value, MAX_NODES values.
"""

import re
import unicodedata
from typing import Any, Dict, List

MAX_TEXT = 100_000
MAX_NODES = 2_000
MAX_DEPTH = 20
SNIPPET = 80

SEVERITIES = ("medium", "high", "critical")
RANK = {s: i for i, s in enumerate(SEVERITIES)}

COMMAND_KEYS = {"cmd", "command", "commands", "shell", "script", "code", "args", "argv", "exec", "run",
                "bash", "sh", "powershell", "query_command", "program"}
PATH_KEYS = {"path", "file", "filename", "file_path", "filepath", "dir", "directory", "folder", "url", "uri",
             "src", "source", "dest", "destination", "target", "location", "key", "object_key"}

_F = re.IGNORECASE
_FM = re.IGNORECASE | re.MULTILINE

# (label, severity, scope, regexes)
PATTERNS = [
    # ---------------------------------------------------------------- critical
    ("reverse_shell", "critical", "any", [
        re.compile(r"/dev/(?:tcp|udp)/[\w.\-]{1,100}/\d{1,5}", _F),
        re.compile(r"\bn(?:c|cat|etcat)\b[^\n]{0,80}\s-[a-z]*e\s+\S*(?:/bin/)?(?:ba|z|da)?sh\b", _F),
        re.compile(r"\bmkfifo\b[^\n]{0,80}\bn(?:c|cat)\b", _F),
        re.compile(r"socket[^\n]{0,120}(?:subprocess|pty\.spawn|os\.dup2)", _F),
    ]),
    ("pipe_to_shell", "critical", "any", [
        re.compile(r"\b(?:curl|wget|iwr|invoke-webrequest)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b", _F),
        re.compile(r"\bbase64\s+(?:-d|--decode)\b[^\n|]{0,100}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", _F),
        re.compile(r"\bpowershell(?:\.exe)?\b[^\n]{0,60}\s-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", _F),
        re.compile(r"\biex\s*\(\s*(?:new-object|iwr|invoke-webrequest|\(new-object)", _F),
    ]),
    ("destructive_command", "critical", "any", [
        re.compile(r"\brm\s+(?:-[a-z]*r[a-z]*\s+|-[a-z]*f[a-z]*\s+|--recursive\s+|--force\s+|--no-preserve-root\s+){1,4}"
                   r"(?:/|/\*|~/?|\$HOME/?|\*)(?=\s|$|;|&|\|)", _F),
        re.compile(r"\bmkfs(?:\.\w+)?\s+/dev/", _F),
        re.compile(r"\bdd\s+if=[^\n]{0,60}\bof=/dev/(?:sd|nvme|hd|xvd|vd|disk)", _F),
        re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
        re.compile(r"\bformat\s+[a-z]:\s*/[qy]", _F),
    ]),
    ("jndi_lookup", "critical", "any", [
        re.compile(r"\$\{(?:jndi|\$\{[^}]{0,20}\}j)[^}]{0,20}:", _F),
    ]),
    ("sql_os_command", "critical", "any", [
        re.compile(r"\bxp_cmdshell\b", _F),
        re.compile(r"\bcopy\b[^\n;]{0,120}\b(?:from|to)\s+program\b", _F),
        re.compile(r"\binto\s+(?:out|dump)file\b", _F),
        re.compile(r"\blo_(?:import|export)\s*\(|\bload_file\s*\(", _F),
    ]),
    ("serialized_object", "critical", "any", [
        re.compile(r"\brO0AB[A-Za-z0-9+/=]{20,}"),          # Java serialization, base64
        re.compile(r"\bgASV[A-Za-z0-9+/=]{20,}"),           # Python pickle protocol 4+, base64
        re.compile(r"!!python/(?:object|name|module)", _F),  # unsafe YAML tags
        re.compile(r"\bO:\d+:\"[A-Za-z_\\]{1,100}\":\d+:\{"),  # PHP serialize()
    ]),
    # ---------------------------------------------------------------- high
    ("code_eval", "high", "any", [
        re.compile(r"(?<![.\w])(?:eval|exec|execfile)\s*\(\s*[\"'\w(]"),
        re.compile(r"__import__\s*\(|\bimportlib\.import_module\s*\("),
        re.compile(r"\bos\.(?:system|popen|exec[lv]p?e?|spawn\w*)\s*\("),
        re.compile(r"\bsubprocess\.(?:run|call|Popen|check_output|check_call|getoutput)\s*\("),
        re.compile(r"\bRuntime\.getRuntime\(\)\.exec\s*\(|\bProcessBuilder\s*\("),
        re.compile(r"\brequire\s*\(\s*[\"']child_process[\"']\s*\)|\bchild_process\.(?:exec|spawn)"),
        re.compile(r"\b(?:pickle|cPickle|marshal|dill|shelve)\.loads?\s*\("),
        re.compile(r"\byaml\.(?:unsafe_)?load\s*\((?![^)]{0,200}SafeLoader)"),
        re.compile(r"\bnew\s+Function\s*\(|\bsetTimeout\s*\(\s*[\"']"),
    ]),
    ("template_injection", "high", "any", [
        re.compile(r"\{\{[^}]{0,120}(?:__class__|__globals__|__subclasses__|__builtins__|__mro__|config\.items|request\.application)", _F),
        re.compile(r"\$\{[^}]{0,80}(?:Runtime|getClass|T\(java)", _F),
        re.compile(r"<%=?[^%]{0,120}(?:Runtime|exec|system)\s*\(", _F),
    ]),
    ("sql_injection", "high", "any", [
        re.compile(r"'\s*(?:or|and)\s+'?\w{1,10}'?\s*=\s*'?\w{1,10}'?\s*(?:--|#|/\*|$)", _FM),
        re.compile(r"\bunion\s+(?:all\s+)?select\b", _F),
        re.compile(r";\s*(?:drop|truncate|alter|grant|revoke)\s+(?:table|database|schema|user|role|all|index)\b", _F),
        re.compile(r";\s*(?:delete\s+from|update\s+\w+\s+set|insert\s+into|create\s+(?:user|role|function))\b", _F),
        re.compile(r"\b(?:pg_sleep|benchmark)\s*\(\s*\d+|'\s*(?:and|or)\s+sleep\s*\(|\bwaitfor\s+delay\s+'", _F),
    ]),
    ("sensitive_file", "high", "any", [
        re.compile(r"/etc/(?:shadow|gshadow|sudoers|master\.passwd)\b"),
        re.compile(r"/etc/passwd\b"),
        re.compile(r"(?:^|[/\\~])\.ssh[/\\](?:id_\w+|authorized_keys|known_hosts)\b"),
        re.compile(r"(?:^|[/\\~])\.(?:aws[/\\]credentials|docker[/\\]config\.json|kube[/\\]config|netrc|pgpass|git-credentials)\b"),
        re.compile(r"/proc/(?:self|\d+)/(?:environ|mem|maps|cmdline)\b"),
        re.compile(r"\b169\.254\.169\.254\b|\bmetadata\.google\.internal\b"),  # cloud metadata (SSRF)
        re.compile(r"\\windows\\system32\\config\\(?:sam|system|security)\b", _F),
    ]),
    ("encoded_traversal", "high", "any", [
        re.compile(r"(?:%2e|\.){2}(?:%2f|%5c)|(?:%2e){2}[/\\]|%252e%252e|\.\.%c0%af", _F),
    ]),
    # ---------------------------------------------------------------- medium (command scope)
    ("shell_chaining", "medium", "command", [
        re.compile(r"(?:;|&&|\|\|)\s*\S|(?<![|])\|(?![|])\s*\S|`[^`\n]{1,200}`|\$\([^)\n]{1,200}\)"),
    ]),
    ("network_tool", "medium", "command", [
        re.compile(r"\b(?:curl|wget|nc|ncat|netcat|socat|telnet|ssh|scp|rsync|ftp|tftp)\b", _F),
    ]),
    ("privilege_escalation", "medium", "command", [
        re.compile(r"\bsudo\b|\bsu\s+-|\bchmod\s+(?:-R\s+)?(?:[0-7]?777|u\+s|\+s)\b|\bchown\s+(?:-R\s+)?root\b|\bsetcap\b", _F),
    ]),
    ("interpreter_inline", "medium", "command", [
        re.compile(r"\b(?:python[23]?|perl|ruby|node|php)\s+-[a-z]*[ce]\b|\bbash\s+-c\b|\bsh\s+-c\b|\bcmd(?:\.exe)?\s+/c\b", _F),
    ]),
]

LABEL_SEVERITY: Dict[str, str] = {label: sev for label, sev, _, _ in PATTERNS}
LABEL_SEVERITY["path_traversal"] = "high"

_TRAVERSAL = re.compile(r"(?:^|[/\\])\.\.(?:[/\\]|$)")


def _snippet(s: str) -> str:
    s = s.replace("\n", " ").strip()
    return s if len(s) <= SNIPPET else s[: SNIPPET - 1] + "…"


def _key(path: str) -> str:
    """Last key of a path such as "steps[0].cmd" -> "cmd"."""
    last = re.split(r"[.\[]", path)[-1] if path else ""
    return last.rstrip("]").lower()


def scan_value(text: str, path: str = "", code_tool: bool = False) -> List[dict]:
    """Findings for one string value."""
    if not isinstance(text, str) or not text:
        return []
    text = unicodedata.normalize("NFKC", text[:MAX_TEXT])
    key = _key(path)
    command = code_tool or key in COMMAND_KEYS
    out: List[dict] = []
    for label, sev, scope, regexes in PATTERNS:
        if scope == "command" and not command:
            continue
        for rx in regexes:
            m = rx.search(text)
            if m:
                out.append({"label": label, "severity": sev, "path": path or "$", "snippet": _snippet(m.group(0))})
                break
    if key in PATH_KEYS or command:
        m = _TRAVERSAL.search(text)
        if m:
            start = max(0, m.start() - 20)
            out.append({"label": "path_traversal", "severity": "high", "path": path or "$",
                        "snippet": _snippet(text[start:m.end() + 40])})
    return out


def worst(findings: List[dict]) -> str:
    if not findings:
        return "none"
    return max((f["severity"] for f in findings), key=lambda s: RANK[s])


def scan_arguments(obj: Any, code_tool: bool = False) -> dict:
    """Scan every string value of a tool's arguments.

    Returns {severity: none|medium|high|critical, findings: [...]} with the
    findings ordered most severe first (at most 20, one per label and path).
    """
    findings: List[dict] = []
    nodes = 0

    def visit(node: Any, path: str, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            return
        if isinstance(node, str):
            findings.extend(scan_value(node, path, code_tool))
        elif isinstance(node, dict):
            for k, v in node.items():
                visit(v, f"{path}.{k}" if path else str(k), depth + 1)
        elif isinstance(node, (list, tuple)):
            # a list of strings under a command key is one command line: ["sh", "-c", "..."]
            if node and all(isinstance(x, str) for x in node) and (code_tool or _key(path) in COMMAND_KEYS):
                findings.extend(scan_value(" ".join(node), path, code_tool))
                return
            for i, v in enumerate(node):
                visit(v, f"{path}[{i}]", depth + 1)

    visit(obj, "", 0)
    findings.sort(key=lambda f: -RANK[f["severity"]])
    return {"severity": worst(findings), "findings": findings[:20]}
