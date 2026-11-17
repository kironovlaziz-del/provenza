# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
A stand-in for DeepWiki's MCP server (https://mcp.deepwiki.com/mcp) for the
quickstart test (e2e/quickstart.py): the same three tools, answering at once,
so the test does not depend on a service on the internet.

    python3 e2e/fake_deepwiki.py --port 8765

Streamable HTTP, JSON responses, no session. Every tools/call it receives is
appended to --log, so the test can tell that a refused call never arrived.
"""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOLS = [
    {"name": "read_wiki_structure", "description": "Get a list of documentation topics for a GitHub repository.",
     "inputSchema": {"type": "object", "properties": {"repoName": {"type": "string"}}, "required": ["repoName"]}},
    {"name": "read_wiki_contents", "description": "View documentation about a GitHub repository.",
     "inputSchema": {"type": "object", "properties": {"repoName": {"type": "string"}}, "required": ["repoName"]}},
    {"name": "ask_wiki_question", "description": "Ask any question about a GitHub repository.",
     "inputSchema": {"type": "object", "properties": {"repoName": {"type": "string"}, "question": {"type": "string"}},
                     "required": ["repoName", "question"]}},
]


class Handler(BaseHTTPRequestHandler):
    log_path = None

    def log_message(self, *args):  # quiet
        pass

    def _send(self, code, body=None):
        data = b"" if body is None else json.dumps(body).encode()
        self.send_response(code)
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._send(405)

    def do_POST(self):
        msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        method, mid = msg.get("method"), msg.get("id")
        if mid is None:                       # a notification
            return self._send(202)
        if method == "initialize":
            asked = (msg.get("params") or {}).get("protocolVersion") or "2025-06-18"
            result = {"protocolVersion": asked, "capabilities": {"tools": {}},
                      "serverInfo": {"name": "fake-deepwiki", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            p = msg.get("params") or {}
            with open(self.log_path, "a") as f:
                f.write(json.dumps({"tool": p.get("name"), "arguments": p.get("arguments")}) + "\n")
            result = {"content": [{"type": "text", "text": f"fake-deepwiki answered {p.get('name')}"}]}
        elif method == "ping":
            result = {}
        else:                                 # server/discover and the like: not a modern server
            return self._send(404)
        self._send(200, {"jsonrpc": "2.0", "id": mid, "result": result})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--log", default="/tmp/fake-deepwiki-calls.jsonl")
    a = ap.parse_args()
    Handler.log_path = a.log
    open(a.log, "w").close()
    ThreadingHTTPServer((a.host, a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
