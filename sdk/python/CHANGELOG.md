# Changelog

## Unreleased

- Every `check` is signed by the agent: a nonce, the time and a signature
  over the request (Ed25519, plus ML-DSA-65 for hybrid keys). The server
  now refuses unsigned checks from agents.
- `provenza.auto.instrument(agent)`: direct calls to AI providers (httpx
  sync and async, requests) become governed "egress" actions, decided by
  the server against the organization's AI domain catalog. A refusal is an
  HTTP 403 that provider SDKs do not retry. Only hashes of request bodies
  are recorded, never prompts.
- `agent.proxy_check` / `aproxy_check`: SDK mode of the egress proxy. The
  agent checks a request itself and sends `check.proxy_headers`.
- `agent.call(..., output_of=...)` chooses what is recorded of a result.

## 0.1.0 (2026-10-11)

First release.

- `Agent`: enrollment with a one-time token, with keys generated on the
  agent's side. The identity is stored in a file (mode 600, the format of
  `tools/provenza_sign.py`) or in the OS keychain (`[keychain]`). Hybrid
  Ed25519 + ML-DSA-65 keys are available with `[pq]`.
- `@agent.tool` (sync and async), `agent.call` / `acall`, `check` /
  `record`, `delegate` / `adelegate`, and `agent.chain(...)`.
- Connected mode is fail-closed by default (`fail_open=True` to opt out).
  Standalone mode writes a local, signed, hash-chained audit log, which
  `audit_log.verify()` checks.
- An action that ran but could not be recorded on the server becomes a
  signed gap in the local log. `record_mode="background"` keeps one
  round-trip on the hot path.
- Integrations: OpenAI (through the LLM gateway), MCP (connection to the
  MCP gateway), LangChain, AutoGen and CrewAI. Each is an optional extra.
