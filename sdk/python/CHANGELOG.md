# Changelog

## 0.1.0 (unreleased)

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
