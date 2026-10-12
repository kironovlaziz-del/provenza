# Changelog

## v0.1.0 (unreleased)

First release. It has the same behaviour and the same bytes as the Python
and JS SDKs 0.1.

- `New`: enrollment with keys generated on the agent's side, stored in the
  shared identity file format. Optional hybrid Ed25519 + ML-DSA-65 keys,
  using `crypto/mldsa` from the Go standard library.
- `Call` (generic), `Check` / `Record`, `Delegate`, `WithChain`. The SDK
  fails closed by default. Standalone mode writes a signed local audit
  log, and `VerifyAuditLog` checks it. Unrecorded actions become signed
  gaps. `RecordBackground` keeps the order of records.
- The canonical form, hashes and signatures are byte-identical to the
  server's. Tests check them against the shared vectors and against the
  real server.
- `LLMGateway` and `MCPConnection` give the settings for Provenza's
  gateways.
- Standard library only.
