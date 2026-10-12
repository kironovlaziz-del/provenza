// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

// Package provenza is the Go SDK for Provenza: governed, signed and auditable
// actions for AI agents. It behaves like the Python and JS SDKs and speaks the
// same bytes - identity files, signatures and local audit logs are shared.
//
//	agent, err := provenza.New(ctx, provenza.Config{Name: "billing-bot"}) // PROVENZA_URL / PROVENZA_TOKEN
//	rows, err := provenza.Call(ctx, agent, "db.read", map[string]any{"query": q},
//		func(ctx context.Context) ([]Row, error) { return db.Query(ctx, q) })
//
// In connected mode every call is checked by the server, runs only if
// allowed, and is recorded with the agent's signature. A denied call returns a
// *DeniedError; the server unreachable returns an *UnavailableError and the
// function does not run (fail-closed). In standalone mode calls go to a
// local, signed, hash-chained audit log.
//
// The SDK runs inside the agent's process: it is the agent's honest record and
// cooperative enforcement. Enforcement independent of the agent's code is
// Provenza's gateways (LLM, MCP, A2A).
//
// Only the Go standard library is used (ML-DSA-65 is crypto/mldsa, Go 1.27).
package provenza
