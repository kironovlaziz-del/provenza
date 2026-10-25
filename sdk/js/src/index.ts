// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

/** Provenza SDK - governed, signed and auditable actions for AI agents. See README.md. */

export { Agent } from "./agent.js";
export type { AgentOptions, CallOptions, Check, SignedRequest, ToolSpec } from "./agent.js";
export { verify as verifyAuditLog } from "./auditLog.js";
export { canonical } from "./canonical.js";
export { PROXY_HEADER, PROXY_REQUEST_HEADER, proxyDescriptor, proxyHeaders } from "./proxy.js";
export { PERMIT_HEADER, PermitError, PermitVerifier, permitHeaders, permitMiddleware, withPermit } from "./permit.js";
export type { Permit, PermitVerifierOptions } from "./permit.js";
export type { ProxyDescriptor } from "./proxy.js";
export { contentHash, fingerprint, Keys } from "./crypto.js";
export { ProvenzaApprovalRequired, ProvenzaConfigError, ProvenzaDenied, ProvenzaError, ProvenzaRequestError,
         ProvenzaUnavailable } from "./errors.js";

export const VERSION = "0.1.0";
