// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

/** Every SDK error derives from ProvenzaError. */
export class ProvenzaError extends Error {
  override name = "ProvenzaError";
}

/** The agent is not set up (no server, no identity, no enrollment token, ...). */
export class ProvenzaConfigError extends ProvenzaError {
  override name = "ProvenzaConfigError";
}

/**
 * The server could not be reached or failed (network error, timeout, 5xx).
 * In connected mode the tool did NOT run - the SDK fails closed unless the
 * agent was created with failOpen: true.
 */
export class ProvenzaUnavailable extends ProvenzaError {
  override name = "ProvenzaUnavailable";
}

/** The server refused the request itself (4xx). */
export class ProvenzaRequestError extends ProvenzaError {
  override name = "ProvenzaRequestError";
  constructor(readonly status: number, readonly detail: unknown, readonly path = "") {
    super(`${path}: HTTP ${status}: ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
  }
}

/** Provenza's verdict refused the call; the tool did not run. The attempt is recorded. */
export class ProvenzaDenied extends ProvenzaError {
  override name = "ProvenzaDenied";
  constructor(
    readonly tool: string,
    readonly reason: string,
    readonly decision = "denied",
    readonly incidentType: string | null = null,
    readonly checkId: string | null = null,
    readonly actionId: number | null = null,
  ) {
    super(`${tool}: ${decision}: ${reason}`);
  }
}

/** The call needs a human approval first; it did not run. The pending action is recorded. */
export class ProvenzaApprovalRequired extends ProvenzaDenied {
  override name = "ProvenzaApprovalRequired";
}
