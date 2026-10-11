// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

/**
 * HTTP to a Provenza server (the global fetch, or one you pass in).
 *
 *   network error, timeout, HTTP 5xx  -> ProvenzaUnavailable (fail-closed: nothing ran)
 *   HTTP 4xx                          -> ProvenzaRequestError
 *
 * Redirects are not followed: the agent key is never re-sent elsewhere.
 */

import { ProvenzaRequestError, ProvenzaUnavailable } from "./errors.js";
import { trimEnd } from "./text.js";

export type Fetch = typeof fetch;
const API = "/api/v1";

export class Client {
  readonly serverUrl: string;

  constructor(serverUrl: string, readonly apiKey: string | null = null,
              private readonly timeoutMs = 10_000, private readonly fetchImpl: Fetch = fetch) {
    if (!/^https?:\/\//.test(serverUrl)) throw new TypeError("serverUrl must start with https:// (or http:// for a local server)");
    this.serverUrl = trimEnd(serverUrl, "/");
  }

  private headers(authenticated: boolean): Record<string, string> {
    const h: Record<string, string> = { "user-agent": "provenza-js", accept: "application/json" };
    if (authenticated) {
      if (!this.apiKey) throw new ProvenzaRequestError(401, "this agent has no API key");
      h["x-agent-key"] = this.apiKey;
    }
    return h;
  }

  async request(method: "GET" | "POST", path: string, body?: unknown, authenticated = true): Promise<any> {
    const headers = this.headers(authenticated);
    if (body !== undefined) headers["content-type"] = "application/json";
    let resp: Response;
    try {
      resp = await this.fetchImpl(this.serverUrl + API + path, {
        method, headers, body: body === undefined ? undefined : JSON.stringify(body),
        redirect: "manual", signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (exc) {
      throw new ProvenzaUnavailable(`${path}: ${(exc as Error).name}: ${(exc as Error).message}`);
    }
    const text = await resp.text();
    if (resp.status >= 500 || (resp.status >= 300 && resp.status < 400)) {
      throw new ProvenzaUnavailable(`${path}: HTTP ${resp.status}`);
    }
    let data: any = null;
    if (text) {
      try { data = JSON.parse(text); } catch { if (resp.ok) throw new ProvenzaUnavailable(`${path}: not JSON`); data = text; }
    }
    if (resp.status >= 400) throw new ProvenzaRequestError(resp.status, data?.detail ?? data, path);
    return data;
  }

  post(path: string, body: unknown, authenticated = true): Promise<any> {
    return this.request("POST", path, body, authenticated);
  }

  get(path: string): Promise<any> {
    return this.request("GET", path);
  }
}
