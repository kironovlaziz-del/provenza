// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

/**
 * The tool's side of signed permits: run only what Provenza allowed.
 *
 * An allowed check gives the agent a permit - a JWS signed by the
 * organization's permit key, for one tool, one input, a few minutes. The agent
 * sends it with the call; the tool verifies it here and refuses without it:
 *
 *   const verifier = new PermitVerifier("https://provenza.example.com", "acme");
 *   app.post("/update", express.json(), permitMiddleware(verifier, { tool: "crm.update" }), handler);
 *   // or any fetch-style server (Next.js route, Hono, Bun, Deno):
 *   export const POST = withPermit(verifier, "crm.update", async (request, permit) => Response.json({ ok: true }));
 *
 * The agent side:
 *
 *   const chk = await agent.check("crm.update", payload);
 *   await fetch(url, { method: "POST", body: JSON.stringify(payload), headers: permitHeaders(chk) });
 *
 * Checked: the signature against the organization's JWKS (refetched when an
 * unknown key id appears, after a rotation), the issuer, the tool (aud), the
 * SHA-256 of the canonical input (the JSON body must be the input the agent
 * checked), the expiry. Then the permit is redeemed with Provenza: used once
 * across every replica of the tool. With redeem: false only this process
 * remembers what it has seen. What cannot be verified is refused.
 */

import { createPublicKey, verify as edVerify, type KeyObject } from "node:crypto";

import { contentHash } from "./crypto.js";
import { ProvenzaError } from "./errors.js";
import { trimEnd } from "./text.js";

export const PERMIT_HEADER = "Provenza-Permit";
const TYP = "provenza-permit+jwt";
const MAX_TOKEN_BYTES = 4096;
const MAX_BODY = 8 * 1024 * 1024;

/** code: permit.missing | permit.invalid | permit.mismatch | permit.expired | permit.redeemed | permit.unverifiable */
export class PermitError extends ProvenzaError {
  override name = "PermitError";
  constructor(readonly code: string, message = "") {
    super(message ? `${code}: ${message}` : code);
  }
}

export interface Permit {
  permitId: string;
  agentId: number;
  tool: string;
  actionType: string | null;
  chainId: number | null;
  inputSha256: string;
  expiresAt: number;
  issuer: string;
  redeemed: boolean;
}

export interface PermitVerifierOptions {
  /** Redeem with Provenza (once, server-wide). Default true. */
  redeem?: boolean;
  jwksTtlMs?: number;
  leewaySeconds?: number;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

/** The header that carries the permit of an allowed check, or {} for a refused one. */
export function permitHeaders(check: { permit?: string | null }): Record<string, string> {
  return check.permit ? { [PERMIT_HEADER]: check.permit } : {};
}

const unb64 = (s: string) => Buffer.from(s, "base64url");

function split(token: unknown) {
  if (typeof token !== "string" || !token) throw new PermitError("permit.missing", `no ${PERMIT_HEADER}`);
  const parts = token.split(".");
  if (token.length > MAX_TOKEN_BYTES || parts.length !== 3) throw new PermitError("permit.invalid", "not a permit");
  const [h, c, s] = parts as [string, string, string];
  let header: any, claims: any;
  try {
    header = JSON.parse(unb64(h).toString("utf8"));
    claims = JSON.parse(unb64(c).toString("utf8"));
  } catch {
    throw new PermitError("permit.invalid", "not a permit");
  }
  if (!header || typeof header !== "object" || !claims || typeof claims !== "object" || header.alg !== "EdDSA"
      || header.typ !== TYP || typeof header.kid !== "string") {
    throw new PermitError("permit.invalid", "not a Provenza permit");
  }
  return { header, claims, signature: unb64(s), signingInput: Buffer.from(`${h}.${c}`, "ascii") };
}

/** Verifies permits of one organization. Share one per process. */
export class PermitVerifier {
  readonly issuer: string;
  readonly jwksUrl: string;
  readonly redeemUrl: string;
  private keys = new Map<string, KeyObject>();
  private fetchedAt = 0;
  private seen = new Map<string, number>();
  private readonly redeem: boolean;
  private readonly ttl: number;
  private readonly leeway: number;
  private readonly timeout: number;
  private readonly fetchFn: typeof fetch;

  constructor(serverUrl: string, readonly org: string, opts: PermitVerifierOptions = {}) {
    let base = trimEnd(serverUrl, "/");
    if (!base.endsWith("/api/v1")) base += "/api/v1";
    this.issuer = `provenza:org:${org}`;
    this.jwksUrl = `${base}/pvp/permits/${encodeURIComponent(org)}/jwks.json`;
    this.redeemUrl = `${base}/pvp/permits/redeem`;
    this.redeem = opts.redeem ?? true;
    this.ttl = opts.jwksTtlMs ?? 300_000;
    this.leeway = opts.leewaySeconds ?? 30;
    this.timeout = opts.timeoutMs ?? 5_000;
    this.fetchFn = opts.fetch ?? globalThis.fetch;
  }

  private async http(url: string, init: RequestInit = {}): Promise<Response> {
    try {
      return await this.fetchFn(url, { ...init, signal: AbortSignal.timeout(this.timeout) });
    } catch (err) {
      throw new PermitError("permit.unverifiable", `could not reach Provenza: ${(err as Error).message}`);
    }
  }

  private async loadKeys(): Promise<void> {
    const r = await this.http(this.jwksUrl);
    if (!r.ok) throw new PermitError("permit.unverifiable", `could not fetch the JWKS: HTTP ${r.status}`);
    const doc: any = await r.json().catch(() => null);
    const keys = new Map<string, KeyObject>();
    for (const k of Array.isArray(doc?.keys) ? doc.keys : []) {
      if (k?.kty !== "OKP" || k?.crv !== "Ed25519" || typeof k?.kid !== "string" || typeof k?.x !== "string") continue;
      try {
        keys.set(k.kid, createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: k.x }, format: "jwk" }));
      } catch {
        /* an unusable key is skipped */
      }
    }
    this.keys = keys;
    this.fetchedAt = Date.now();
  }

  /** The permit, if it allows exactly this call; else PermitError. Give the
   *  input as received (its canonical hash is compared) or its hash. */
  async verify(token: string | null | undefined,
               opts: { tool: string; input?: unknown; inputSha256?: string }): Promise<Permit> {
    const { header, claims, signature, signingInput } = split(token);
    if (!this.keys.has(header.kid) || Date.now() - this.fetchedAt > this.ttl) await this.loadKeys();
    const key = this.keys.get(header.kid);
    if (!key) throw new PermitError("permit.invalid", "signed by a key this organization does not publish");
    if (!edVerify(null, signingInput, key, signature)) throw new PermitError("permit.invalid", "bad signature");
    const now = Date.now() / 1000;
    if (claims.iss !== this.issuer) throw new PermitError("permit.invalid", "issued for another organization");
    if (!Number.isInteger(claims.exp) || !Number.isInteger(claims.nbf) || now < claims.nbf - this.leeway) {
      throw new PermitError("permit.invalid", "bad validity");
    }
    if (now > claims.exp + this.leeway) throw new PermitError("permit.expired");
    if (claims.aud !== opts.tool) throw new PermitError("permit.mismatch", `issued for ${claims.aud}, not ${opts.tool}`);
    const inputSha256 = opts.inputSha256 ?? contentHash(opts.input ?? {});
    if (claims.ish !== inputSha256) throw new PermitError("permit.mismatch", "issued for another input");
    const sub = String(claims.sub ?? "");
    if (!/^agent:\d+$/.test(sub) || typeof claims.jti !== "string") throw new PermitError("permit.invalid", "bad subject");
    const permit: Permit = {
      permitId: claims.jti, agentId: Number(sub.slice(6)), tool: opts.tool, actionType: claims.act ?? null,
      chainId: claims.chain ?? null, inputSha256, expiresAt: claims.exp, issuer: this.issuer, redeemed: false,
    };
    if (!this.redeem) {
      this.once(permit);
      return permit;
    }
    const r = await this.http(this.redeemUrl, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ permit: token, tool: opts.tool, input_sha256: inputSha256 }),
    });
    if (r.ok) return { ...permit, redeemed: true };
    const body: any = await r.json().catch(() => null);
    const code = typeof body?.detail === "string" ? body.detail : body?.detail?.code;
    if (r.status >= 500 || typeof code !== "string" || !code.startsWith("permit.")) {
      throw new PermitError("permit.unverifiable", `redeem failed: HTTP ${r.status}`);
    }
    throw new PermitError(code);
  }

  private once(permit: Permit): void {
    const now = Date.now() / 1000;
    for (const [jti, exp] of this.seen) if (exp + this.leeway < now) this.seen.delete(jti);
    if (this.seen.has(permit.permitId)) throw new PermitError("permit.redeemed", "already used here");
    this.seen.set(permit.permitId, permit.expiresAt);
  }
}

const statusOf = (err: PermitError) => (err.code === "permit.unverifiable" ? 503 : 403);

async function readJson(req: any): Promise<unknown> {
  if (req.body !== undefined && !(req.body instanceof Uint8Array) && typeof req.body !== "string") return req.body;
  let raw: Buffer;
  if (req.body instanceof Uint8Array || typeof req.body === "string") {
    raw = Buffer.from(req.body);
  } else {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > MAX_BODY) throw new PermitError("permit.body_too_large");
      chunks.push(Buffer.from(chunk));
    }
    raw = Buffer.concat(chunks);
  }
  const text = raw.toString("utf8");
  try {
    const data = text.trim() ? JSON.parse(text) : {};
    req.body = data;
    return data;
  } catch {
    throw new PermitError("permit.body_not_json");
  }
}

/**
 * Express / Connect middleware: the request runs only with a valid permit for
 * `tool` and its JSON body as the input (after express.json(), or it reads the
 * body itself and sets req.body). `tool` may be a function of the request
 * (undefined = not governed, passed through). The Permit is in req.permit.
 */
export function permitMiddleware(verifier: PermitVerifier, opts: { tool: string | ((req: any) => string | undefined) }) {
  return async (req: any, res: any, next: (err?: unknown) => void) => {
    const tool = typeof opts.tool === "function" ? opts.tool(req) : opts.tool;
    if (tool === undefined) return next();
    try {
      const input = await readJson(req);
      const headers = req.headers ?? {};
      const token = headers[PERMIT_HEADER.toLowerCase()];
      req.permit = await verifier.verify(Array.isArray(token) ? token[0] : token, { tool, input });
    } catch (err) {
      if (!(err instanceof PermitError)) return next(err);
      res.statusCode = err.code === "permit.body_too_large" ? 413 : err.code === "permit.body_not_json" ? 400 : statusOf(err);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ error: err.code }));
      return;
    }
    next();
  };
}

/** For fetch-style handlers (Request -> Response): runs `handler` only with a valid permit. */
export function withPermit(verifier: PermitVerifier, tool: string,
                           handler: (request: Request, permit: Permit, input: unknown) => Response | Promise<Response>) {
  return async (request: Request): Promise<Response> => {
    let input: unknown;
    try {
      const text = await request.text();
      if (text.length > MAX_BODY) throw new PermitError("permit.body_too_large");
      try {
        input = text.trim() ? JSON.parse(text) : {};
      } catch {
        throw new PermitError("permit.body_not_json");
      }
      const permit = await verifier.verify(request.headers.get(PERMIT_HEADER), { tool, input });
      return await handler(request, permit, input);
    } catch (err) {
      if (!(err instanceof PermitError)) throw err;
      const status = err.code === "permit.body_too_large" ? 413 : err.code === "permit.body_not_json" ? 400 : statusOf(err);
      return Response.json({ error: err.code }, { status });
    }
  };
}
