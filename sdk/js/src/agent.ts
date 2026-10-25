// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

/**
 * Agent - the SDK's entry point (the same behaviour as the Python SDK).
 *
 *   const agent = await Agent.create({ name: "billing-bot" });   // PROVENZA_URL / PROVENZA_TOKEN
 *   const read = agent.tool("db.read", async ({ query }: { query: string }) => db.query(query));
 *   await read({ query: "select 1" });
 *
 * connected   check on the server -> the tool runs only if allowed -> the result
 *             is recorded, signed with the agent's key under the single-use
 *             check_id. Denied / pending calls throw and are recorded. Server
 *             unreachable: the tool does NOT run (fail-closed) unless failOpen.
 * standalone  no server: calls run (within allowedTools) and go to the local
 *             signed audit log.
 *
 * Said plainly: the SDK runs inside the agent's process - the agent's honest
 * record and cooperative enforcement. Enforcement independent of the agent's
 * code is Provenza's gateways (LLM, MCP, A2A).
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";

import { AuditLog } from "./auditLog.js";
import { Json, toJson } from "./canonical.js";
import { Client, Fetch } from "./client.js";
import { contentHash, Keys } from "./crypto.js";
import { createHash } from "node:crypto";
import { beacon as egressBeacon, connect as egressConnect, egressPayload } from "./egressCheck.js";
import { ProvenzaApprovalRequired, ProvenzaConfigError, ProvenzaDenied, ProvenzaRequestError, ProvenzaUnavailable } from "./errors.js";
import * as ids from "./identity.js";
import { PROXY_ACTION_TYPE, PROXY_REQUEST_HEADER, proxyDescriptor, proxyHeaders, RawBytes } from "./proxy.js";
import { trimEnd } from "./text.js";

export interface ToolSpec {
  name: string;
  actionType?: string;
  version?: string;
  digest?: string;
}

export interface Check {
  checkId: string;
  decision: "allowed" | "denied" | "pending_approval";
  reason: string;
  tool: string;
  actionType: string;
  input: Json;
  chainId: number | null;
  incidentType: string | null;
  policyId: number | null;
  /** Allowed: the signed permit the tool verifies (permitHeaders(check), see permit.ts). */
  permit: string | null;
  /** The agent's signed action.request behind this check, with its public key(s):
   *  an egress proxy that enforces the signed policy verifies it itself (proxyHeaders). */
  request?: SignedRequest | null;
}

export interface SignedRequest {
  payload: Record<string, Json>;
  signature: string;
  public_key: string;
  pq_signature?: string;
  pq_public_key?: string;
}

export interface AgentOptions {
  name?: string;
  serverUrl?: string;
  enrollmentToken?: string;
  identityPath?: string;
  mode?: "connected" | "standalone";
  hybrid?: boolean;
  allowedTools?: string[];           // standalone only
  auditLog?: string;
  failOpen?: boolean;
  recordMode?: "sync" | "background";
  timeoutMs?: number;
  fetch?: Fetch;
  /** an egress proxy (http://host:8443): HTTP tools are called there - it holds their credentials */
  egressProxy?: string;
}

export interface CallOptions {
  actionType?: string;
  outputOf?: (result: any) => unknown;
}

export const RECORD_RETRIES_MS = [200, 1000];
const chainStore = new AsyncLocalStorage<number | null>();
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function asOutput(result: unknown): Json {
  if (result === undefined || result === null) return null;
  let v: Json;
  try {
    v = toJson(result, "output");
  } catch {
    return { repr: String(result).slice(0, 2000) };
  }
  return v !== null && typeof v === "object" && !Array.isArray(v) ? v : { result: v };
}

function asInput(args: unknown): Json {
  const v = toJson(args ?? {}, "tool arguments");
  if (v === null || typeof v !== "object" || Array.isArray(v)) {
    throw new TypeError("tool arguments must be a plain object (they are what policies inspect)");
  }
  return v;
}

export class Agent {
  readonly name: string;
  readonly mode: "connected" | "standalone";
  readonly failOpen: boolean;
  readonly recordMode: "sync" | "background";
  readonly allowedTools: ReadonlySet<string> | null;
  readonly identityPath: string;
  readonly auditLog: AuditLog;
  private readonly pending = new Set<Promise<unknown>>();
  private toolsClient: Client | null = null;

  private constructor(readonly identity: ids.Identity, private readonly client: Client | null, opts: Required<Pick<AgentOptions,
    "failOpen" | "recordMode">> & { name: string; mode: "connected" | "standalone"; identityPath: string;
    allowedTools: string[] | null; auditLog: string }) {
    this.name = opts.name;
    this.mode = opts.mode;
    this.failOpen = opts.failOpen;
    this.recordMode = opts.recordMode;
    this.identityPath = opts.identityPath;
    this.allowedTools = opts.allowedTools ? new Set(opts.allowedTools) : null;
    this.auditLog = new AuditLog(opts.auditLog, identity.keys, opts.name);
  }

  /** Load (or create, or enroll) the agent's identity. */
  static async create(options: AgentOptions = {}): Promise<Agent> {
    const env = process.env;
    const name = options.name || env.PROVENZA_AGENT_NAME || "agent";
    let serverUrl = options.serverUrl || env.PROVENZA_URL || "";
    const token = options.enrollmentToken || env.PROVENZA_TOKEN;
    const mode = options.mode || (env.PROVENZA_MODE as AgentOptions["mode"]) || (serverUrl ? "connected" : "standalone");
    if (mode !== "connected" && mode !== "standalone") throw new ProvenzaConfigError("mode must be 'connected' or 'standalone'");
    const recordMode = options.recordMode ?? "sync";
    if (recordMode !== "sync" && recordMode !== "background") {
      throw new ProvenzaConfigError("recordMode must be 'sync' or 'background'");
    }
    const identityPath = options.identityPath || env.PROVENZA_IDENTITY || ids.defaultPath(name);
    const auditLog = options.auditLog || identityPath.replace(/\.json$/, "") + ".audit.jsonl";
    const timeoutMs = options.timeoutMs ?? 10_000;
    const fetchImpl = options.fetch ?? fetch;
    let identity = ids.load(identityPath);
    let client: Client | null = null;

    if (mode === "standalone") {
      if (!identity) {
        identity = { keys: Keys.generate(Boolean(options.hybrid)), server: null, agentId: null, apiKey: null, name };
        ids.save(identity, identityPath);
      }
    } else {
      serverUrl = trimEnd(serverUrl || identity?.server || "", "/");
      if (!serverUrl) throw new ProvenzaConfigError("connected mode needs serverUrl (or PROVENZA_URL)");
      if (identity?.server && trimEnd(identity.server, "/") !== serverUrl) {
        // never present this agent's key to a server it was not enrolled with
        throw new ProvenzaConfigError(`${identityPath} belongs to ${identity.server}, not ${serverUrl}`);
      }
      if (!identity || identity.agentId === null) {
        if (!token) {
          throw new ProvenzaConfigError("this agent is not enrolled: pass enrollmentToken (or PROVENZA_TOKEN), " +
                                        "issued in Provenza under Agents -> New agent");
        }
        identity = await ids.enroll(new Client(serverUrl, null, timeoutMs, fetchImpl), token, name, Boolean(options.hybrid));
        ids.save(identity, identityPath);
      }
      client = new Client(serverUrl, identity.apiKey, timeoutMs, fetchImpl);
    }
    const agent = new Agent(identity, client, { name, mode, identityPath, auditLog, failOpen: Boolean(options.failOpen),
                                                recordMode, allowedTools: options.allowedTools ?? null });
    const proxyUrl = options.egressProxy || env.PROVENZA_EGRESS_PROXY;
    if (proxyUrl && client) agent.toolsClient = new Client(proxyUrl, identity.apiKey, Math.max(timeoutMs, 60_000), fetchImpl, "");
    return agent;
  }

  get agentId(): number | null {
    return this.identity.agentId;
  }

  /** Give this to whoever verifies the agent's signatures. */
  get fingerprint(): string {
    return this.identity.keys.fingerprint;
  }

  get serverUrl(): string | null {
    return this.client?.serverUrl ?? null;
  }

  /** Server URL and agent key, for clients that talk to Provenza's gateways themselves. */
  credentials(): { serverUrl: string; apiKey: string } {
    const c = this.connected();
    if (!c.apiKey) throw new ProvenzaConfigError("this agent has no API key");
    return { serverUrl: c.serverUrl, apiKey: c.apiKey };
  }

  /** The AI provider domains provenza/auto intercepts (GET /pvp/egress-catalog). */
  egressCatalog(): Promise<{ domains?: { domain: string; status?: string }[] }> {
    return this.connected().get("/pvp/egress-catalog");
  }

  /** Run fn with every governed call inside it acting in this delegation chain. */
  withChain<T>(chainId: number | null, fn: () => T): T {
    return chainStore.run(chainId, fn);
  }

  private connected(): Client {
    if (!this.client) throw new ProvenzaConfigError("this needs connected mode");
    return this.client;
  }

  // ------------------------------------------------------------------ protocol

  private checkBody(spec: ToolSpec, input: Json, chainId: number | null) {
    return this.signedCheck(spec, input, chainId).body;
  }

  /** The check body, and the signed request as an egress proxy verifies it. */
  private signedCheck(spec: ToolSpec, input: Json, chainId: number | null) {
    const actionType = spec.actionType ?? "tool_call";
    // signed, with a single-use nonce and the time: the server refuses a check
    // the agent did not sign, so a stolen API key alone gets nothing
    const nonce = randomBytes(16).toString("hex");
    const issuedAt = Math.floor(Date.now() / 1000);
    const payload: Record<string, Json> = {
      type: "action.request", agent_id: this.agentId, chain_id: chainId, action_type: actionType,
      tool_name: spec.name, input_sha256: contentHash(input), tool_version: spec.version ?? null,
      tool_digest: spec.digest ?? null, nonce, issued_at: issuedAt,
    };
    const keys = this.identity.keys;
    const [signature, pqSignature] = keys.sign(payload);
    const body = {
      agent_id: this.agentId, chain_id: chainId, action_type: actionType, tool_name: spec.name, input,
      ...(spec.version ? { tool_version: spec.version } : {}), ...(spec.digest ? { tool_digest: spec.digest } : {}),
      nonce, issued_at: issuedAt, signature, ...(pqSignature ? { pq_signature: pqSignature } : {}),
    };
    const request: SignedRequest = { payload, signature, public_key: keys.publicKey,
      ...(pqSignature ? { pq_signature: pqSignature, pq_public_key: keys.pqPublicKey ?? undefined } : {}) };
    return { body, request };
  }

  private static checkOf(res: any, spec: ToolSpec, input: Json, chainId: number | null,
                         request: SignedRequest | null = null): Check {
    return { checkId: res.check_id, decision: res.decision, reason: res.reason ?? "", tool: spec.name,
             actionType: spec.actionType ?? "tool_call", input, chainId, incidentType: res.incident_type ?? null,
             policyId: res.policy_id ?? null, permit: res.permit ?? null, request };
  }

  /** Ask before doing something that is not a governed tool. */
  async check(tool: string, input: Record<string, unknown>, opts: { actionType?: string; chainId?: number | null } = {}) {
    const spec = { name: tool, actionType: opts.actionType };
    const inp = asInput(input);
    const chainId = opts.chainId !== undefined ? opts.chainId : chainStore.getStore() ?? null;
    const { body, request } = this.signedCheck(spec, inp, chainId);
    return Agent.checkOf(await this.connected().post("/agents/actions/check", body), spec, inp, chainId, request);
  }

  /** Check a request to send through the egress proxy (SDK mode). Send it with
   *  proxyHeaders(check); the proxy records it - do not record() it. */
  async proxyCheck(route: string, method: string, path: string,
                   opts: { query?: RawBytes; body?: RawBytes; chainId?: number | null } = {}): Promise<Check> {
    const input = proxyDescriptor(route, method, path, opts) as unknown as Record<string, unknown>;
    return this.check("proxy." + route, input, { actionType: PROXY_ACTION_TYPE, chainId: opts.chainId });
  }

  /** The headers for a request through the egress proxy: a check when
   *  Provenza answers (proxyCheck); while it is unreachable, only the agent's
   *  signed request - a proxy that enforces the signed policy then judges it by
   *  the signed release alone, for at most the release's offline time, and
   *  Provenza records it when it is back (docs/pvp/edge.md, section 6). */
  async proxyRequestHeaders(route: string, method: string, path: string,
                            opts: { query?: RawBytes; body?: RawBytes; chainId?: number | null } = {}):
    Promise<Record<string, string>> {
    try {
      return proxyHeaders(await this.proxyCheck(route, method, path, opts));
    } catch (exc) {
      if (!(exc instanceof ProvenzaUnavailable)) throw exc;
      const input = proxyDescriptor(route, method, path, opts) as unknown as Json;
      const chainId = opts.chainId !== undefined ? opts.chainId : chainStore.getStore() ?? null;
      const { request } = this.signedCheck({ name: "proxy." + route, actionType: PROXY_ACTION_TYPE }, input, chainId);
      return { [PROXY_REQUEST_HEADER]: Buffer.from(JSON.stringify(request), "utf8").toString("base64url") };
    }
  }

  /**
   * Call an HTTP tool registered in Provenza: checked, called and recorded in
   * one operation - by the egress proxy, which holds the tool's credential
   * (egressProxy / PROVENZA_EGRESS_PROXY), or by Provenza's gateway for a tool
   * that takes none. Allowed:
   * { decision, reason, action_id, status, body } ("error" / "withheld" instead
   * of "body" when the API failed or the answer was refused). A refusal throws
   * ProvenzaDenied (ProvenzaApprovalRequired when it waits for a human).
   */
  async invoke(tool: string, args: Record<string, unknown>, opts: { chainId?: number | null } = {}): Promise<any> {
    const spec = { name: tool };
    const inp = asInput(args);
    const chainId = opts.chainId !== undefined ? opts.chainId : chainStore.getStore() ?? null;
    const res = this.toolsClient
      ? await this.toolsClient.post("/_tools/call", this.checkBody(spec, inp, chainId), true, (raw) => {
        // the HTTP request itself, signed: a proxy in enforce mode requires it on every path
        const desc = proxyDescriptor("_tools", "POST", "/call", { body: raw }) as unknown as Json;
        const { request } = this.signedCheck({ name: "proxy._tools", actionType: PROXY_ACTION_TYPE }, desc, chainId);
        return { [PROXY_REQUEST_HEADER]: Buffer.from(JSON.stringify(request), "utf8").toString("base64url") };
      })
      : await this.connected().post("/http-tools/call", this.checkBody(spec, inp, chainId));
    if (res.decision !== "allowed") {
      const Cls = res.decision === "pending_approval" ? ProvenzaApprovalRequired : ProvenzaDenied;
      throw new Cls(tool, res.reason ?? "", res.decision ?? "denied", res.incident_type ?? null, null, res.action_id ?? null);
    }
    return res;
  }

  /**
   * Prove where this agent runs: `evidence` is the workload's token (a
   * Kubernetes projected ServiceAccount token, or an OIDC token from GitHub
   * Actions, Google Cloud, Azure, ...). Returns the server's record:
   * { ok, reason, identity, valid_until, ... }.
   */
  async attest(evidence: string): Promise<any> {
    const c = this.connected();
    const ch = await c.post(`/agents/${this.agentId}/attestation/challenge`, {});
    const token = evidence.trim();
    const [signature, pqSignature] = this.identity.keys.sign({
      type: "provenza.agent.attestation", v: 1, challenge: ch.challenge, agent_id: this.agentId, kind: ch.kind,
      evidence_sha256: createHash("sha256").update(token, "utf8").digest("hex"),
    });
    return c.post(`/agents/${this.agentId}/attestation`, {
      challenge: ch.challenge, kind: ch.kind, evidence: token, signature, ...(pqSignature ? { pq_signature: pqSignature } : {}),
    });
  }

  /**
   * Is this host confined to the egress proxy? Tries the server's targets and
   * beacon directly and reports, signed. Returns the server's verdict:
   * { verdict: "confined" | "open", ... }. Run at start-up and periodically.
   */
  async egressSelfcheck(opts: { timeoutMs?: number; beaconFetch?: typeof fetch } = {}): Promise<any> {
    const timeout = opts.timeoutMs ?? 3000;
    const c = this.connected();
    const started = await c.post("/agents/egress-check", {});
    const reached = await Promise.all((started.targets as string[]).map((t) => egressConnect(t, timeout)));
    const results = (started.targets as string[]).map((target, i) => ({ target, reachable: reached[i] ?? false }));
    const beaconReached = await egressBeacon(started.beacon_url, timeout, opts.beaconFetch);
    const [signature, pqSignature] = this.identity.keys.sign(egressPayload(this.agentId ?? 0, started.check_id, results,
                                                                           beaconReached));
    return c.post(`/agents/egress-check/${started.check_id}/report`, {
      results, beacon_reached: beaconReached, signature, ...(pqSignature ? { pq_signature: pqSignature } : {}),
    });
  }

  /** Where a held call stands: { action_id, decision (pending_approval, approved, denied, expired),
   *  decided_at, used, redeemable_until }. */
  async approval(actionId: number): Promise<any> {
    if (!Number.isSafeInteger(actionId) || actionId < 1) throw new RangeError("actionId must be a positive integer");
    return this.connected().get(`/agents/actions/${actionId}/decision`);
  }

  /**
   * Wait until a person decides on a held call (ProvenzaApprovalRequired.actionId) or the
   * timeout passes, and return the last state. When it is "approved", make exactly the
   * same call again - same arguments, same chain - before redeemable_until: it runs once.
   * Nothing is replayed for you.
   */
  async waitForApproval(actionId: number, opts: { timeoutMs?: number; intervalMs?: number } = {}): Promise<any> {
    const deadline = Date.now() + (opts.timeoutMs ?? 600_000);
    for (;;) {
      const state = await this.approval(actionId);
      if (state.decision !== "pending_approval" || Date.now() >= deadline) return state;
      const wait = Math.max(500, Math.min(opts.intervalMs ?? 5_000, deadline - Date.now()));
      await new Promise((r) => setTimeout(r, wait));
    }
  }

  /** The HTTP tools this agent may invoke: name, description, method, input_schema. */
  async httpTools(): Promise<Array<{ name: string; description: string; method: string; input_schema: unknown }>> {
    return (await this.connected().get("/http-tools/available")).tools;
  }

  /** Record what was done under a check (once); retries a server that is down. */
  async record(check: Check, output: unknown = null, durationMs: number | null = null): Promise<any> {
    const out = asOutput(output);
    const payload = {
      check_id: check.checkId, agent_id: this.agentId, chain_id: check.chainId, action_type: check.actionType,
      tool_name: check.tool, input_sha256: contentHash(check.input), output_sha256: contentHash(out),
    };
    const [signature, pqSignature] = this.identity.keys.sign(payload);
    const body = { agent_id: this.agentId, chain_id: check.chainId, action_type: check.actionType, tool_name: check.tool,
                   input: check.input, output: out, duration_ms: durationMs, check_id: check.checkId, signature,
                   pq_signature: pqSignature };
    const pauses = [0, ...RECORD_RETRIES_MS];
    for (let attempt = 0; attempt < pauses.length; attempt++) {
      if (pauses[attempt]) await sleep(pauses[attempt] as number);
      try {
        return await this.connected().post("/agents/actions/record", body);
      } catch (exc) {
        if (exc instanceof ProvenzaUnavailable && attempt < pauses.length - 1) continue;
        if (exc instanceof ProvenzaRequestError && exc.status === 409 && attempt > 0) {
          return { id: null, check_id: check.checkId, note: "recorded by an earlier attempt" };
        }
        throw exc;
      }
    }
  }

  /** Hand a task and a subset of this agent's rights to another agent (signed, single-use nonce). */
  async delegate(toAgentId: number, task: string, capabilities: string[] = [],
                 opts: { tools?: string[]; expiresIn?: number; chainId?: number | null } = {}): Promise<any> {
    const chainId = opts.chainId !== undefined ? opts.chainId : chainStore.getStore() ?? null;
    const payload: Record<string, unknown> = {
      from_agent_id: this.agentId, to_agent_id: toAgentId, task, delegated_capabilities: [...capabilities].sort(),
      chain_id: chainId, nonce: randomBytes(16).toString("hex"), issued_at: Math.floor(Date.now() / 1000),
      expires_in: opts.expiresIn ?? null,
    };
    if (opts.tools !== undefined) payload.delegated_tools = [...new Set(opts.tools)].sort();
    const [signature, pqSignature] = this.identity.keys.sign(payload);
    return this.connected().post(`/agents/${this.agentId}/delegate`, {
      to_agent_id: toAgentId, task, delegated_capabilities: capabilities, delegated_tools: opts.tools ?? null,
      chain_id: chainId, nonce: payload.nonce, issued_at: payload.issued_at, expires_in: payload.expires_in,
      signature, pq_signature: pqSignature,
    });
  }

  // ------------------------------------------------------------------ tools

  /** A governed version of fn. Tools take one arguments object - that is what policies inspect. */
  tool<A extends Record<string, unknown>, R>(spec: string | ToolSpec, fn: (args: A) => R | Promise<R>): (args: A) => Promise<R> {
    const s: ToolSpec = typeof spec === "string" ? { name: spec } : spec;
    // async: a bad argument rejects the promise, it never throws synchronously
    const governed = async (args: A) => this.governed(s, asInput(args), () => fn(args));
    Object.defineProperty(governed, "name", { value: fn.name || s.name });
    (governed as any).provenzaTool = s;
    return governed;
  }

  /** Govern one call whose arguments you already have - what integrations use. */
  async call<R>(tool: string, args: Record<string, unknown>, fn: () => R | Promise<R>, opts: CallOptions = {}): Promise<R> {
    return this.governed({ name: tool, actionType: opts.actionType }, asInput(args), fn, opts.outputOf);
  }

  private async governed<R>(spec: ToolSpec, input: Json, fn: () => R | Promise<R>,
                            outputOf?: (r: any) => unknown): Promise<R> {
    const out = (r: unknown) => asOutput(outputOf ? outputOf(r) : r);
    const chainId = chainStore.getStore() ?? null;
    if (this.mode === "standalone") {
      if (this.allowedTools && !this.allowedTools.has(spec.name)) {
        const reason = "not in this agent's allowedTools (standalone)";
        this.auditLog.append({ status: "denied", tool: spec.name, action_type: spec.actionType ?? "tool_call",
                               input_sha256: contentHash(input), reason });
        throw new ProvenzaDenied(spec.name, reason);
      }
      return this.local(spec, input, fn, "recorded", out);
    }
    let res: any;
    try {
      res = await this.connected().post("/agents/actions/check", this.checkBody(spec, input, chainId));
    } catch (exc) {
      if (!(exc instanceof ProvenzaUnavailable) || !this.failOpen) throw exc;
      process.emitWarning(`${spec.name}: Provenza unreachable, running unchecked (failOpen)`, { code: "PROVENZA_UNCHECKED" });
      return this.local(spec, input, fn, "unchecked", out);
    }
    const chk = Agent.checkOf(res, spec, input, chainId);
    if (chk.decision !== "allowed") {
      const action = await this.tryRecord(chk, null, null);
      const Cls = chk.decision === "pending_approval" ? ProvenzaApprovalRequired : ProvenzaDenied;
      throw new Cls(spec.name, chk.reason, chk.decision, chk.incidentType, chk.checkId, action?.id ?? null);
    }
    const started = performance.now();
    let result: R;
    try {
      result = await fn();
    } catch (exc) {
      await this.recordAfter(chk, { error: (exc as Error)?.name ?? "Error" }, Math.round(performance.now() - started));
      throw exc;
    }
    await this.recordAfter(chk, out(result), Math.round(performance.now() - started));
    return result;
  }

  private async local<R>(spec: ToolSpec, input: Json, fn: () => R | Promise<R>, status: string,
                         out: (r: unknown) => Json): Promise<R> {
    const started = performance.now();
    const result = await fn();
    this.auditLog.append({ status, tool: spec.name, action_type: spec.actionType ?? "tool_call",
                           input_sha256: contentHash(input), output_sha256: contentHash(out(result)),
                           duration_ms: Math.round(performance.now() - started), reason: "" });
    return result;
  }

  private async recordAfter(chk: Check, output: Json, durationMs: number): Promise<void> {
    if (this.recordMode === "background") {
      const p = this.tryRecord(chk, output, durationMs).finally(() => this.pending.delete(p));
      this.pending.add(p);
    } else {
      await this.tryRecord(chk, output, durationMs);
    }
  }

  private async tryRecord(chk: Check, output: Json, durationMs: number | null): Promise<any> {
    try {
      return await this.record(chk, output, durationMs);
    } catch (exc) {
      if (!(exc instanceof ProvenzaUnavailable || exc instanceof ProvenzaRequestError)) throw exc;
      this.auditLog.append({ status: "unrecorded", tool: chk.tool, action_type: chk.actionType, check_id: chk.checkId,
                             input_sha256: contentHash(chk.input), output_sha256: contentHash(output),
                             duration_ms: durationMs ?? 0, reason: `${exc.name}: ${exc.message.slice(0, 200)}` });
      process.emitWarning(`${chk.tool} ran but could not be recorded on the server (${exc.message}); the gap is in ` +
                          this.auditLog.path, { code: "PROVENZA_UNRECORDED" });
      return null;
    }
  }

  /** Wait for background records. */
  async flush(): Promise<void> {
    await Promise.allSettled([...this.pending]);
  }

  async close(): Promise<void> {
    await this.flush();
  }
}
