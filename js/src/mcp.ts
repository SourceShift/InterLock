/**
 * Intercept MCP tool calls in-process, block before effect.
 *
 * A port of `interlock/interceptors/mcp.py`. An agent that talks to MCP servers
 * makes every tool call through a client session: `session.callTool({name,
 * arguments})`. `guardMcpSession` wraps that one method so each outbound call is
 * turned into a `SensorEvent`, run through the policy engine, and blocked or
 * modified BEFORE it reaches the server.
 *
 * It is dependency-free on purpose: it duck-types on `.callTool` and never
 * imports the MCP SDK, so it wraps any client exposing that method. The real
 * `@modelcontextprotocol/sdk` `Client` drops in unchanged.
 *
 * `enforceToolCall` / `enforceToolResult` are the transport-agnostic core, the
 * twins of the Python pair. They are **async** here where Python's are sync,
 * because the engine that decides them lives in the daemon and is reached over a
 * promise - MCP's own `callTool` is already async, so the wrapper fits.
 *
 * **No receipt is emitted.** Python's interceptor calls `emit_receipt`, but here
 * the *daemon* already recorded the decision when it answered. A JS receipt
 * would double-record one decision into a chain this side cannot sign.
 */

import { BlockedError, Decision, Verdict } from "./enforce.js";
import type { SensorEvent } from "./event.js";
import { sensorEvent } from "./event.js";

export type Enforcement = "blocking" | "monitor";

/** The one method the interceptors need: decide an event, or reject. */
export interface Engine {
  evaluate(event: SensorEvent): Promise<Decision>;
}

export interface EnforceOptions {
  engine: Engine;
  enforcement?: Enforcement;
  /** Who is acting, if the caller knows. `null`/omitted leaves it unattributed. */
  principal?: string | null;
}

/** The shape `guardMcpSession` duck-types - the official SDK's params object. */
export interface ToolCallParams {
  name: string;
  arguments?: Record<string, unknown> | null;
  _meta?: unknown;
  [key: string]: unknown;
}

/**
 * The shape `guardMcpSession` duck-types. Deliberately loose: the wrapper is
 * signature-preserving (every extra argument is forwarded to the original), so
 * pinning the concrete parameter types here would force a cast on every real
 * client - `@modelcontextprotocol/sdk`'s `Client` included - for no gain.
 */
export interface McpSession {
  callTool(...args: any[]): any;
}

/** A plain object, in the sense Python's `isinstance(x, dict)` means. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Decide on one tool call and enforce the verdict before it runs.
 *
 * Resolves with the arguments to actually use: unchanged on ALLOW, rewritten on
 * MODIFY (`modified_args` merged in). Rejects with `BlockedError` on BLOCK under
 * the default `enforcement: "blocking"`. Under `enforcement: "monitor"` it
 * records the would-be decision and never intervenes.
 */
export async function enforceToolCall(
  action: string,
  args: Record<string, unknown> | null | undefined,
  options: EnforceOptions,
): Promise<Record<string, unknown>> {
  // A shallow copy, so the caller's object is never mutated by a rewrite.
  const safe: Record<string, unknown> = { ...(args ?? {}) };
  const event = sensorEvent({
    action,
    args: safe,
    principal: options.principal ?? null,
  });
  const decision = await options.engine.evaluate(event);
  const enforcement = options.enforcement ?? "blocking";

  if (decision.verdict === Verdict.ALLOW || enforcement === "monitor") {
    return safe;
  }
  if (decision.verdict === Verdict.BLOCK) {
    throw new BlockedError(decision, action);
  }
  if (decision.verdict === Verdict.MODIFY) {
    // Python gates on `if decision.modified_args:` - an empty dict is falsy
    // there and truthy here, so ask the length, not the object.
    if (
      decision.modified_args !== null &&
      Object.keys(decision.modified_args).length > 0
    ) {
      Object.assign(safe, decision.modified_args);
    }
  }
  return safe;
}

/**
 * Decide on one tool result and enforce the verdict before it is returned.
 *
 * Resolves with the value the caller actually receives: the **original** result
 * on ALLOW, `decision.modified_result` on MODIFY (the whole return value is
 * replaced - `modified_args` rewrites the request, not the response). The
 * `{result: ...}` wrapper is a policy-visible view only; it must never leak out.
 *
 * BLOCK on the result path does NOT un-run the tool: the call already happened
 * and its side effects stand. It rejects with `BlockedError` in place of
 * delivering the payload, so the caller sees the refusal, never what the tool
 * said.
 */
export async function enforceToolResult(
  action: string,
  result: unknown,
  options: EnforceOptions,
): Promise<unknown> {
  const payload: Record<string, unknown> = isPlainObject(result)
    ? { ...result }
    : { result };
  const event = sensorEvent({
    action,
    args: payload,
    principal: options.principal ?? null,
    phase: "result",
  });
  const decision = await options.engine.evaluate(event);
  const enforcement = options.enforcement ?? "blocking";

  if (decision.verdict === Verdict.ALLOW || enforcement === "monitor") {
    return result;
  }
  if (decision.verdict === Verdict.BLOCK) {
    throw new BlockedError(decision, action);
  }
  if (decision.verdict === Verdict.MODIFY) {
    // Python's `is not None`: even a legitimate `null` replacement is ignored,
    // ported as-is rather than "fixed" into a divergence.
    if (
      decision.modified_result !== null &&
      decision.modified_result !== undefined
    ) {
      return decision.modified_result;
    }
  }
  return result;
}

/**
 * Wrap an MCP client session so every `callTool` is guarded in-process.
 *
 * Patches `session.callTool` in place and returns the same session. The wrapper
 * takes the SDK's params object, replaces `arguments` with the enforced copy
 * (preserving `_meta` and every other field via a spread), calls the original
 * bound to the session, and funnels the result through `enforceToolResult`.
 */
export function guardMcpSession<S extends McpSession>(
  session: S,
  options: EnforceOptions,
): S {
  // Bind the original to the session, and type it loosely: the wrapper forwards
  // `...rest` verbatim, so it must be able to call whatever shape it replaced.
  const original: (...args: any[]) => any = session.callTool.bind(session);
  (session as McpSession).callTool = async function (
    params: ToolCallParams,
    ...rest: unknown[]
  ): Promise<unknown> {
    const safe = await enforceToolCall(params.name, params.arguments, options);
    const out: unknown = await original({ ...params, arguments: safe }, ...rest);
    return enforceToolResult(params.name, out, options);
  };
  return session;
}
