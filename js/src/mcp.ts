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

import {
  BlockedError,
  Decision,
  NotApprovedError,
  Verdict,
  isPlainObject,
} from "./enforce.js";
import type { Phase, SensorEvent } from "./event.js";
import { newCallId, sensorEvent } from "./event.js";

export type Enforcement = "blocking" | "monitor";

/** The one method the interceptors need: decide an event, or reject. */
export interface Engine {
  evaluate(event: SensorEvent): Promise<Decision>;
}

/** What an `onEscalate` callback is asked to decide. */
export interface EscalationRequest {
  action: string;
  phase: Phase;
  /** One line, at most 512 UTF-8 bytes - written for the human deciding. */
  reason: string;
  policy_id: string | null;
  attributed_to: string | null;
  principal: string | null;
  call_id: string | null;
  /** The call (or result payload) the human is being asked about. */
  args: Record<string, unknown>;
}

export interface EnforceOptions {
  engine: Engine;
  enforcement?: Enforcement;
  /** Who is acting, if the caller knows. `null`/omitted leaves it unattributed. */
  principal?: string | null;
  /**
   * Decides ESCALATE verdicts. Resolve `true` to run this one call; anything
   * else - including a throw - blocks it with `NotApprovedError`. Without a
   * callback every escalation is blocked.
   */
  onEscalate?: (request: EscalationRequest) => boolean | Promise<boolean>;
  /**
   * Links a call's event to its result's. `guardMcpSession` mints one per
   * call; pass the same value to `enforceToolCall` and `enforceToolResult`
   * when you drive them yourself.
   */
  callId?: string | null;
}

/** The policy id on a block caused by a verdict this client does not know. */
export const UNHANDLED_POLICY_ID = "unhandled_verdict";

const MAX_REASON_BYTES = 512;

/** One printable line of at most 512 UTF-8 bytes (Python's `bound_reason`). */
export function boundReason(reason: string): string {
  // eslint-disable-next-line no-control-regex
  const line = String(reason ?? "").split(/\s+/).filter(Boolean).join(" ").replace(/[\x00-\x1f\x7f]/g, "");
  const bytes = new TextEncoder().encode(line);
  if (bytes.length <= MAX_REASON_BYTES) {
    return line;
  }
  return new TextDecoder("utf-8", { fatal: false })
    .decode(bytes.slice(0, MAX_REASON_BYTES))
    .replace(/\uFFFD+$/, "");
}

/**
 * Enforce one decision. Resolves with what the action proceeds with (an
 * ALLOW, or the MODIFY to apply); rejects with `BlockedError` /
 * `NotApprovedError` otherwise. Every verdict has a branch, and a verdict
 * without one is blocked rather than falling through to "run it".
 */
async function settle(
  event: SensorEvent,
  decision: Decision,
  options: EnforceOptions,
): Promise<Decision> {
  const enforcement = options.enforcement ?? "blocking";
  if (decision.verdict === Verdict.ALLOW) {
    return decision;
  }
  if (enforcement === "monitor") {
    return Decision.allow();
  }
  switch (decision.verdict) {
    case Verdict.BLOCK:
      throw new BlockedError(decision, event.action);
    case Verdict.MODIFY:
      return decision;
    case Verdict.ESCALATE: {
      const reason = boundReason(decision.reason);
      const refuse = (why: string): never => {
        throw new NotApprovedError(
          Decision.block(
            `not approved (${why}): ${reason}`,
            decision.policy_id,
            decision.attributed_to,
          ),
          event.action,
        );
      };
      if (!options.onEscalate) {
        refuse("no approver is installed");
      }
      let approved = false;
      try {
        approved =
          (await options.onEscalate!({
            action: event.action,
            phase: event.phase,
            reason,
            policy_id: decision.policy_id,
            attributed_to: decision.attributed_to,
            principal: event.principal,
            call_id: event.call_id ?? null,
            args: event.args,
          })) === true;
      } catch {
        refuse("the approver threw");
      }
      if (!approved) {
        refuse("declined by the approver");
      }
      const hasArgs =
        decision.modified_args !== null &&
        Object.keys(decision.modified_args).length > 0;
      const hasResult =
        decision.modified_result !== null && decision.modified_result !== undefined;
      if (hasArgs || hasResult) {
        return new Decision({
          verdict: Verdict.MODIFY,
          reason: decision.reason,
          policy_id: decision.policy_id,
          attributed_to: decision.attributed_to,
          modified_args: decision.modified_args,
          modified_result: decision.modified_result,
        });
      }
      return Decision.allow(decision.reason, decision.policy_id);
    }
    default:
      throw new BlockedError(
        Decision.block(
          `unhandled verdict ${JSON.stringify(decision.verdict)}, denied fail-closed`,
          decision.policy_id ?? UNHANDLED_POLICY_ID,
          decision.attributed_to,
        ),
        event.action,
      );
  }
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

/**
 * Decide on one tool call and enforce the verdict before it runs.
 *
 * Resolves with the arguments to actually use: unchanged on ALLOW, rewritten on
 * MODIFY (`modified_args` merged in). Rejects with `BlockedError` on BLOCK under
 * the default `enforcement: "blocking"`. An ESCALATE proceeds only when
 * `onEscalate` approves it, else rejects with `NotApprovedError`. Under
 * `enforcement: "monitor"` it records the would-be decision and never
 * intervenes.
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
    call_id: options.callId ?? null,
  });
  const decision = await settle(event, await options.engine.evaluate(event), options);
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
    call_id: options.callId ?? null,
  });
  const decision = await settle(event, await options.engine.evaluate(event), options);
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
    const perCall: EnforceOptions = { ...options, callId: newCallId() };
    const safe = await enforceToolCall(params.name, params.arguments, perCall);
    const out: unknown = await original({ ...params, arguments: safe }, ...rest);
    return enforceToolResult(params.name, out, perCall);
  };
  return session;
}
