/**
 * Guard the tools a model SDK calls, without importing the SDK.
 *
 * An MCP agent goes through `session.callTool`; an agent driven by a model SDK
 * (Anthropic, OpenAI, or a home-grown loop) goes through a *tool runner* - the
 * function the application writes to execute whatever `tool_use` the model
 * emitted. This module guards that seam, and it is the JS counterpart of
 * `guard_langchain_tools` in Python: hand it the tools or the runner you already
 * give the agent, and it hands back drop-in replacements whose execution is
 * first run through the policy engine.
 *
 * Nothing here imports a model SDK. Two shapes are accepted, and both funnel
 * through the one transport-agnostic core (`enforceToolCall` /
 * `enforceToolResult`), so a rule you write once enforces identically whether the
 * agent speaks MCP, LangChain, or a raw model loop:
 *
 * - `guardToolRunner(run)` - wrap a `(name, args) => result` dispatcher.
 * - `guardToolMap(tools)` - wrap a `{name: fn}` record of tool functions.
 *
 * **Result-phase enforcement is included here**, where Python's LangChain twin
 * is call-only. The tool has already run by the time a result is inspected, so a
 * BLOCK withholds the payload rather than un-running the effect; the value of it
 * is redaction (`enforceToolResult` can replace what the caller receives), which
 * is worth having on by default.
 */

import { isPlainObject } from "./enforce.js";
import type { EnforceOptions } from "./mcp.js";
import { enforceToolCall, enforceToolResult } from "./mcp.js";

type AnyFn = (...args: any[]) => any;

/** A `(tool name, arguments) => result` dispatcher - the model-SDK seam. */
export type ToolRunner = (
  name: string,
  args: Record<string, unknown>,
) => unknown;

/** A record of tool functions, keyed by the name the model calls. */
export type ToolMap = Record<string, AnyFn>;

/**
 * Wrap a tool runner so every call is decided before it runs.
 *
 * The returned runner has the same `(name, args)` signature - `await` it, since
 * the decision it makes is a promise.
 */
export function guardToolRunner<R extends ToolRunner>(
  run: R,
  options: EnforceOptions,
): R {
  const guarded = async (
    name: string,
    args: Record<string, unknown>,
  ): Promise<unknown> => {
    const safe = await enforceToolCall(name, args, options);
    const out = await run(name, safe);
    return enforceToolResult(name, out, options);
  };
  return guarded as unknown as R;
}

/**
 * Wrap a `{name: fn}` tool map, returning a new map of the same keys.
 *
 * A tool function is called with the arguments the model produced. When the
 * first argument is a plain object it *is* the arguments the policy sees, and a
 * MODIFY rewrites it in place of the original; any other shape (a bare string, a
 * `Buffer`, no arguments at all) is shown to the policy under the key `"input"`
 * and handed back unchanged unless the policy rewrote it.
 */
export function guardToolMap<T extends ToolMap>(
  tools: T,
  options: EnforceOptions,
): T {
  const guarded: Record<string, AnyFn> = {};
  for (const [name, fn] of Object.entries(tools)) {
    guarded[name] = guardOne(name, fn, options);
  }
  return guarded as T;
}

function guardOne(name: string, fn: AnyFn, options: EnforceOptions): AnyFn {
  return async (...args: unknown[]): Promise<unknown> => {
    const [first, ...rest] = args;
    const objectArgs = isPlainObject(first);

    // The policy-visible view. An argument-less call sends `{}` rather than
    // `{input: undefined}` - the wire refuses `undefined`, and a tool that takes
    // no arguments is not suspicious.
    const dict: Record<string, unknown> =
      args.length === 0 ? {} : objectArgs ? { ...first } : { input: first };

    const safe = await enforceToolCall(name, dict, options);
    const callArgs: unknown[] =
      args.length === 0
        ? []
        : objectArgs
          ? [safe, ...rest]
          : [safe["input"], ...rest];

    const out = await fn(...callArgs);
    return enforceToolResult(name, out, options);
  };
}
