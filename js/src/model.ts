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
import { encodeValue } from "./wire.js";

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
 * first argument is a plain object its own keys are what the policy sees, and a
 * MODIFY rewrites them in place of the original; any other shape (a bare
 * string, a `Buffer`, no arguments at all) is shown to the policy under the key
 * `"input"`.
 *
 * Every representable trailing argument is visible too, under the reserved key
 * `"positional_args"`. A plain-object first argument with no trailing
 * arguments keeps exactly the old shape; the key appears only when there is at
 * least one trailing argument *and* the wire can carry all of them. A value
 * the codec refuses (an `AbortSignal`, a class instance, a function) omits the
 * whole key rather than blocking the call: the policy cannot see what cannot
 * be transmitted, and the tool still receives the argument untouched. A MODIFY
 * whose `positional_args` is an array replaces the trailing arguments.
 * `positional_args` never reaches the tool as a key of the first argument, and
 * the caller's arrays and objects are never mutated.
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

/**
 * The trailing arguments, if the wire can carry every one of them.
 *
 * A model SDK commonly appends an `AbortSignal`, a context/options object, or a
 * callback. Values `encodeValue` refuses cannot cross the wire, and including
 * one would make the guard throw before the tool ran - blocking a call the
 * policy never got to see. They are therefore omitted from the event, as the
 * fetch view omits its unrepresentable `init` fields; the real call still
 * receives them. The key is dropped as a whole rather than per element, so an
 * index into `positional_args` always names the same real argument.
 */
function representableTrailing(rest: readonly unknown[]): unknown[] | undefined {
  const copy = [...rest];
  try {
    encodeValue(copy);
    return copy;
  } catch {
    return undefined;
  }
}

function guardOne(name: string, fn: AnyFn, options: EnforceOptions): AnyFn {
  return async (...args: unknown[]): Promise<unknown> => {
    const [first, ...rest] = args;
    const objectArgs = isPlainObject(first);

    // The policy-visible view. An argument-less call sends `{}` rather than
    // `{input: undefined}` - the wire refuses `undefined`, and a tool that takes
    // no arguments is not suspicious. `positional_args` is reserved: it is
    // present only when there are representable trailing arguments, and it
    // replaces any own key of the same name in the first object (documented in
    // `js/README.md`).
    const dict: Record<string, unknown> =
      args.length === 0 ? {} : objectArgs ? { ...first } : { input: first };
    const trailing = rest.length > 0 ? representableTrailing(rest) : undefined;
    if (trailing !== undefined) {
      dict["positional_args"] = trailing;
    }

    const safe = await enforceToolCall(name, dict, options);

    // Build a fresh argument list; never hand the caller's array back, and never
    // expose the synthetic `positional_args` key inside the first argument.
    const callArgs: unknown[] = [];
    if (args.length > 0) {
      if (objectArgs) {
        // Only strip the key when it is the synthetic one this wrapper added;
        // otherwise (no trailing arguments, or an unrepresentable one) it
        // belongs to the caller, if present.
        if (trailing !== undefined) {
          const firstForTool = { ...safe };
          delete firstForTool["positional_args"];
          callArgs.push(firstForTool);
        } else {
          callArgs.push(safe);
        }
      } else {
        callArgs.push(safe["input"]);
      }
    }
    // Only a policy rewrite replaces the trailing arguments. The projected
    // array is passed by reference through `enforceToolCall`, so an unchanged
    // value is the same object; anything else is a MODIFY. This also keeps a
    // caller's own `positional_args` key (present only when the synthetic one
    // was not added) from being mistaken for a rewrite.
    const rewritten = safe["positional_args"];
    if (trailing !== undefined && Array.isArray(rewritten) && rewritten !== trailing) {
      callArgs.push(...rewritten);
    } else if (rest.length > 0) {
      callArgs.push(...rest);
    }

    const out = await fn(...callArgs);
    return enforceToolResult(name, out, options);
  };
}
