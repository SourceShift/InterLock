/**
 * The shared core of the native (fs / exec / http) interceptors.
 *
 * Those three surfaces differ only in where a call's policy-visible fields sit:
 * `fs.readFile(path, options)`, `child_process.exec(command, options)`,
 * `fetch(url, init)`. Each is a positional argument list whose interesting
 * fields are at fixed positions. This module turns such a call into the
 * `{name: value}` shape the policy engine reads, runs it through the one
 * transport-agnostic core (`enforceToolCall`), and writes any rewrite back into
 * the positional list.
 *
 * **What it deliberately does not do.** It never touches a field whose value is
 * a function (a Node callback is not policy-visible, and is not JSON), and it
 * never includes an `undefined` field - the wire refuses `undefined` outright
 * rather than let it become a silent allow, so an optional argument that was not
 * passed is simply absent from the event.
 *
 * Patching is by property assignment on a **CJS module object**. That is not an
 * arbitrary choice: ESM named imports and `import * as ns` bind at link time to
 * the original function and cannot be redirected by any pure-JS patch. Only the
 * CJS object (`require`, and an ESM *default* import of a builtin, which is the
 * same object) sees a reassigned property. The `js/README.md` "What is not
 * guarded" section states the consequence.
 */

import type { EnforceOptions } from "./mcp.js";
import { enforceToolCall } from "./mcp.js";

/** One policy-visible field, named for the policy, at a call position. */
export interface FieldSpec {
  /** The name the policy reads it under, e.g. `"path"`. */
  name: string;
  /** Its index in the positional argument list. */
  index: number;
}

/** One patched member of a module object. */
export interface EffectSpec {
  /** The property name on the target, e.g. `"readFile"`. */
  member: string;
  /** The action the policy sees, e.g. `"fs.readFile"`. */
  action: string;
  fields: readonly FieldSpec[];
}

/** `at("path", 0)` - a terse constructor for the spec tables below. */
export function at(name: string, index: number): FieldSpec {
  return { name, index };
}

type AnyFn = (...args: any[]) => any;

/**
 * Marks a function that is already guarded, so installing twice wraps the
 * wrapper (and evaluates the policy twice) rather than being a no-op.
 */
const GUARDED = Symbol.for("interlock.guarded");

/**
 * Read the policy-visible fields out of a positional call.
 *
 * A function-valued position (a Node callback) and an `undefined` one (an
 * argument that was simply not passed) are both skipped - see the module
 * docstring for why each would be wrong to include.
 */
export function projectArgs(
  args: readonly unknown[],
  fields: readonly FieldSpec[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const field of fields) {
    const value = args[field.index];
    if (value === undefined || typeof value === "function") {
      continue;
    }
    out[field.name] = value;
  }
  return out;
}

/** Write the (possibly rewritten) fields back into a fresh argument list. */
export function applyMods(
  args: readonly unknown[],
  fields: readonly FieldSpec[],
  safe: Record<string, unknown>,
): unknown[] {
  const out = [...args];
  for (const field of fields) {
    if (
      field.index < out.length &&
      Object.prototype.hasOwnProperty.call(safe, field.name)
    ) {
      out[field.index] = safe[field.name];
    }
  }
  return out;
}

/**
 * Wrap one call so it is decided before it runs.
 *
 * The wrapper is async, because the engine it asks lives in the daemon and is
 * reached over a promise. The original function is still called with its
 * original arguments (including any callback), so a callback-style caller keeps
 * working - and a **refusal is routed to that callback** rather than left as a
 * rejected promise the caller never awaited: `fs.readFile(path, cb)` that is
 * blocked calls `cb(err)`, which is what a callback caller is written to handle.
 *
 * What that trades away is the *return value*: it becomes a `Promise` where the
 * original returned one synchronously. That is why the members whose caller
 * depends on the return value - a `ChildProcess`, a `ClientRequest`, a
 * `FileHandle` - are not in any spec table: they cannot be awaited into
 * existence.
 */
export function guardCall(
  action: string,
  original: AnyFn,
  fields: readonly FieldSpec[],
  options: EnforceOptions,
): AnyFn {
  const wrapper = (...args: unknown[]): unknown => {
    const callback = args.length > 0 ? args[args.length - 1] : undefined;
    const pending = (async (): Promise<unknown> => {
      const safe = await enforceToolCall(action, projectArgs(args, fields), options);
      return original(...applyMods(args, fields, safe));
    })();
    if (typeof callback !== "function") {
      return pending;
    }
    pending.catch((err: unknown) => {
      callback(err);
    });
    return undefined;
  };
  (wrapper as unknown as Record<symbol, unknown>)[GUARDED] = action;
  return wrapper;
}

export interface Patch {
  /** The action names now guarded. */
  covered: string[];
  /** Restore every patched member to the function it replaced. */
  uninstall(): void;
}

/**
 * Patch a set of members on a module object, returning the uninstaller.
 *
 * A member that is not a function is skipped rather than assumed: `fs.cp` does
 * not exist on older Node, and a spec table should not have to know which
 * runtime it is running on.
 */
export function patchEffects(
  target: object,
  specs: readonly EffectSpec[],
  options: EnforceOptions,
): Patch {
  const bag = target as Record<string, unknown>;
  const saved: Array<[string, unknown]> = [];
  const covered: string[] = [];
  for (const spec of specs) {
    const original = bag[spec.member];
    if (typeof original !== "function") {
      continue;
    }
    if ((original as unknown as Record<symbol, unknown>)[GUARDED] !== undefined) {
      covered.push(spec.action);
      continue;
    }
    bag[spec.member] = guardCall(spec.action, original as AnyFn, spec.fields, options);
    saved.push([spec.member, original]);
    covered.push(spec.action);
  }
  return {
    covered,
    uninstall(): void {
      for (const [member, original] of saved) {
        bag[member] = original;
      }
    },
  };
}
