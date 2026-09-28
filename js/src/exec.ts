/**
 * Intercept process execution: decide a shell command before it is spawned.
 *
 * `child_process.exec` / `execFile` are guarded with the action names
 * `child_process.exec` and `child_process.execFile`, reading `command` (and
 * `args`, for `execFile`) from the event. A BLOCK throws before the process
 * exists; a MODIFY rewrites `command` and the rewritten string is what runs.
 *
 * ## What is not guarded, and why
 *
 * Every `child_process` entry point returns a `ChildProcess` **synchronously**.
 * A guard must await the daemon before the effect, and it cannot return a live
 * handle it does not yet have - so the members whose caller uses that handle are
 * out of reach:
 *
 * - `spawn` / `fork` - the caller reads `.stdout` / `.on("exit")` off the return
 *   value; there is no handle to give until after the decision.
 * - `execSync` / `execFileSync` / `spawnSync` - synchronous by contract, and the
 *   decision is a promise.
 *
 * `exec` and `execFile` *are* guarded because their return value is conventionally
 * ignored (the result arrives via callback or `util.promisify`). The guarded
 * wrapper returns a `Promise` where the original returned a `ChildProcess`, so a
 * caller that used the handle must not be routed through it. This trade - and the
 * exact `uncovered` list - is reported by `installInterceptors()` and stated in
 * `js/README.md`.
 */

import { createRequire } from "node:module";

import { at, patchEffects, type EffectSpec, type Patch } from "./effects.js";
import type { EnforceOptions } from "./mcp.js";

const require_ = createRequire(import.meta.url);

const CHILD_OPS: readonly EffectSpec[] = [
  {
    member: "exec",
    action: "child_process.exec",
    fields: [at("command", 0), at("options", 1)],
  },
  {
    member: "execFile",
    action: "child_process.execFile",
    // `execFile(file, args, options, callback)` - the file *is* the command.
    fields: [at("command", 0), at("args", 1), at("options", 2)],
  },
];

/**
 * Guard `exec` / `execFile` for this process. Returns an uninstaller.
 *
 * Only the callback module object is patched; `require("node:child_process")`
 * and an ESM default import are the same object, so both are covered.
 */
export function patchChildProcess(options: EnforceOptions): Patch {
  const childProcess = require_("node:child_process") as unknown as Record<
    string,
    unknown
  >;
  return patchEffects(childProcess, CHILD_OPS, options);
}
