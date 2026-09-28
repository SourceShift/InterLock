/**
 * Intercept the filesystem: decide a `fs` operation before it reaches the disk.
 *
 * `fs` is where an agent's blast radius actually lands - an unguarded `rm`,
 * `writeFile`, or `readFile` is the whole point of a sandbox. This wraps the
 * promise API (`fs.promises.*`, which *is* the `node:fs/promises` module) and
 * the callback API (`fs.*`) with the same action names, so one rule matches
 * either spelling of the same operation.
 *
 * ## What is not guarded, and why
 *
 * - **The `*Sync` variants.** `readFileSync` cannot be guarded: deciding it
 *   means awaiting the daemon, and there is no way to await inside a function
 *   whose contract is to return a value now. This is the same platform fact that
 *   makes a synchronous JS tool call unguardable, and it is stated rather than
 *   papered over. `installInterceptors()` reports it in `uncovered`.
 * - **The handle-returning openers.** `open`/`opendir` return a `FileHandle` /
 *   `Dir` synchronously, and `createReadStream`/`createWriteStream` return a
 *   stream synchronously; a wrapper that must await first cannot produce them.
 *   (`createReadStream` is a *read* of a path, so it is listed too.)
 * - **ESM named imports.** `import { readFile } from "node:fs"` and
 *   `import * as fs from "node:fs"` bind to the original function at link time;
 *   no pure-JS patch can redirect them. Only `require("node:fs")` and
 *   `import fs from "node:fs"` (a default import, which *is* the CJS object) see
 *   this interceptor. See `js/README.md`.
 * - **Result-phase rules.** These wrappers decide the call, not the return
 *   value. An `fs` function can hand back a `Stats`, a `Dirent`, or a stream -
 *   objects with no wire form - so running a result through the policy would
 *   turn an ordinary `fs.stat` into a fail-closed block. Result-phase redaction
 *   belongs on the MCP and model-SDK paths (`enforceToolResult`), where the
 *   value is a tool payload.
 *
 * The action names are `fs.<op>` - `fs.readFile`, `fs.writeFile`, `fs.rm` - so a
 * rule reads `event.action == "fs.rm"` and `event.args["path"]`. `path` is the
 * field a policy will match; the second path of `rename`/`copyFile`/`symlink` is
 * named `dest` (and `symlink`'s target is `target`, so a rule can tell a link's
 * target from the link it creates).
 */

import { createRequire } from "node:module";

import { at, patchEffects, type EffectSpec, type Patch } from "./effects.js";
import type { EnforceOptions } from "./mcp.js";

const require_ = createRequire(import.meta.url);

/** The operations, shared by the callback and the promise surface. */
const FS_OPS: readonly EffectSpec[] = [
  { member: "readFile", action: "fs.readFile", fields: [at("path", 0), at("options", 1)] },
  { member: "writeFile", action: "fs.writeFile", fields: [at("path", 0), at("data", 1), at("options", 2)] },
  { member: "appendFile", action: "fs.appendFile", fields: [at("path", 0), at("data", 1), at("options", 2)] },
  { member: "unlink", action: "fs.unlink", fields: [at("path", 0)] },
  { member: "rm", action: "fs.rm", fields: [at("path", 0), at("options", 1)] },
  { member: "rmdir", action: "fs.rmdir", fields: [at("path", 0), at("options", 1)] },
  { member: "rename", action: "fs.rename", fields: [at("path", 0), at("dest", 1)] },
  { member: "mkdir", action: "fs.mkdir", fields: [at("path", 0), at("options", 1)] },
  { member: "readdir", action: "fs.readdir", fields: [at("path", 0), at("options", 1)] },
  { member: "stat", action: "fs.stat", fields: [at("path", 0), at("options", 1)] },
  { member: "lstat", action: "fs.lstat", fields: [at("path", 0), at("options", 1)] },
  { member: "chmod", action: "fs.chmod", fields: [at("path", 0), at("mode", 1)] },
  { member: "chown", action: "fs.chown", fields: [at("path", 0), at("uid", 1), at("gid", 2)] },
  { member: "copyFile", action: "fs.copyFile", fields: [at("path", 0), at("dest", 1), at("mode", 2)] },
  { member: "cp", action: "fs.cp", fields: [at("path", 0), at("dest", 1), at("options", 2)] },
  { member: "symlink", action: "fs.symlink", fields: [at("target", 0), at("path", 1), at("type", 2)] },
  { member: "link", action: "fs.link", fields: [at("path", 0), at("dest", 1)] },
  { member: "truncate", action: "fs.truncate", fields: [at("path", 0), at("len", 1)] },
  { member: "access", action: "fs.access", fields: [at("path", 0), at("mode", 1)] },
  { member: "realpath", action: "fs.realpath", fields: [at("path", 0), at("options", 1)] },
  { member: "readlink", action: "fs.readlink", fields: [at("path", 0), at("options", 1)] },
  { member: "utimes", action: "fs.utimes", fields: [at("path", 0), at("atime", 1), at("mtime", 2)] },
];

/**
 * Guard the filesystem for this process.
 *
 * Patches both the callback surface (`fs.*`) and the promise surface
 * (`fs.promises.*`), returning an uninstaller. Call `installInterceptors()` to
 * install fs alongside exec and http; call this directly to guard fs alone.
 */
export function patchFs(options: EnforceOptions): Patch {
  const fs = require_("node:fs") as unknown as Record<string, unknown>;
  const callback = patchEffects(fs, FS_OPS, options);
  // `fs.promises` is the `node:fs/promises` module itself, so this one patch
  // covers both spellings.
  const promises = patchEffects(
    fs["promises"] as object,
    FS_OPS,
    options,
  );
  return {
    covered: [...new Set([...callback.covered, ...promises.covered])],
    uninstall(): void {
      callback.uninstall();
      promises.uninstall();
    },
  };
}
