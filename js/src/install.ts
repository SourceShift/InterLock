/**
 * Install the native interceptors, and say exactly what they did not cover.
 *
 * `installInterceptors({engine})` patches the process's filesystem, process, and
 * outbound-HTTP surfaces so an agent's effects are decided before they happen.
 * It returns an uninstaller **and a coverage report**.
 *
 * The report is the point. Some of Node's API surface cannot be guarded by any
 * pure-JS patch - a synchronous call cannot await a verdict, and a function that
 * returns a live handle synchronously cannot return one it has not awaited. Those
 * holes are permanent, not oversights, so they are *named* in `uncovered` rather
 * than left for a deployer to assume away. A guard whose coverage is a guess is
 * worse than one whose coverage is stated.
 */

import type { Patch } from "./effects.js";
import { patchChildProcess } from "./exec.js";
import { patchFs } from "./fs.js";
import { patchFetch } from "./http.js";
import type { EnforceOptions } from "./mcp.js";

export interface InstallOptions extends EnforceOptions {
  /** Guard `fs` / `fs.promises`. Default true. */
  fs?: boolean;
  /** Guard `child_process.exec` / `execFile`. Default true. */
  exec?: boolean;
  /** Guard `globalThis.fetch`. Default true. */
  http?: boolean;
}

export interface Interceptors {
  /** Action names now guarded, e.g. `"fs.rm"`, `"http.fetch"`. */
  covered: string[];
  /** Action names that cannot be guarded, for the deployer to route around. */
  uncovered: string[];
  uninstall(): void;
}

/**
 * The permanent holes, in the same `action` spelling the policy reads so a rule
 * author can see at a glance that no rule on them will ever fire.
 */
export const UNGUARDABLE: readonly string[] = [
  // fs: synchronous variants, and the openers that return a handle/stream.
  "fs.readFileSync",
  "fs.writeFileSync",
  "fs.appendFileSync",
  "fs.unlinkSync",
  "fs.rmSync",
  "fs.rmdirSync",
  "fs.renameSync",
  "fs.mkdirSync",
  "fs.readdirSync",
  "fs.statSync",
  "fs.lstatSync",
  "fs.chmodSync",
  "fs.chownSync",
  "fs.copyFileSync",
  "fs.cpSync",
  "fs.symlinkSync",
  "fs.linkSync",
  "fs.truncateSync",
  "fs.accessSync",
  "fs.realpathSync",
  "fs.readlinkSync",
  "fs.utimesSync",
  "fs.open",
  "fs.openSync",
  "fs.opendir",
  "fs.createReadStream",
  "fs.createWriteStream",
  // child_process: a ChildProcess is returned synchronously.
  "child_process.spawn",
  "child_process.spawnSync",
  "child_process.fork",
  "child_process.execSync",
  "child_process.execFileSync",
  // http: a ClientRequest is returned synchronously.
  "http.request",
  "http.get",
  "https.request",
  "https.get",
];

/**
 * Install the selected interceptors. Returns the coverage report and the
 * uninstaller that restores every patched function.
 */
export function installInterceptors(options: InstallOptions): Interceptors {
  const patches: Patch[] = [];
  if (options.fs ?? true) {
    patches.push(patchFs(options));
  }
  if (options.exec ?? true) {
    patches.push(patchChildProcess(options));
  }
  if (options.http ?? true) {
    patches.push(patchFetch(options));
  }

  return {
    covered: [...new Set(patches.flatMap((patch) => patch.covered))].sort(),
    uncovered: [...UNGUARDABLE],
    uninstall(): void {
      for (const patch of patches) {
        patch.uninstall();
      }
    },
  };
}
