/**
 * Register the ESM loader alongside the native interceptors.
 *
 * `installInterceptors` closes the CJS hole (property assignment on the module
 * object). `registerEsmInterceptors` closes the ESM hole: it installs the same
 * patches, then registers `./esm-loader.js`, which replaces the patched builtins
 * with synthetic modules whose named exports delegate to the patched functions
 * at call time.
 *
 * **Register before the application loads.** The loader only affects modules
 * linked after registration; an `fs` namespace imported before it keeps binding
 * the original functions. The supported entry point is a preload:
 *
 * ```sh
 * INTERLOCK_SOCKET=/run/interlock.sock \
 *   node --import interlock-guard/esm-hook app.mjs
 * ```
 *
 * Registration is process-wide and cannot be undone - Node has no unregister.
 * The returned `uninstall` restores the patched functions, and the loader's
 * proxies then delegate to the originals, so an uninstalled process behaves
 * exactly as it did before install.
 */

import * as nodeModule from "node:module";

import type { InstallOptions, Interceptors } from "./install.js";
import { installInterceptors } from "./install.js";

const ESM_NAMED_IMPORT = "esm.named-import";

let registered = false;

/**
 * Install the interceptors and register the ESM loader.
 *
 * The coverage report is the one `installInterceptors` returns, with the ESM
 * hole moved from `uncovered` to `covered`. Installing twice returns two
 * reporter objects over the same patches, exactly as `installInterceptors` does.
 *
 * Throws on Node versions without `module.register` (before 20.6), because a
 * silent fallback would leave the ESM surface unguarded while the report said
 * otherwise.
 */
export function registerEsmInterceptors(options: InstallOptions): Interceptors {
  const interceptors = installInterceptors(options);
  if (!registered) {
    const register = (
      nodeModule as { register?: (specifier: string, parentURL?: string) => void }
    ).register;
    if (typeof register !== "function") {
      interceptors.uninstall();
      throw new Error(
        "registerEsmInterceptors requires Node >= 20.6 (module.register); " +
          "the CJS interceptors were uninstalled, so nothing is half-guarded",
      );
    }
    register("./esm-loader.js", import.meta.url);
    registered = true;
  }
  return {
    covered: [...interceptors.covered, ESM_NAMED_IMPORT].sort(),
    uncovered: interceptors.uncovered.filter((name) => name !== ESM_NAMED_IMPORT),
    uninstall: interceptors.uninstall,
  };
}

/** Whether the ESM loader has been registered in this process. */
export function esmLoaderRegistered(): boolean {
  return registered;
}
