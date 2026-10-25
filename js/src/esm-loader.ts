/**
 * The ESM half of the native interceptors: a module loader that makes named
 * imports of the patched builtins delegate to the patched functions.
 *
 * **Why a loader.** An ESM named import (`import { readFile } from
 * "node:fs/promises"`) is a binding established when the module is linked. It is
 * not a property lookup, so reassigning `fs.promises.readFile` - the whole
 * mechanism the CJS patches rely on - cannot redirect it. The only place with a
 * say is module resolution: replace the builtin's module record with a synthetic
 * one whose exports are thin proxies.
 *
 * Each proxy forwards `apply` and `construct` to `__real[name]` **at call time**,
 * where `__real` is the same CJS module object the interceptors patch. Three
 * consequences fall out of that:
 *
 * - the wrappers are installed *after* patching, but stay correct if the
 *   interceptors are uninstalled and re-installed later in the process;
 * - unguarded members (`readFileSync`, `createReadStream`) pass through
 *   unchanged, so their identities and constructor behaviour are preserved;
 * - properties (`util.promisify`'s custom symbol, `.native`, `.prototype`) are
 *   read from the live function, because the proxy forwards every lookup too.
 *
 * **What this still cannot reach.** Node resolves builtins *before* this hook
 * for any module that was already linked, and the sync variants and
 * handle-returning openers remain unguardable for the reasons stated in
 * `install.ts`. Registration must therefore happen at process start - which is
 * what `node --import interlock-guard/esm-hook` is for.
 *
 * The module is loaded by Node in the hooks thread. It only enumerates export
 * names with a throwaway `require`; the generated source evaluates in the
 * importing realm, against that realm's (patched) CJS object.
 */

import { createRequire } from "node:module";

import { CHILD_OPS } from "./exec.js";
import { FS_OPS } from "./fs.js";

const require_ = createRequire(process.execPath);

/** A loader hook's context; only `format` is relevant to a short-circuit. */
interface LoadContext {
  format?: string | null;
}

type NextLoad = (url: string, context: LoadContext) => Promise<unknown>;

/**
 * The builtins this loader replaces, and the members the interceptors patch on
 * each. `node:fs` and `node:fs/promises` share one op table in `fs.ts`; the
 * names are the same on both surfaces.
 */
const MEMBERS: ReadonlyMap<string, readonly string[]> = new Map([
  ["node:fs", FS_OPS.map((spec) => spec.member)],
  ["node:fs/promises", FS_OPS.map((spec) => spec.member)],
  ["node:child_process", CHILD_OPS.map((spec) => spec.member)],
]);

/** Identifiers only: an export name that is not one cannot be declared. */
const IDENTIFIER = /^[A-Za-z_$][\w$]*$/;

/**
 * Build the synthetic module for one builtin.
 *
 * Every real export is re-exported, so replacing the module does not narrow its
 * surface: an unguarded member is delegated (`export const x = __real["x"]`),
 * a patched member is wrapped, and values (`fs.constants`, `fs.promises`) are
 * passed through. `export default __real` keeps `import fs from "node:fs"`
 * pointing at the same (patched) object it always was.
 */
function moduleSource(specifier: string, members: readonly string[]): string {
  const real = require_(specifier) as Record<string, unknown>;
  const guarded = new Set(members);
  const wrapped: string[] = [];
  const passed: string[] = [];
  for (const name of Object.keys(real)) {
    if (!IDENTIFIER.test(name) || name === "default") {
      continue;
    }
    if (guarded.has(name) && typeof real[name] === "function") {
      wrapped.push(`export const ${name} = __delegate(${JSON.stringify(name)});`);
    } else {
      passed.push(`export const ${name} = __real[${JSON.stringify(name)}];`);
    }
  }
  return [
    'import { createRequire as __createRequire } from "node:module";',
    `const __real = __createRequire(process.execPath)(${JSON.stringify(specifier)});`,
    "const __delegate = (name) => new Proxy(__real[name], {",
    "  apply: (_target, thisArg, args) => Reflect.apply(__real[name], thisArg, args),",
    "  construct: (_target, args, newTarget) =>",
    "    Reflect.construct(__real[name], args, newTarget),",
    "});",
    ...wrapped,
    ...passed,
    "export default __real;",
    "",
  ].join("\n");
}

/**
 * The `load` hook. Builtins are short-circuited; every other module goes on to
 * the next loader untouched.
 */
export async function load(
  url: string,
  context: LoadContext,
  nextLoad: NextLoad,
): Promise<unknown> {
  const members = MEMBERS.get(url);
  if (members === undefined) {
    return nextLoad(url, context);
  }
  return {
    format: "module",
    shortCircuit: true,
    source: moduleSource(url, members),
  };
}
