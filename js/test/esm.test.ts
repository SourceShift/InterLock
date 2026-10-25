/**
 * The ESM loader: named and namespace imports of the patched builtins are
 * decided, not just default imports.
 *
 * The case the CJS surface cannot reach is `import { readFile } from
 * "node:fs/promises"` - a binding fixed at link time, which no property
 * assignment can redirect. So these tests spawn a *fresh* node process against
 * the real sidecar daemon, because that is the only honest way to exercise a
 * loader: registration has to happen before the application links.
 *
 * What is asserted:
 * 1. `registerEsmInterceptors` moves the named-import hole from `uncovered` to
 *    `covered`, and uninstalling still restores the patched functions;
 * 2. a blocked `readFile` really throws through a named import, a namespace
 *    import, and the callback surface of a bare `fs` specifier;
 * 3. an allowed read through the same imports returns the file's bytes - the
 *    wrapper delegates, it does not merely refuse;
 * 4. the documented `--import interlock-guard/esm-hook` entry works from
 *    `INTERLOCK_SOCKET`, and fails loudly without it.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

import { esmLoaderRegistered, registerEsmInterceptors } from "../src/esm.js";
import { installInterceptors, UNGUARDABLE } from "../src/install.js";
import { EFFECT_RULES, withEngine } from "./harness.js";

const HERE = dirname(fileURLToPath(import.meta.url));
/** `js/dist-test/test/` -> `js/dist-test/src/` (the compiled sources). */
const SRC = resolve(HERE, "..", "src");

const CLIENT_URL = pathToFileURL(join(SRC, "client.js")).href;
const ESM_URL = pathToFileURL(join(SRC, "esm.js")).href;
const ESM_HOOK_URL = pathToFileURL(join(SRC, "esm-hook.js")).href;

interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

function runNode(args: readonly string[], env: NodeJS.ProcessEnv = {}): Promise<RunResult> {
  return new Promise((done, fail) => {
    // Strip the runner's own marker: an inherited NODE_TEST_CONTEXT makes the
    // child believe it is a test-runner child and try to speak the runner's
    // protocol over descriptors this test did not set up - a silent hang.
    const base = { ...process.env };
    delete base["NODE_TEST_CONTEXT"];
    const child = spawn(process.execPath, args, {
      env: { ...base, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", fail);
    child.on("close", (code) => done({ code, stdout, stderr }));
  });
}

/** A preload that installs the interceptors and the loader against `socket`. */
function writePreload(dir: string, socket: string): string {
  const path = join(dir, "preload.mjs");
  writeFileSync(
    path,
    [
      `import { RemoteEngine } from ${JSON.stringify(CLIENT_URL)};`,
      `import { registerEsmInterceptors } from ${JSON.stringify(ESM_URL)};`,
      `registerEsmInterceptors({`,
      `  engine: new RemoteEngine(${JSON.stringify(socket)}, { timeout: 5 }),`,
      `});`,
      "",
    ].join("\n"),
  );
  return path;
}

/**
 * An app that reads `IL_TARGET` through the surface named by `IL_STYLE` and
 * prints one machine-readable line. Exit code 2 means the call was refused.
 */
const APP = `\
const style = process.env["IL_STYLE"];
const target = process.env["IL_TARGET"];
const report = (text) => console.log(text);

try {
  if (style === "named") {
    const { readFile } = await import("node:fs/promises");
    report("OK " + (await readFile(target, "utf8")));
  } else if (style === "namespace") {
    const fsp = await import("node:fs/promises");
    report("OK " + (await fsp.readFile(target, "utf8")));
  } else if (style === "callback") {
    const { readFile } = await import("fs");
    await new Promise((done, fail) => {
      readFile(target, "utf8", (error, text) => {
        if (error) fail(error);
        else {
          report("OK " + text);
          done();
        }
      });
    });
  } else {
    throw new Error("unknown IL_STYLE " + style);
  }
} catch (error) {
  report("ERR " + (error && error.name) + " " + (error && error.message));
  process.exitCode = 2;
}
`;

test("esm: registration closes the named-import hole and uninstall restores", async () => {
  await withEngine(EFFECT_RULES, async ({ engine }) => {
    const before = installInterceptors({ engine });
    before.uninstall();
    assert.ok(
      before.uncovered.includes("esm.named-import"),
      "the CJS-only surface must still report the hole",
    );

    assert.equal(esmLoaderRegistered(), false);
    const report = registerEsmInterceptors({ engine });
    try {
      assert.equal(esmLoaderRegistered(), true);
      assert.ok(report.covered.includes("esm.named-import"));
      assert.deepEqual(
        report.uncovered,
        UNGUARDABLE.filter((name) => name !== "esm.named-import"),
        "every other permanent hole stays reported",
      );
      assert.equal(
        report.covered.filter((name) => report.uncovered.includes(name)).length,
        0,
        "covered and uncovered must stay disjoint",
      );
    } finally {
      report.uninstall();
    }
  });
});

test("esm: a blocked call throws through named, namespace and callback imports", async () => {
  await withEngine(EFFECT_RULES, async ({ engine, dir, daemon }) => {
    writeFileSync(join(dir, "blockme.txt"), "REAL CONTENT");
    const preload = writePreload(dir, daemon.path);
    const app = join(dir, "app.mjs");
    writeFileSync(app, APP);

    for (const style of ["named", "namespace", "callback"]) {
      const result = await runNode(["--import", preload, app], {
        IL_STYLE: style,
        IL_TARGET: join(dir, "blockme.txt"),
      });
      assert.equal(result.code, 2, `${style}: ${result.stdout}${result.stderr}`);
      assert.match(
        result.stdout,
        /^ERR BlockedError .*off limits/m,
        `${style}: ${result.stdout}${result.stderr}`,
      );
      assert.doesNotMatch(result.stdout, /REAL CONTENT/, "the bytes must not escape");
    }

    assert.equal(engine.fallbacks, 0, "every decision came from the daemon");
  });
});

test("esm: an allowed call still reads through the same imports", async () => {
  await withEngine(EFFECT_RULES, async ({ engine, dir, daemon }) => {
    writeFileSync(join(dir, "ok.txt"), "hello");
    const preload = writePreload(dir, daemon.path);
    const app = join(dir, "app.mjs");
    writeFileSync(app, APP);

    for (const style of ["named", "namespace", "callback"]) {
      const result = await runNode(["--import", preload, app], {
        IL_STYLE: style,
        IL_TARGET: join(dir, "ok.txt"),
      });
      assert.equal(result.code, 0, `${style}: ${result.stdout}${result.stderr}`);
      assert.equal(result.stdout.trim(), "OK hello", `${style}: ${result.stderr}`);
    }
    assert.equal(engine.fallbacks, 0);
  });
});

test("esm: the documented esm-hook entry guards from INTERLOCK_SOCKET", async () => {
  await withEngine(EFFECT_RULES, async ({ dir, daemon }) => {
    writeFileSync(join(dir, "blockme.txt"), "REAL CONTENT");
    const app = join(dir, "app.mjs");
    writeFileSync(app, APP);

    const guarded = await runNode(["--import", ESM_HOOK_URL, app], {
      IL_STYLE: "named",
      IL_TARGET: join(dir, "blockme.txt"),
      INTERLOCK_SOCKET: daemon.path,
    });
    assert.equal(guarded.code, 2, guarded.stdout + guarded.stderr);
    assert.match(guarded.stdout, /^ERR BlockedError /m, guarded.stderr);

    const missing = await runNode(["--import", ESM_HOOK_URL, app], {
      IL_STYLE: "named",
      IL_TARGET: join(dir, "blockme.txt"),
      INTERLOCK_SOCKET: "",
    });
    assert.notEqual(missing.code, 0, "an unconfigured preload must not start unguarded");
    assert.match(missing.stderr, /INTERLOCK_SOCKET is not set/);
  });
});

test("esm: the loader leaves unguarded exports and classes alone", async () => {
  const dir = mkdtempSync(join("/tmp", "il-esm-"));
  try {
    const app = join(dir, "app.mjs");
    writeFileSync(
      app,
      `\
import { createRequire } from "node:module";
import { readFileSync, Stats, constants, promises } from "node:fs";
import { readFile } from "node:fs/promises";
import { exec, spawn } from "node:child_process";

// The CJS object the interceptors patch - the thing the wrappers must reach.
const real = createRequire(process.execPath)("node:fs");
for (const [name, value] of Object.entries({ readFile, readFileSync, exec, spawn })) {
  if (typeof value !== "function") throw new Error(name + " is not callable");
}
// Unguarded exports keep their identity; only guarded members are wrapped.
for (const name of ["readFileSync", "Stats", "constants", "promises"]) {
  if (name === "constants") {
    if (constants !== real.constants) throw new Error("constants must pass through");
  } else if ({ readFileSync, Stats, promises }[name] !== real[name]) {
    throw new Error(name + " must keep its identity");
  }
}
if (typeof promises.readFile !== "function") {
  throw new Error("the promises object must stay the patched one");
}
console.log("OK");
`,
    );
    const preload = join(dir, "preload.mjs");
    writeFileSync(
      preload,
      `\
import { registerEsmInterceptors } from ${JSON.stringify(ESM_URL)};
const engine = {
  async evaluate() {
    return { verdict: "allow", reason: "test", policy_id: "p.allow" };
  },
};
registerEsmInterceptors({ engine });
`,
    );
    const result = await runNode(["--import", preload, app]);
    assert.equal(result.code, 0, result.stdout + result.stderr);
    assert.equal(result.stdout.trim(), "OK");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
