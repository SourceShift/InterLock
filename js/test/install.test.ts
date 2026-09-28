/**
 * The install facade: the coverage report, and the promise that uninstall is
 * complete.
 *
 * 1. `covered` names the action names now guarded; `uncovered` names the ones no
 *    pure-JS patch can reach, so a deployer can route around them rather than
 *    assume they are covered;
 * 2. `uninstall` puts every original function back - fs, child_process, and the
 *    global `fetch`;
 * 3. a blocked call really throws through the installed surface;
 * 4. installing twice does not evaluate the policy twice, and uninstalling both
 *    still restores the originals.
 */
import assert from "node:assert/strict";
import child from "node:child_process";
import fs from "node:fs";
import { join } from "node:path";
import test from "node:test";

import { BlockedError } from "../src/enforce.js";
import { installInterceptors } from "../src/install.js";
import type { Engine } from "../src/mcp.js";
import { EFFECT_RULES, withEngine } from "./harness.js";

test("install: the coverage report names what is and is not guarded", async () => {
  await withEngine(EFFECT_RULES, async ({ engine }) => {
    const interceptors = installInterceptors({ engine });
    try {
      for (const action of ["fs.readFile", "child_process.exec", "http.fetch"]) {
        assert.ok(interceptors.covered.includes(action), `covered: ${action}`);
      }
      for (const action of [
        "fs.readFileSync",
        "child_process.spawn",
        "http.request",
      ]) {
        assert.ok(interceptors.uncovered.includes(action), `uncovered: ${action}`);
      }
    } finally {
      interceptors.uninstall();
    }
  });
});

test("install: uninstall restores every patched function", async () => {
  const fsBag = fs as unknown as Record<string, unknown>;
  const childBag = child as unknown as Record<string, unknown>;
  const beforeRead = fsBag["readFile"];
  const beforeExec = childBag["exec"];
  const beforeFetch = globalThis.fetch;
  await withEngine(EFFECT_RULES, async ({ engine }) => {
    const interceptors = installInterceptors({ engine });
    assert.notEqual(fsBag["readFile"], beforeRead);
    assert.notEqual(childBag["exec"], beforeExec);
    assert.notEqual(globalThis.fetch, beforeFetch);
    interceptors.uninstall();
    assert.equal(fsBag["readFile"], beforeRead);
    assert.equal(childBag["exec"], beforeExec);
    assert.equal(globalThis.fetch, beforeFetch);
  });
});

test("install: a blocked fs call throws through the installed surface", async () => {
  await withEngine(EFFECT_RULES, async ({ engine, dir }) => {
    fs.writeFileSync(join(dir, "blockme.txt"), "REAL CONTENT");
    const interceptors = installInterceptors({ engine });
    try {
      await assert.rejects(
        fs.promises.readFile(join(dir, "blockme.txt"), "utf8"),
        BlockedError,
      );
    } finally {
      interceptors.uninstall();
    }
  });
});

test("install: a second install does not evaluate twice, and both uninstalls restore", async () => {
  await withEngine(EFFECT_RULES, async ({ engine, dir }) => {
    fs.writeFileSync(join(dir, "ok.txt"), "hello");
    const fsBag = fs as unknown as Record<string, unknown>;
    const beforeRead = fsBag["readFile"];
    let evals = 0;
    const counting: Engine = {
      async evaluate(event) {
        evals += 1;
        return engine.evaluate(event);
      },
    };
    const first = installInterceptors({ engine: counting });
    const second = installInterceptors({ engine: counting });
    try {
      assert.equal(await fs.promises.readFile(join(dir, "ok.txt"), "utf8"), "hello");
      assert.equal(evals, 1, "two installs must not double-guard the same member");
    } finally {
      first.uninstall();
      second.uninstall();
    }
    assert.equal(fsBag["readFile"], beforeRead);
  });
});
