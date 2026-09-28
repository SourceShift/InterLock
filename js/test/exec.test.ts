/**
 * The process-execution interceptor, against a real daemon.
 *
 * `exec` / `execFile` are guarded because their return value is conventionally
 * ignored - the result arrives through the callback. The claims, in order:
 *
 * 1. an allowed command runs;
 * 2. a refused command is blocked **before the effect** - proved by the file the
 *    command would have deleted still being on disk;
 * 3. a MODIFY rewrites `command`, and the rewritten string is what runs;
 * 4. `execFile` is guarded under its own action and stays usable;
 * 5. `spawn` is **not** touched: it returns a live handle synchronously, which a
 *    guard that must await a verdict cannot produce.
 */
import assert from "node:assert/strict";
import child from "node:child_process";
import fs from "node:fs";
import { join } from "node:path";
import test from "node:test";

import { BlockedError } from "../src/enforce.js";
import { patchChildProcess } from "../src/exec.js";
import { EFFECT_RULES, withEngine } from "./harness.js";

type ExecCallback = (err: Error | null, stdout: string, stderr: string) => void;

/** Drive a callback-style `exec` as a promise, so `await` can observe it. */
function execWith(
  fn: (...args: any[]) => any,
  command: string,
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    (fn as (c: string, cb: ExecCallback) => void)(command, (err, stdout, stderr) =>
      err ? reject(err) : resolve({ stdout, stderr }),
    );
  });
}

/** Drive `execFile(file, args, cb)` as a promise. */
function execFileWith(
  fn: (...args: any[]) => any,
  file: string,
  args: string[],
): Promise<string> {
  return new Promise((resolve, reject) => {
    (fn as (f: string, a: string[], cb: ExecCallback) => void)(file, args, (err, stdout) =>
      err ? reject(err) : resolve(stdout),
    );
  });
}

test("exec: an allowed command runs", async () => {
  await withEngine(EFFECT_RULES, async ({ engine }) => {
    const patch = patchChildProcess({ engine });
    try {
      assert.equal((await execWith(child.exec, "echo hello")).stdout.trim(), "hello");
    } finally {
      patch.uninstall();
    }
  });
});

test("exec: a refused command is blocked before the effect", async () => {
  await withEngine(EFFECT_RULES, async ({ engine, dir }) => {
    fs.mkdirSync(join(dir, "victim"));
    fs.writeFileSync(join(dir, "victim", "victim.txt"), "still here");
    const patch = patchChildProcess({ engine });
    try {
      await assert.rejects(
        execWith(child.exec, `rm -rf ${join(dir, "victim")}`),
        BlockedError,
      );
      // The directory survived, so the refusal above was the guard and not a
      // command that ran and failed.
      assert.equal(
        fs.readFileSync(join(dir, "victim", "victim.txt"), "utf8"),
        "still here",
      );
    } finally {
      patch.uninstall();
    }
  });
});

test("exec: MODIFY rewrites the command, and the rewrite is what runs", async () => {
  await withEngine(EFFECT_RULES, async ({ engine }) => {
    const patch = patchChildProcess({ engine });
    try {
      assert.equal((await execWith(child.exec, "echo a")).stdout.trim(), "b");
    } finally {
      patch.uninstall();
    }
  });
});

test("exec: execFile is guarded under its own action and stays usable", async () => {
  await withEngine(EFFECT_RULES, async ({ engine }) => {
    const patch = patchChildProcess({ engine });
    try {
      assert.equal((await execFileWith(child.execFile, "/bin/echo", ["hi"])).trim(), "hi");
      assert.ok(patch.covered.includes("child_process.execFile"));
    } finally {
      patch.uninstall();
    }
  });
});

test("exec: spawn is left alone - it returns a live handle", async () => {
  const bag = child as unknown as Record<string, unknown>;
  const originalSpawn = bag["spawn"];
  await withEngine(EFFECT_RULES, async ({ engine }) => {
    const patch = patchChildProcess({ engine });
    try {
      assert.equal(bag["spawn"], originalSpawn);
      assert.ok(!patch.covered.includes("child_process.spawn"));
    } finally {
      patch.uninstall();
    }
  });
});
