/**
 * The filesystem interceptor, against a real daemon.
 *
 * The claims, in order:
 *
 * 1. a read the policy has no opinion about is untouched;
 * 2. a refused read is blocked **before the effect** - proved by the file still
 *    being readable through the *sync* API, which is deliberately not guarded;
 * 3. a MODIFY rewrites the path, and the rewritten path is what is read;
 * 4. a callback-style caller gets the refusal **in its callback**;
 * 5. `uninstall` puts every original function back;
 * 6. the documented ESM hole, as an executable fact: a *named* import and the
 *    namespace's own function binding bypass the guard, while
 *    `ns.promises.readFile` (a member of the live object) does not.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import * as fsNs from "node:fs";
import { readFile as namedReadFile } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import { BlockedError } from "../src/enforce.js";
import { patchFs } from "../src/fs.js";
import { EFFECT_RULES, withEngine } from "./harness.js";

type Callback = (err: Error | null, data: Buffer) => void;

/** Drive a callback-style read as a promise, so `await` can observe it. */
function readWith(fn: (...args: any[]) => any, path: string): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    (fn as (p: string, cb: Callback) => void)(path, (err, data) =>
      err ? reject(err) : resolve(data),
    );
  });
}

test("fs: an allowed read is untouched", async () => {
  await withEngine(EFFECT_RULES, async ({ engine, dir }) => {
    fs.writeFileSync(join(dir, "ok.txt"), "hello");
    const patch = patchFs({ engine });
    try {
      assert.equal(await fs.promises.readFile(join(dir, "ok.txt"), "utf8"), "hello");
    } finally {
      patch.uninstall();
    }
  });
});

test("fs: a refused read is blocked before the effect", async () => {
  await withEngine(EFFECT_RULES, async ({ engine, dir }) => {
    const target = join(dir, "blockme.txt");
    fs.writeFileSync(target, "REAL CONTENT");
    const patch = patchFs({ engine });
    try {
      await assert.rejects(fs.promises.readFile(target, "utf8"), BlockedError);
      // The file is readable, so the refusal above was the guard and not ENOENT:
      // the sync API is long enough to outrun the guard, and is not guarded.
      assert.equal(fs.readFileSync(target, "utf8"), "REAL CONTENT");
    } finally {
      patch.uninstall();
    }
  });
});

test("fs: MODIFY rewrites the path, and the rewritten file is read", async () => {
  await withEngine(EFFECT_RULES, async ({ engine, dir }) => {
    fs.writeFileSync(join(dir, "redirectme.txt"), "FROM REDIRECT");
    fs.writeFileSync(join(dir, "target.txt"), "FROM TARGET");
    const patch = patchFs({ engine });
    try {
      assert.equal(
        await fs.promises.readFile(join(dir, "redirectme.txt"), "utf8"),
        "FROM TARGET",
      );
    } finally {
      patch.uninstall();
    }
  });
});

test("fs: a callback-style caller receives the refusal in its callback", async () => {
  await withEngine(EFFECT_RULES, async ({ engine, dir }) => {
    const target = join(dir, "blockme.txt");
    fs.writeFileSync(target, "REAL CONTENT");
    const patch = patchFs({ engine });
    try {
      await assert.rejects(readWith(fs.readFile, target), BlockedError);
    } finally {
      patch.uninstall();
    }
  });
});

test("fs: uninstall restores the original functions", async () => {
  const originalReadFile = (fs as unknown as Record<string, unknown>)["readFile"];
  await withEngine(EFFECT_RULES, async ({ engine, dir }) => {
    const target = join(dir, "blockme.txt");
    fs.writeFileSync(target, "REAL CONTENT");
    const patch = patchFs({ engine });
    await assert.rejects(fs.promises.readFile(target, "utf8"), BlockedError);
    patch.uninstall();
    assert.equal((fs as unknown as Record<string, unknown>)["readFile"], originalReadFile);
    assert.equal(await fs.promises.readFile(target, "utf8"), "REAL CONTENT");
  });
});

test("fs: the ESM hole - named imports bypass, ns.promises does not", async () => {
  await withEngine(EFFECT_RULES, async ({ engine, dir }) => {
    const target = join(dir, "blockme.txt");
    fs.writeFileSync(target, "REAL CONTENT");
    const patch = patchFs({ engine });
    try {
      // A named import bound at link time is the original function - the patch
      // cannot reach it, and this is the hole the README states.
      assert.equal((await readWith(namedReadFile, target)).toString(), "REAL CONTENT");
      // Same for the namespace's own function binding.
      assert.equal((await readWith(fsNs.readFile, target)).toString(), "REAL CONTENT");
      // But `promises` is a member of the live object, so this route is guarded.
      await assert.rejects(fsNs.promises.readFile(target, "utf8"), BlockedError);
    } finally {
      patch.uninstall();
    }
  });
});
