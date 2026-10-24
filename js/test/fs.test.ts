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
 *    `ns.promises.readFile` (a member of the live object) does not;
 * 7. path shapes are projected as text - a `Buffer` path and a `file://` `URL`
 *    reach a path rule as the path string, so the rule can match;
 * 8. `open` and `opendir` are decided in both the callback and promise shapes,
 *    and a benign open still returns a usable handle.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import * as fsNs from "node:fs";
import { readFile as namedReadFile } from "node:fs";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { tmpdir } from "node:os";
import test from "node:test";

import { BlockedError, Decision } from "../src/enforce.js";
import { patchFs } from "../src/fs.js";
import type { Engine } from "../src/mcp.js";
import { EFFECT_RULES, withEngine } from "./harness.js";

/**
 * An in-process engine for the `open`/`opendir` cases. `EFFECT_ENGINE` has no
 * rule for those actions (it is Python and out of scope), so this returns BLOCK
 * for a sensitive path and ALLOW otherwise. The interceptor under test is the
 * real one.
 */
function handleEngine(): Engine {
  return {
    async evaluate(event) {
      if (
        (event.action === "fs.open" || event.action === "fs.opendir") &&
        String(event.args["path"] ?? "").includes("blockme")
      ) {
        return Decision.block("sensitive path", "p.shape", "path");
      }
      return Decision.allow();
    },
  };
}

/** Drive a callback-style open as a promise, so `await` can observe it. */
function openWith(
  fn: (...args: any[]) => any,
  path: string,
  flags: string,
): Promise<any> {
  return new Promise((resolve, reject) => {
    fn(path, flags, (err: Error | null, handle: unknown) =>
      err ? reject(err) : resolve(handle),
    );
  });
}


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

test("fs: a Buffer path is projected as text, so a path rule matches", async () => {
  await withEngine(EFFECT_RULES, async ({ engine, dir }) => {
    const target = join(dir, "blockme-buffer.txt");
    fs.writeFileSync(target, "REAL CONTENT");
    const patch = patchFs({ engine });
    try {
      // The rule matches the token "blockme" in the path *string*: a raw Buffer
      // would reach it as a bytes envelope and match nothing.
      await assert.rejects(fs.promises.readFile(Buffer.from(target), "utf8"), BlockedError);
      assert.equal(fs.readFileSync(target, "utf8"), "REAL CONTENT");
    } finally {
      patch.uninstall();
    }
  });
});

test("fs: a file:// URL path is projected as text", async () => {
  await withEngine(EFFECT_RULES, async ({ engine, dir }) => {
    const target = join(dir, "blockme-url.txt");
    fs.writeFileSync(target, "REAL CONTENT");
    const patch = patchFs({ engine });
    try {
      await assert.rejects(
        fs.promises.readFile(pathToFileURL(target), "utf8"),
        BlockedError,
      );
    } finally {
      patch.uninstall();
    }
  });
});

test("fs: a benign Buffer path still reads, and the caller's Buffer is not replaced", async () => {
  await withEngine(EFFECT_RULES, async ({ engine, dir }) => {
    fs.writeFileSync(join(dir, "ok.txt"), "hello");
    const pathBuffer = Buffer.from(join(dir, "ok.txt"));
    const patch = patchFs({ engine });
    try {
      assert.equal(await fs.promises.readFile(pathBuffer, "utf8"), "hello");
      // The original argument list was used as-is; projection is event-only.
      assert.equal(pathBuffer.toString("utf8"), join(dir, "ok.txt"));
      assert.ok(Buffer.isBuffer(pathBuffer));
    } finally {
      patch.uninstall();
    }
  });
});

test("fs: fs.promises.open decides before the handle exists", async () => {
  const dir = mkdtempSync(join(tmpdir(), "il-open-"));
  try {
    const blocked = join(dir, "blockme.txt");
    const allowed = join(dir, "ok.txt");
    fs.writeFileSync(blocked, "REAL CONTENT");
    fs.writeFileSync(allowed, "hello");
    const patch = patchFs({ engine: handleEngine() });
    try {
      assert.ok(patch.covered.includes("fs.open"));
      assert.ok(patch.covered.includes("fs.opendir"));

      await assert.rejects(fs.promises.open(blocked, "r"), BlockedError);

      const handle = await fs.promises.open(allowed, "r");
      try {
        assert.equal(await handle.readFile("utf8"), "hello");
      } finally {
        await handle.close();
      }

      // The blocked file is still readable through the sync API, which is not
      // guarded - proof the refusal above was the guard, not the disk.
      assert.equal(fs.readFileSync(blocked, "utf8"), "REAL CONTENT");
    } finally {
      patch.uninstall();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fs: callback-style open receives the refusal in its callback and a handle otherwise", async () => {
  const dir = mkdtempSync(join(tmpdir(), "il-open-cb-"));
  try {
    const blocked = join(dir, "blockme.txt");
    const allowed = join(dir, "ok.txt");
    fs.writeFileSync(blocked, "REAL CONTENT");
    fs.writeFileSync(allowed, "hello");
    const patch = patchFs({ engine: handleEngine() });
    try {
      await assert.rejects(openWith(fs.open, blocked, "r"), BlockedError);
      // The callback surface reports a numeric file descriptor, not a
      // `FileHandle`; the promise surface (above) hands back the handle.
      const fd = await openWith(fs.open, allowed, "r");
      assert.equal(typeof fd, "number");
      assert.ok(fd >= 0);
      fs.closeSync(fd);
    } finally {
      patch.uninstall();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fs: opendir decides before the directory is listed", async () => {
  const dir = mkdtempSync(join(tmpdir(), "il-opendir-"));
  try {
    const blocked = join(dir, "blockme");
    const allowed = join(dir, "ok");
    fs.mkdirSync(blocked);
    fs.mkdirSync(allowed);
    fs.writeFileSync(join(allowed, "a.txt"), "a");
    const patch = patchFs({ engine: handleEngine() });
    try {
      await assert.rejects(fs.promises.opendir(blocked), BlockedError);
      const listing = await fs.promises.opendir(allowed);
      const names: string[] = [];
      // `for await` closes the `Dir` when the iteration finishes.
      for await (const entry of listing) {
        names.push(entry.name);
      }
      assert.deepEqual(names, ["a.txt"]);
    } finally {
      patch.uninstall();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
