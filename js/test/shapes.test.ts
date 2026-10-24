/**
 * The projection helpers, as units: what a call's positional arguments become
 * for the policy, and what (if anything) a decision writes back.
 *
 * These are the two invariants the interceptors depend on:
 *
 * 1. **Only path-carrying names are projected.** `path`/`dest`/`target`/`file`
 *    become text (a `Buffer`/`Uint8Array` as UTF-8, a `URL` as a path or its
 *    `href`); a binary `data` payload is left exactly as it is.
 * 2. **Projection is event-only.** `applyMods` writes a field back only when the
 *    policy's value differs from the projected view, so an ALLOW hands the
 *    original `Buffer`/`URL` argument to the real call untouched.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { pathToFileURL } from "node:url";

import { applyMods, at, projectArgs } from "../src/effects.js";

test("projectArgs: a Buffer path becomes its UTF-8 string", () => {
  const projected = projectArgs(
    [Buffer.from("/tmp/secret.txt"), {}],
    [at("path", 0), at("options", 1)],
  );
  assert.equal(projected["path"], "/tmp/secret.txt");
  assert.deepEqual(projected["options"], {});
});

test("projectArgs: a file URL becomes a path, a non-file URL keeps its href", () => {
  const fileUrl = pathToFileURL("/tmp/secret.txt");
  assert.equal(
    projectArgs([fileUrl], [at("path", 0)])["path"],
    "/tmp/secret.txt",
  );

  const remote = new URL("https://example.test/x");
  // `fileURLToPath` would throw here; projection must not turn a legitimate
  // call into a fail-closed block.
  assert.equal(projectArgs([remote], [at("path", 0)])["path"], remote.href);
});

test("projectArgs: dest, target and file are path fields too", () => {
  for (const name of ["dest", "target", "file"]) {
    assert.equal(
      projectArgs([Buffer.from(`/tmp/${name}`)], [at(name, 0)])[name],
      `/tmp/${name}`,
    );
  }
});

test("projectArgs: a binary data field is not projected", () => {
  const payload = Buffer.from([0x00, 0xff, 0x10]);
  const projected = projectArgs(
    ["/tmp/out.bin", payload],
    [at("path", 0), at("data", 1)],
  );
  assert.equal(projected["path"], "/tmp/out.bin");
  assert.equal(projected["data"], payload, "write payload bytes must be untouched");
  assert.ok(Buffer.isBuffer(projected["data"]));
});

test("applyMods: a projected value is not written back, an actual rewrite is", () => {
  const original = Buffer.from("/tmp/secret.txt");
  const fields = [at("path", 0)];
  const projected = { path: "/tmp/secret.txt" };

  // ALLOW: the event value equals the projection, so the caller's Buffer stays.
  const untouched = applyMods([original], fields, { ...projected }, projected);
  assert.equal(untouched[0], original);
  assert.ok(Buffer.isBuffer(untouched[0]));

  // MODIFY: the policy's string differs, so it replaces the argument.
  const rewritten = applyMods([original], fields, { path: "/tmp/target.txt" }, projected);
  assert.equal(rewritten[0], "/tmp/target.txt");
});

test("applyMods: without a projected baseline the old write-back rule holds", () => {
  const out = applyMods(["a"], [at("path", 0)], { path: "b" });
  assert.deepEqual(out, ["b"]);
});
