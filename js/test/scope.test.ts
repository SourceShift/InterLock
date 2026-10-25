/**
 * A client that pins the scope document it expects - R29's Node.js half.
 *
 * The daemon serves per-principal decisions from the scope document it
 * published. A client that presents that same signed envelope is decided (and
 * recorded) under it; a client pinning a *different* well-signed envelope is
 * refused with `scope_mismatch` rather than quietly decided under the daemon's
 * scope set. The mismatch case is what proves the envelope is sent at all: a
 * client that sent nothing would be served a verdict.
 *
 * The daemon here is the real CLI (`spawnDaemon`), so the boundary is the one a
 * deployment has: a signed file on disk, a unix socket, and Python on the far
 * end.
 */
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import { RemoteEngine } from "../src/client.js";
import { BlockedError, Verdict } from "../src/enforce.js";
import { sensorEvent } from "../src/event.js";
import {
  WireError,
  canonical,
  readScopeEnvelope,
  scopeMac,
  verifyScopeEnvelope,
} from "../src/wire.js";
import { Daemon, spawnDaemon } from "./harness.js";

/** 32 bytes as 64 hex characters - the key-file format `readKeyFile` accepts. */
const KEY_HEX = "5c".repeat(32);
const KEY = new Uint8Array(Buffer.from(KEY_HEX, "hex"));
const SCOPE_RULES = "tests.fixtures.rules:rules";

function scratch(): string {
  return mkdtempSync(join("/tmp", "il-scope-"));
}

/** One signed envelope over the fixture's document. */
function envelope(writtenAt: number): Record<string, unknown> {
  // Same message the Python `scope_envelope` signs; the document's content is
  // irrelevant to an identity test, only the signed bytes are.
  const policy = canonical({ version: 1, bindings: {}, default_scope: [] });
  return { version: 1, written_at: writtenAt, policy, mac: scopeMac(KEY, writtenAt, policy) };
}

function writeEnvelope(dir: string, name: string, body: Record<string, unknown>): string {
  const path = join(dir, name);
  writeFileSync(path, canonical(body));
  return path;
}

async function withScopedDaemon(
  dir: string,
  body: (daemon: Daemon, scope: string) => Promise<void>,
): Promise<void> {
  const keyFile = join(dir, "key");
  writeFileSync(keyFile, KEY_HEX);
  const scope = join(dir, "scope.json");
  const daemon = await spawnDaemon({
    rules: SCOPE_RULES,
    scopeDocument: scope,
    keyFile,
  });
  try {
    await body(daemon, scope);
    daemon.assertAlive("the body of the test");
  } finally {
    await daemon.stop();
  }
}

test("the client presents the published document and is decided under it", async () => {
  const dir = scratch();
  try {
    await withScopedDaemon(dir, async (daemon, scope) => {
      const engine = new RemoteEngine(daemon.path, {
        timeout: 5,
        scopeFile: scope,
        scopeKey: KEY,
      });
      try {
        assert.notEqual(engine.scope, null);
        // acme/agent1 may run ls and may not run rm; acme may run pwd.
        const allowed = await engine.evaluate(
          sensorEvent({ action: "run_shell", args: { cmd: "ls" }, principal: "acme/agent1" }),
        );
        assert.equal(allowed.verdict, Verdict.ALLOW);
        const blocked = await engine.evaluate(
          sensorEvent({ action: "run_shell", args: { cmd: "rm -rf /" }, principal: "acme/agent1" }),
        );
        assert.equal(blocked.verdict, Verdict.BLOCK);
        const parent = await engine.evaluate(
          sensorEvent({ action: "run_shell", args: { cmd: "pwd" }, principal: "acme" }),
        );
        assert.equal(parent.verdict, Verdict.ALLOW);
      } finally {
        await engine.close();
      }
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a client pinning a different document is refused, not decided", async () => {
  const dir = scratch();
  try {
    const other = writeEnvelope(dir, "other.json", envelope(1_600_000_000));
    await withScopedDaemon(dir, async (daemon) => {
      const engine = new RemoteEngine(daemon.path, {
        timeout: 5,
        scopeFile: other,
        scopeKey: KEY,
      });
      try {
        const err = await engine
          .evaluate(sensorEvent({ action: "run_shell", args: { cmd: "ls" }, principal: "acme/agent1" }))
          .then(() => null)
          .catch((caught: unknown) => caught);
        assert.ok(err instanceof BlockedError, "expected a BlockedError");
        assert.match((err as BlockedError).decision.reason, /scope_mismatch/);
      } finally {
        await engine.close();
      }
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a document signed with another key is refused at construction", () => {
  const dir = scratch();
  try {
    const path = writeEnvelope(dir, "foreign.json", envelope(1_700_000_000));
    assert.throws(
      () => new RemoteEngine(join(dir, "never.sock"), { scopeFile: path, scopeKey: new Uint8Array(32) }),
      (err: unknown) => err instanceof WireError && err.code === "unauthenticated_scope",
    );
    assert.throws(
      () => new RemoteEngine(join(dir, "never.sock"), { scopeFile: join(dir, "absent.json"), scopeKey: KEY }),
      (err: unknown) => err instanceof WireError && err.code === "unauthenticated_scope",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a scope file without a key, or a key without a file, is a TypeError", () => {
  const dir = scratch();
  try {
    const path = writeEnvelope(dir, "scope.json", envelope(1_700_000_000));
    assert.throws(
      () => new RemoteEngine(join(dir, "never.sock"), { scopeFile: path }),
      (err: unknown) => err instanceof TypeError && /scopeKey/.test((err as Error).message),
    );
    assert.throws(
      () => new RemoteEngine(join(dir, "never.sock"), { scopeKey: KEY }),
      (err: unknown) => err instanceof TypeError && /scopeFile/.test((err as Error).message),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("readScopeEnvelope verifies and returns the envelope", () => {
  const dir = scratch();
  try {
    const signed = envelope(1_700_000_000);
    const path = writeEnvelope(dir, "scope.json", signed);
    assert.deepEqual(readScopeEnvelope(path, KEY), signed);
    assert.equal(verifyScopeEnvelope(signed, KEY), signed["policy"]);
    assert.equal(readFileSync(path, "utf8"), canonical(signed));
    const tampered = { ...signed, mac: "0".repeat(64) };
    assert.throws(
      () => verifyScopeEnvelope(tampered, KEY),
      (err: unknown) => err instanceof WireError && err.code === "unauthenticated_scope",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
