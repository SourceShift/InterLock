/**
 * `RemoteEngine` against a real daemon - and, most importantly, without one.
 *
 * The fail-closed contract is the whole availability story: an agent that
 * cannot reach the daemon does not act. So the first test here is not a happy
 * path. It is the one that proves a missing daemon blocks rather than allows.
 */
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import { RemoteEngine, probe } from "../src/client.js";
import { BlockedError, Verdict } from "../src/enforce.js";
import { sensorEvent } from "../src/event.js";
import type { Decision } from "../src/enforce.js";
import { Daemon, delay, spawnDaemon } from "./harness.js";

async function withDaemon(
  body: (daemon: Daemon, engine: RemoteEngine) => Promise<void>,
): Promise<void> {
  const daemon = await spawnDaemon();
  const engine = new RemoteEngine(daemon.path, { timeout: 5 });
  try {
    await body(daemon, engine);
    daemon.assertAlive("the body of the test");
  } finally {
    await engine.close();
    await daemon.stop();
  }
}

function deadPath(): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(join("/tmp", "il-"));
  return { path: join(dir, "g.sock"), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("fail-closed: with no daemon listening, evaluate blocks", async () => {
  const { path, cleanup } = deadPath();
  const engine = new RemoteEngine(path, { timeout: 5 });
  try {
    const err = await engine
      .evaluate(sensorEvent({ action: "ping" }))
      .then(() => null)
      .catch((caught: unknown) => caught);
    assert.ok(err instanceof BlockedError, "expected a BlockedError");
    const blocked = err as BlockedError;
    assert.equal(blocked.action, "ping");
    assert.equal(blocked.decision.verdict, Verdict.BLOCK);
    // A reason a human can act on: it names the socket and says it was unreachable.
    assert.match(blocked.decision.reason, /unreachable/);
    assert.ok(blocked.decision.reason.includes(path));
  } finally {
    await engine.close();
    cleanup();
  }
});

test("fail-closed: a daemon that dies mid-session blocks the next call", async () => {
  const daemon = await spawnDaemon();
  const engine = new RemoteEngine(daemon.path, { timeout: 5 });
  try {
    const first = await engine.evaluate(sensorEvent({ action: "ping" }));
    assert.equal(first.verdict, Verdict.ALLOW);

    await daemon.stop();
    // The daemon is gone; the reused connection is dead. The next call must
    // block, not reconnect its way into a silent allow.
    const err = await engine
      .evaluate(sensorEvent({ action: "ping" }))
      .then(() => null)
      .catch((caught: unknown) => caught);
    assert.ok(err instanceof BlockedError);
  } finally {
    await engine.close();
    await daemon.stop();
  }
});

test("a decision survives the round trip: verdict, reason, policy_id, attributed_to", async () => {
  await withDaemon(async (_daemon, engine) => {
    const decision = await engine.evaluate(
      sensorEvent({ action: "read_file", args: { path: "/etc/passwd" } }),
    );
    assert.equal(decision.verdict, Verdict.BLOCK);
    assert.equal(decision.reason, "etc is off limits");
    assert.equal(decision.policy_id, "p.no-etc");
    assert.equal(decision.attributed_to, "path");
    // The guard's own claim: attributed_to is the argument NAME, and the value
    // never appears in a field of the decision.
    assert.ok(!JSON.stringify(decision).includes("/etc/passwd"));
  });
});

test("a MODIFY rewrite crosses the wire", async () => {
  await withDaemon(async (_daemon, engine) => {
    const decision = await engine.evaluate(
      sensorEvent({ action: "write_file", args: { path: "/etc/hosts" } }),
    );
    assert.equal(decision.verdict, Verdict.MODIFY);
    assert.deepEqual(decision.modified_args, { path: "/tmp/quarantine" });
  });
});

test("probe tells a live daemon from a stale socket path", async () => {
  const { path, cleanup } = deadPath();
  try {
    assert.equal(await probe(path), false);
  } finally {
    cleanup();
  }
  await withDaemon(async (daemon) => {
    assert.equal(await probe(daemon.path), true);
  });
});

test("close drops the connection, and the next call reconnects", async () => {
  await withDaemon(async (_daemon, engine) => {
    assert.equal((await engine.evaluate(sensorEvent({ action: "ping" }))).verdict, Verdict.ALLOW);
    await engine.close();
    assert.equal((await engine.evaluate(sensorEvent({ action: "ping" }))).verdict, Verdict.ALLOW);
  });
});

test("concurrency: parallel calls share one connection and all decide correctly", async () => {
  await withDaemon(async (daemon, engine) => {
    const inputs: Array<[string, Record<string, unknown>, Verdict]> = [
      ["ping", {}, Verdict.ALLOW],
      ["read_file", { path: "/etc/passwd" }, Verdict.BLOCK],
      ["write_file", { path: "/etc/hosts" }, Verdict.MODIFY],
      ["rm_rf", {}, Verdict.BLOCK],
    ];
    const calls: Promise<Decision>[] = [];
    for (let i = 0; i < 40; i++) {
      const [action, args, wanted] = inputs[i % inputs.length]!;
      calls.push(
        engine.evaluate(sensorEvent({ action, args: { ...args } })).then((decision) => {
          assert.equal(decision.verdict, wanted, `${action} (#${i})`);
          return decision;
        }),
      );
    }
    await Promise.all(calls);
    // The daemon is still serving after the burst.
    daemon.assertAlive("the concurrent burst");
    await delay(10);
    assert.equal((await engine.evaluate(sensorEvent({ action: "ping" }))).verdict, Verdict.ALLOW);
  });
});
