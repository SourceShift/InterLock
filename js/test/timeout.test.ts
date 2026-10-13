/**
 * `RemoteEngine` timeouts: a hung daemon must block a call, not hang it, and an
 * idle connection must not be mistaken for a hung one.
 */
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import * as net from "node:net";
import { join } from "node:path";
import test from "node:test";

import { DEFAULT_TIMEOUT_SECONDS, RemoteEngine } from "../src/client.js";
import { BlockedError, Verdict } from "../src/enforce.js";
import { sensorEvent } from "../src/event.js";
import { delay, spawnDaemon } from "./harness.js";

/** A server that accepts connections and never answers: a hung daemon. */
async function hungDaemon(): Promise<{ path: string; stop: () => Promise<void> }> {
  const dir = mkdtempSync(join("/tmp", "il-"));
  const path = join(dir, "g.sock");
  const held: net.Socket[] = [];
  const server = net.createServer((socket) => {
    held.push(socket);
    socket.on("error", () => undefined);
  });
  await new Promise<void>((done) => server.listen(path, done));
  return {
    path,
    stop: async () => {
      for (const socket of held) {
        socket.destroy();
      }
      await new Promise<void>((done) => server.close(() => done()));
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

test("the default timeout is DEFAULT_TIMEOUT_SECONDS, and null disables it", () => {
  assert.equal(DEFAULT_TIMEOUT_SECONDS, 5);
  assert.equal(new RemoteEngine("/nonexistent.sock").timeout, 5);
  assert.equal(new RemoteEngine("/nonexistent.sock", {}).timeout, 5);
  assert.equal(new RemoteEngine("/nonexistent.sock", { timeout: 2 }).timeout, 2);
  assert.equal(new RemoteEngine("/nonexistent.sock", { timeout: null }).timeout, null);
});

test("fail-closed: a daemon that never replies blocks the call after the timeout", async () => {
  const hung = await hungDaemon();
  const engine = new RemoteEngine(hung.path, { timeout: 0.3 });
  try {
    const started = Date.now();
    const err = await engine
      .evaluate(sensorEvent({ action: "ping" }))
      .then(() => null)
      .catch((caught: unknown) => caught);
    const elapsed = Date.now() - started;
    assert.ok(err instanceof BlockedError, "expected a BlockedError");
    const blocked = err as BlockedError;
    assert.equal(blocked.decision.verdict, Verdict.BLOCK);
    assert.match(blocked.decision.reason, /no reply within 0\.3s/);
    assert.ok(elapsed >= 250, `blocked too early (${elapsed}ms)`);
    assert.ok(elapsed < 3_000, `blocked too late (${elapsed}ms)`);
  } finally {
    await engine.close();
    await hung.stop();
  }
});

test("an idle gap longer than the timeout does not block the next call", async () => {
  const daemon = await spawnDaemon();
  const engine = new RemoteEngine(daemon.path, { timeout: 0.3 });
  try {
    const first = await engine.evaluate(sensorEvent({ action: "ping" }));
    assert.equal(first.verdict, Verdict.ALLOW);

    // Longer than the timeout, with the connection open and nothing pending.
    await delay(700);

    const second = await engine.evaluate(sensorEvent({ action: "ping" }));
    assert.equal(second.verdict, Verdict.ALLOW);
    daemon.assertAlive("the idle-gap test");
  } finally {
    await engine.close();
    await daemon.stop();
  }
});
