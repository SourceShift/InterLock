#!/usr/bin/env node
/**
 * A smoke number for the guarded round trip, JS side.
 *
 * R12 owns the methodology and the regression gate; this is the one figure the
 * sidecar needs from the Node.js half - what a policy decision costs an agent
 * that makes one tool call at a time. It times N guarded round trips (a real
 * socket, a real daemon) against a no-guard baseline (the same loop with no
 * daemon in it), so the delta is the guard and not the harness.
 *
 * Run after `npm run build`:
 *
 *     node bench/roundtrip.mjs
 *     N=5000 node bench/roundtrip.mjs
 */
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

import { RemoteEngine, probe, sensorEvent } from "../dist/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");
const ITERATIONS = Number(process.env["N"] ?? 2000);
const WARMUP = Math.min(100, Math.floor(ITERATIONS / 10));

const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

async function startDaemon() {
  const python = process.env["PYTHON"] ?? "python3";
  const dir = mkdtempSync(join("/tmp", "il-bench-"));
  const path = join(dir, "g.sock");
  const child = spawn(
    python,
    [
      "-m",
      "interlock.sidecar",
      "--rules",
      "interlock.testing.fixtures:CONFORMANCE_ENGINE",
      "--socket",
      path,
    ],
    { cwd: REPO_ROOT, stdio: ["ignore", "ignore", "pipe"] },
  );
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`daemon exited (${child.exitCode})\n${stderr}`);
    }
    if (await probe(path, 0.25)) {
      return { child, dir, path };
    }
    await sleep(20);
  }
  throw new Error(`daemon never came up\n${stderr}`);
}

async function stopDaemon(daemon) {
  if (daemon.child.exitCode === null) {
    await new Promise((done) => {
      daemon.child.once("exit", done);
      daemon.child.kill("SIGTERM");
      setTimeout(() => daemon.child.kill("SIGKILL"), 5_000).unref();
    });
  }
  rmSync(daemon.dir, { recursive: true, force: true });
}

/** The same loop with no daemon in it: the floor a guard cannot go below. */
async function baseline() {
  const event = sensorEvent({ action: "ping" });
  await Promise.resolve(event.action);
}

function report(label, ms, iterations) {
  const perCall = (ms * 1000) / iterations;
  const rate = iterations / (ms / 1000);
  console.log(
    `  ${label.padEnd(18)} ${perCall.toFixed(1).padStart(9)} µs/call   ${Math.round(rate).toLocaleString().padStart(12)} calls/s`,
  );
  return perCall;
}

async function main() {
  const daemon = await startDaemon();
  const engine = new RemoteEngine(daemon.path, { timeout: 5 });
  try {
    const event = sensorEvent({ action: "ping", args: {} });

    for (let i = 0; i < WARMUP; i++) {
      await engine.evaluate(event);
    }

    const guardedStart = performance.now();
    for (let i = 0; i < ITERATIONS; i++) {
      await engine.evaluate(event);
    }
    const guardedMs = performance.now() - guardedStart;

    for (let i = 0; i < WARMUP; i++) {
      await baseline();
    }
    const baselineStart = performance.now();
    for (let i = 0; i < ITERATIONS; i++) {
      await baseline();
    }
    const baselineMs = performance.now() - baselineStart;

    console.log(
      `\ninterlock-guard round trip (${ITERATIONS.toLocaleString()} calls, one reused connection)\n`,
    );
    const guardedPer = report("guarded", guardedMs, ITERATIONS);
    const baselinePer = report("no-guard baseline", baselineMs, ITERATIONS);
    console.log(
      `\n  guard overhead     ${(guardedPer - baselinePer).toFixed(1)} µs/call` +
        `   (${(guardedPer / baselinePer).toFixed(1)}x the baseline)\n`,
    );
  } finally {
    await engine.close();
    await stopDaemon(daemon);
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
