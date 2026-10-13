/**
 * R19: tiered failure posture for the sidecar client, and the offline fallback
 * policy evaluator. The fallback files here are written by the Python sidecar's
 * own writer, so the two clients are checked against the same bytes.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { BlockedError, Verdict } from "../src/enforce.js";
import { sensorEvent } from "../src/event.js";
import { RemoteEngine } from "../src/client.js";
import { compileFallback, globToRegExp, readFallback, readKeyFile } from "../src/fallback.js";

const KEY_HEX = "ab".repeat(32);
const POLICY = {
  rules: [
    { id: "no-rm", verdict: "block", reason: "no rm", on: "run_shell",
      when: { arg: "cmd", startswith: "rm " } },
    { id: "ask-pay", verdict: "escalate", reason: "payment", when: { all: [
      { action: { glob: "pay_*" } }, { arg: "amount", gt: 100 }] } },
  ],
};

function pythonWrite(dir: string, policy: unknown): string {
  const policyFile = join(dir, "fallback-policy.json");
  writeFileSync(policyFile, JSON.stringify(policy));
  const out = join(dir, "guard.sock.fallback.json");
  const repo = join(process.cwd(), "..");
  execFileSync("python3", ["-c", `
import json, sys
sys.path.insert(0, ${JSON.stringify(repo)})
from interlock.sidecar.fallback import write_fallback
write_fallback(${JSON.stringify(out)}, json.load(open(${JSON.stringify(policyFile)})), bytes.fromhex(${JSON.stringify(KEY_HEX)}))
`]);
  return out;
}

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "il-fb-"));
}

test("a fallback file written by Python verifies and evaluates in Node", () => {
  const dir = tmp();
  const file = pythonWrite(dir, POLICY);
  const policy = readFallback(file, Buffer.from(KEY_HEX, "hex"));
  assert.equal(policy.rules, 2);
  const block = policy.evaluate(sensorEvent({ action: "run_shell", args: { cmd: "rm -rf x" } }));
  assert.equal(block.verdict, Verdict.BLOCK);
  assert.equal(block.attributed_to, "cmd");
  assert.equal(policy.evaluate(sensorEvent({ action: "other", args: { cmd: "rm x" } })).verdict, Verdict.ALLOW);
  assert.equal(policy.evaluate(sensorEvent({ action: "pay_card", args: { amount: 500 } })).verdict, Verdict.ESCALATE);
  assert.equal(policy.evaluate(sensorEvent({ action: "pay_card", args: { amount: 5 } })).verdict, Verdict.ALLOW);
});

test("tampered, wrong-key and stale fallback files are refused", () => {
  const dir = tmp();
  const file = pythonWrite(dir, POLICY);
  const key = Buffer.from(KEY_HEX, "hex");
  assert.throws(() => readFallback(file, Buffer.from("cd".repeat(32), "hex")), /does not verify/);
  assert.throws(() => readFallback(file, key, 60, Date.now() / 1000 + 3600), /stale/);
  const body = JSON.parse(readFileSync(file, "utf8"));
  body.policy = body.policy.replace("rm ", "zz ");
  writeFileSync(file, JSON.stringify(body));
  assert.throws(() => readFallback(file, key), /does not verify/);
  assert.throws(() => readFallback(join(dir, "missing.json"), key), /no fallback policy/);
});

test("the offline subset refuses what it cannot evaluate", () => {
  assert.throws(() => compileFallback({ rules: [{ id: "x", verdict: "modify", when: { action: "a" } }] }));
  assert.throws(() => compileFallback({ rules: [{ id: "x", verdict: "block", when: { intent: "pkg" } }] }));
  assert.throws(() => compileFallback({ rules: [{ id: "x", verdict: "block", when: { arg: "a", matches: "." } }] }));
  assert.throws(() => compileFallback({ rules: [] }));
});

test("glob follows fnmatchcase", () => {
  assert.ok(globToRegExp("mcp__github__*").test("mcp__github__create"));
  assert.ok(!globToRegExp("mcp__github__*").test("mcp__slack__x"));
  assert.ok(globToRegExp("file?.[!a-c]x").test("file1.dx"));
  assert.ok(!globToRegExp("file?.[!a-c]x").test("file1.bx"));
  assert.ok(globToRegExp("a.b").test("a.b") && !globToRegExp("a.b").test("axb"));
});

test("readKeyFile reads hex and raw keys", () => {
  const dir = tmp();
  writeFileSync(join(dir, "hex"), KEY_HEX + "\n");
  assert.equal(Buffer.from(readKeyFile(join(dir, "hex"))).toString("hex"), KEY_HEX);
  writeFileSync(join(dir, "raw"), "raw-secret\n");
  assert.equal(Buffer.from(readKeyFile(join(dir, "raw"))).toString(), "raw-secret");
});

const event = (cmd: string) => sensorEvent({ action: "run_shell", args: { cmd } });

test("unreachable deny (default) blocks", async () => {
  const engine = new RemoteEngine(join(tmp(), "nope.sock"));
  await assert.rejects(engine.evaluate(event("ls")), BlockedError);
});

test("unreachable allow lets calls through and says so every time", async () => {
  const messages: string[] = [];
  const engine = new RemoteEngine(join(tmp(), "nope.sock"), {
    unreachable: "allow", onFallback: (m) => messages.push(m) });
  assert.equal((await engine.evaluate(event("ls"))).verdict, Verdict.ALLOW);
  await engine.evaluate(event("pwd"));
  assert.equal(messages.length, 2);
  assert.equal(engine.fallbacks, 2);
});

test("unreachable degraded uses the signed fallback, and denies without one", async () => {
  const dir = tmp();
  pythonWrite(dir, POLICY);
  const messages: string[] = [];
  const engine = new RemoteEngine(join(dir, "guard.sock"), {
    unreachable: "degraded", fallbackKey: Buffer.from(KEY_HEX, "hex"), onFallback: (m) => messages.push(m) });
  assert.equal((await engine.evaluate(event("ls"))).verdict, Verdict.ALLOW);
  const blocked = await engine.evaluate(event("rm -rf x"));
  assert.equal(blocked.verdict, Verdict.BLOCK);
  assert.equal(blocked.policy_id, "fallback/no-rm");
  assert.equal(messages.length, 2);
  const bare = new RemoteEngine(join(tmp(), "guard.sock"), {
    unreachable: "degraded", fallbackKey: Buffer.from(KEY_HEX, "hex"), onFallback: () => undefined });
  await assert.rejects(bare.evaluate(event("ls")), /fallback policy is unusable/);
});

test("degraded without a key is a configuration error", () => {
  assert.throws(() => new RemoteEngine("/x.sock", { unreachable: "degraded" }), TypeError);
});
