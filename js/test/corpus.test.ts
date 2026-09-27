/**
 * Replay the language-neutral corpus through a real daemon.
 *
 * This is R13's acceptance criterion made executable: the same file the Python
 * suite replays, replayed by the Node.js client, so "same policy, same
 * decision" stops being an assertion. The JS side never evaluates anything - it
 * encodes the cases, honours the verdicts, and refuses the negatives.
 *
 * The identity check runs first, because replaying a stale or foreign file
 * would pass vacuously.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { RemoteEngine } from "../src/client.js";
import { BlockedError } from "../src/enforce.js";
import { MAX_LINE } from "../src/wire.js";
import {
  CASES,
  CORPUS,
  NEGATIVES,
  eventOf,
  materialiseModifiedResult,
  sameValue,
} from "./corpus.js";
import type { CorpusCase } from "./corpus.js";
import { CONFORMANCE_RULES, spawnDaemon, sendRaw } from "./harness.js";

test("the corpus names the version and engine the daemon must serve", () => {
  assert.equal(CORPUS.corpus_version, 1);
  assert.equal(CORPUS.rules, "interlock.testing.fixtures:CONFORMANCE_ENGINE");
  assert.equal(CORPUS.rules, CONFORMANCE_RULES);
  assert.ok(CASES.length > 0, "the corpus must carry cases");
});

async function checkCase(engine: RemoteEngine, testCase: CorpusCase): Promise<void> {
  const { name, expect } = testCase;
  const event = eventOf(testCase.event);

  if (expect.error !== undefined) {
    // The rewrite has no JSON form, so the daemon cannot say what it decided
    // and says so; the client turns that into a block.
    const caught = await engine
      .evaluate(event)
      .then(() => null)
      .catch((err: unknown) => err);
    assert.ok(caught instanceof BlockedError, `${name}: expected a block`);
    assert.ok(
      (caught as BlockedError).decision.reason.includes(expect.error),
      `${name}: reason "${(caught as BlockedError).decision.reason}" must name ${expect.error}`,
    );
    return;
  }

  const decision = await engine.evaluate(event);
  assert.equal(decision.verdictName, expect.verdict, `${name}: verdict`);
  assert.equal(decision.reason, expect.reason ?? "", `${name}: reason`);
  assert.equal(decision.policy_id, expect.policy_id ?? null, `${name}: policy_id`);
  assert.equal(decision.attributed_to, expect.attributed_to ?? null, `${name}: attributed_to`);
  assert.ok(
    sameValue(decision.modified_args, expect.modified_args ?? null),
    `${name}: modified_args ${JSON.stringify(decision.modified_args)} != ${JSON.stringify(expect.modified_args)}`,
  );
  const wanted = materialiseModifiedResult(expect.modified_result ?? null);
  assert.ok(
    sameValue(decision.modified_result, wanted),
    `${name}: modified_result ${JSON.stringify(decision.modified_result)} != ${JSON.stringify(wanted)}`,
  );
}

test("every corpus case is honoured by the daemon", async (t) => {
  const daemon = await spawnDaemon();
  const engine = new RemoteEngine(daemon.path, { timeout: 5 });
  try {
    for (const testCase of CASES) {
      await t.test(testCase.name, async () => {
        await checkCase(engine, testCase);
      });
    }
    daemon.assertAlive("the corpus replay");
  } finally {
    await engine.close();
    await daemon.stop();
  }
});

test("every frame negative is refused with the daemon's own code", async (t) => {
  const daemon = await spawnDaemon();
  try {
    for (const negative of NEGATIVES) {
      if (negative.kind !== "frame") {
        continue;
      }
      await t.test(negative.name, async () => {
        const reply = await sendRaw(daemon.path, negative.line ?? "");
        const error = reply["error"] as { code?: string } | undefined;
        assert.equal(error?.code, negative.error, negative.name);
      });
    }
    daemon.assertAlive("the negatives replay");
  } finally {
    await daemon.stop();
  }
});

test("the oversized negative is refused against the daemon's real cap", async () => {
  const daemon = await spawnDaemon();
  try {
    const negative = NEGATIVES.find((n) => n.kind === "oversized");
    assert.ok(negative, "the corpus must carry an oversized negative");
    // A real write past the limit: the point is the daemon's cap, not a
    // pre-check the client would do first.
    const reply = await sendRaw(daemon.path, "x".repeat(MAX_LINE + 1));
    const error = reply["error"] as { code?: string } | undefined;
    assert.equal(error?.code, negative.error);
    daemon.assertAlive("the oversized frame");
  } finally {
    await daemon.stop();
  }
});
