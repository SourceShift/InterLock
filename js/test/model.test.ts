/**
 * The model-SDK tool seam, over the conformance engine.
 *
 * A model-driven agent (Anthropic, OpenAI, a home-grown loop) executes whatever
 * `tool_use` the model emitted through a tool runner or a tool map. These tests
 * pin the two shapes against the same rules Python's LangChain twin uses:
 *
 * - a BLOCK stops the tool **before it runs** (a call counter proves it);
 * - a call-side MODIFY rewrites the arguments the tool sees;
 * - a result-phase MODIFY replaces what the caller receives;
 * - an ALLOW returns the tool's own result object, never the `{result: ...}`
 *   view the policy was shown;
 * - a bare (non-object) argument and an argument-less call both pass through;
 * - `guardToolRunner` and `guardToolMap` agree on the same decisions.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { BlockedError } from "../src/enforce.js";
import { guardToolMap, guardToolRunner } from "../src/model.js";
import { CONFORMANCE_RULES, withEngine } from "./harness.js";

test("model: a blocked tool never runs", async () => {
  await withEngine(CONFORMANCE_RULES, async ({ engine }) => {
    let calls = 0;
    const tools = guardToolMap(
      {
        rm_rf: async (_args: Record<string, unknown>) => {
          calls += 1;
          return "ran";
        },
      },
      { engine },
    );
    await assert.rejects(tools.rm_rf({ target: "/" }), BlockedError);
    assert.equal(calls, 0, "the blocked tool must not have been called");
  });
});

test("model: a call-side MODIFY rewrites the arguments the tool sees", async () => {
  await withEngine(CONFORMANCE_RULES, async ({ engine }) => {
    const seen: Array<Record<string, unknown>> = [];
    const tools = guardToolMap(
      {
        write_file: async (args: Record<string, unknown>) => {
          seen.push(args);
          return "ok";
        },
      },
      { engine },
    );
    assert.equal(await tools.write_file({ path: "/etc/hosts", mode: "w" }), "ok");
    assert.deepEqual(seen[0], { path: "/tmp/quarantine", mode: "w" });
  });
});

test("model: a result-phase MODIFY replaces what the caller receives", async () => {
  await withEngine(CONFORMANCE_RULES, async ({ engine }) => {
    const fetchTool = guardToolMap(
      { fetch_url: async (_args: Record<string, unknown>) => "the secret token" },
      { engine },
    );
    assert.equal(await fetchTool.fetch_url({}), "redacted");

    const dictTool = guardToolMap(
      {
        read_dict: async (_args: Record<string, unknown>) => ({
          title: "a",
          secret: "s",
        }),
      },
      { engine },
    );
    assert.deepEqual(await dictTool.read_dict({}), { title: "a" });
  });
});

test("model: ALLOW returns the tool's own result, not a wrapper", async () => {
  await withEngine(CONFORMANCE_RULES, async ({ engine }) => {
    const original = { anything: 1 };
    const tools = guardToolMap(
      { ping: async (_args: Record<string, unknown>) => original },
      { engine },
    );
    assert.equal(await tools.ping({}), original);
  });
});

test("model: a bare argument is shown as input and handed back unchanged", async () => {
  await withEngine(CONFORMANCE_RULES, async ({ engine }) => {
    const seen: unknown[][] = [];
    const tools = guardToolMap(
      {
        echo: async (...args: unknown[]) => {
          seen.push(args);
          return "ok";
        },
      },
      { engine },
    );
    assert.equal(await tools.echo("hi"), "ok");
    assert.deepEqual(seen[0], ["hi"], "a non-object argument passes through as-is");
    assert.equal(await tools.echo(), "ok");
    assert.deepEqual(seen[1], [], "an argument-less call reaches the tool with no args");
  });
});

test("model: guardToolRunner matches guardToolMap", async () => {
  await withEngine(CONFORMANCE_RULES, async ({ engine }) => {
    const calls: Array<[string, Record<string, unknown>]> = [];
    const run = async (
      name: string,
      args: Record<string, unknown>,
    ): Promise<string> => {
      calls.push([name, args]);
      return "ran";
    };
    const guarded = guardToolRunner(run, { engine });
    await assert.rejects(guarded("rm_rf", {}), BlockedError);
    assert.equal(calls.length, 0, "the blocked tool never ran");
    assert.equal(await guarded("write_file", { path: "/etc/hosts" }), "ran");
    assert.deepEqual(calls[0], ["write_file", { path: "/tmp/quarantine" }]);
  });
});
