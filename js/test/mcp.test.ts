/**
 * The MCP interceptor, over a real daemon running the conformance engine.
 *
 * The asymmetries the Python interceptor has are the ones worth pinning, since
 * they are the ones a "cleaner" port would quietly change:
 *
 * - the call side MERGES `modified_args`; the result side REPLACES the whole
 *   result;
 * - the `{result: ...}` wrapper is a policy-visible view only - on ALLOW the
 *   caller gets the ORIGINAL object back, never the wrapper;
 * - a `null` replacement means "no replacement", so even a MODIFY can hand back
 *   what the tool returned;
 * - `monitor` never intervenes on a policy verdict - but an unreachable daemon
 *   is not a policy verdict, so it still blocks.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { RemoteEngine } from "../src/client.js";
import { BlockedError, Verdict } from "../src/enforce.js";
import { enforceToolCall, enforceToolResult, guardMcpSession } from "../src/mcp.js";
import type { McpSession } from "../src/mcp.js";
import type { Daemon } from "./harness.js";
import { spawnDaemon } from "./harness.js";

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

test("call side: ALLOW returns an equal copy and never mutates the caller's object", async () => {
  await withDaemon(async (_daemon, engine) => {
    const original = { path: "/tmp/notes" };
    const safe = await enforceToolCall("ping", original, { engine });
    assert.deepEqual(safe, { path: "/tmp/notes" });
    assert.notEqual(safe, original, "the returned object must be a copy");
    assert.deepEqual(original, { path: "/tmp/notes" });
  });
});

test("call side: BLOCK rejects with the whole decision", async () => {
  await withDaemon(async (_daemon, engine) => {
    const err = await enforceToolCall(
      "read_file",
      { path: "/etc/passwd" },
      { engine },
    )
      .then(() => null)
      .catch((caught: unknown) => caught);
    assert.ok(err instanceof BlockedError);
    const blocked = err as BlockedError;
    assert.equal(blocked.action, "read_file");
    assert.equal(blocked.decision.verdict, Verdict.BLOCK);
    assert.equal(blocked.decision.attributed_to, "path");
    assert.equal(blocked.decision.policy_id, "p.no-etc");
  });
});

test("call side: MODIFY merges modified_args into a copy", async () => {
  await withDaemon(async (_daemon, engine) => {
    const original = { path: "/etc/hosts", mode: "w" };
    const safe = await enforceToolCall("write_file", original, { engine });
    assert.deepEqual(safe, { path: "/tmp/quarantine", mode: "w" });
    assert.deepEqual(original, { path: "/etc/hosts", mode: "w" });
  });
});

test("result side: MODIFY replaces the whole result, dict or not", async () => {
  await withDaemon(async (_daemon, engine) => {
    const stripped = await enforceToolResult(
      "read_dict",
      { title: "a", secret: "s" },
      { engine },
    );
    assert.deepEqual(stripped, { title: "a" });

    const redacted = await enforceToolResult("fetch_url", "token secret", { engine });
    assert.equal(redacted, "redacted");
  });
});

test("result side: ALLOW returns the ORIGINAL value - the wrapper must not leak", async () => {
  await withDaemon(async (_daemon, engine) => {
    const dictResult = { anything: 1 };
    const returnedDict = await enforceToolResult("ping", dictResult, { engine });
    assert.equal(returnedDict, dictResult, "the original reference, not a copy");

    const scalar = 42;
    const returnedScalar = await enforceToolResult("ping", scalar, { engine });
    assert.equal(returnedScalar, 42, "not the {result: 42} view");
    assert.notDeepEqual(returnedScalar, { result: 42 });
  });
});

test("result side: a null replacement means no replacement", async () => {
  await withDaemon(async (_daemon, engine) => {
    const original = { ignored: "still here" };
    const returned = await enforceToolResult("read_null", original, { engine });
    assert.equal(returned, original, "MODIFY with a null replacement leaves the result alone");
  });
});

test("result side: bytes and sets arrive as codec values, not lossy reprs", async () => {
  await withDaemon(async (_daemon, engine) => {
    const bytes = await enforceToolResult("read_binary", {}, { engine });
    assert.ok(Buffer.isBuffer(bytes));
    assert.ok((bytes as Buffer).equals(Buffer.from([0x00, 0x01, 0xff])));

    const set = await enforceToolResult("read_set", {}, { engine });
    assert.deepEqual(set, [1, 2, 3]);
  });
});

test("the phase partition is observable from the caller's side", async () => {
  await withDaemon(async (_daemon, engine) => {
    // The same action name, judged by side: the call-side rule fires on the
    // call and stays silent on the result.
    await assert.rejects(
      enforceToolCall("read_file", { path: "/etc/passwd" }, { engine }),
      BlockedError,
    );
    const passed = await enforceToolResult(
      "read_file",
      { path: "/etc/passwd" },
      { engine },
    );
    assert.deepEqual(passed, { path: "/etc/passwd" });
  });
});

test("monitor: a policy verdict is recorded, not enforced", async () => {
  await withDaemon(async (_daemon, engine) => {
    const safe = await enforceToolCall("rm_rf", { target: "/" }, {
      engine,
      enforcement: "monitor",
    });
    assert.deepEqual(safe, { target: "/" });
  });
});

test("monitor is not exempt from an unreachable daemon", async () => {
  const daemon = await spawnDaemon();
  const engine = new RemoteEngine(daemon.path, { timeout: 5 });
  await daemon.stop();
  // read_opaque is the rule whose rewrite has no JSON form: the daemon answers
  // with an error frame, which is an infrastructure failure, not a verdict.
  await assert.rejects(
    enforceToolResult("read_opaque", {}, { engine, enforcement: "monitor" }),
    BlockedError,
  );
});

test("guardMcpSession: rewrites in place, preserves _meta, and blocks before effect", async () => {
  await withDaemon(async (_daemon, engine) => {
    const seen: Array<Record<string, unknown>> = [];
    const session: McpSession = {
      callTool: async (params: {
        name: string;
        arguments?: Record<string, unknown>;
        _meta?: unknown;
      }) => {
        seen.push({
          name: params.name,
          arguments: params.arguments,
          meta: params._meta,
        });
        return { ok: true };
      },
    };
    guardMcpSession(session, { engine });

    const out = await session.callTool({
      name: "write_file",
      arguments: { path: "/etc/hosts" },
      _meta: { progressToken: "t1" },
    });
    assert.deepEqual(out, { ok: true });
    assert.equal(seen.length, 1);
    assert.deepEqual(seen[0]?.["arguments"], { path: "/tmp/quarantine" });
    assert.deepEqual(seen[0]?.["meta"], { progressToken: "t1" });

    await assert.rejects(
      session.callTool({ name: "rm_rf", arguments: {} }),
      BlockedError,
    );
    assert.equal(seen.length, 1, "the blocked call never reached the server");
  });
});
