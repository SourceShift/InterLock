/**
 * The interceptor against the REAL `@modelcontextprotocol/sdk`, not a stub.
 *
 * The unit tests prove the logic against a hand-rolled session; this proves the
 * duck-typing claim - that `guardMcpSession` wraps an actual `Client` - over a
 * real in-memory transport, with a real tool call that the guard rewrites and a
 * real one it blocks before the server ever hears of it.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { RemoteEngine } from "../src/client.js";
import { BlockedError } from "../src/enforce.js";
import { guardMcpSession } from "../src/mcp.js";
import { spawnDaemon } from "./harness.js";

/** A tiny MCP server exposing one `echo` tool, recording what it is asked. */
async function makeServer(): Promise<{ server: Server; calls: string[] }> {
  const server = new Server(
    { name: "echo-server", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  const calls: string[] = [];
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "echo",
        description: "echo the arguments back",
        inputSchema: {
          type: "object",
          properties: { text: { type: "string" } },
        },
      },
    ],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    calls.push(request.params.name);
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(request.params.arguments ?? {}),
        },
      ],
    };
  });
  return { server, calls };
}

test("guardMcpSession wraps a real SDK Client: passes a clean call, blocks a denied one", async () => {
  const daemon = await spawnDaemon();
  const engine = new RemoteEngine(daemon.path, { timeout: 5 });
  const { server, calls } = await makeServer();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "guard-test", version: "1.0.0" });
  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);
  try {
    guardMcpSession(client, { engine });

    const result = await client.callTool({
      name: "echo",
      arguments: { text: "hi" },
    });
    assert.ok(Array.isArray(result.content) && result.content.length > 0);
    assert.deepEqual(calls, ["echo"]);

    await assert.rejects(
      client.callTool({ name: "rm_rf", arguments: {} }),
      BlockedError,
    );
    assert.deepEqual(calls, ["echo"], "the blocked call never reached the server");
  } finally {
    await client.close();
    await server.close();
    await engine.close();
    await daemon.stop();
  }
});
