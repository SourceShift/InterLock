# interlock-guard (Node.js)

Guard a Node.js agent's MCP tool calls with the **same policy engine** the Python
[`interlock`](../README.md) SDK uses. The JS side enforces; a Python sidecar
decides.

This is not a port. There is one engine, one set of rules, one policy — the
Python one. A `interlock-sidecar` process owns it and answers a narrow RPC over a
unix socket; this package speaks that wire and blocks an outbound tool call
*before* it reaches the server, using the verdict that process returns. Nothing
about policy crosses the language boundary, and there is no second implementation
to drift.

## Before you install: this package needs a daemon

**Fail-closed is the whole contract, so read this first.** There is no bundled
engine. If the daemon is not running — or not reachable, or it dies mid-session —
**every guarded call is denied** with a `BlockedError`. Not a warning, not a
pass-through, not a special case a caller has to know about: an agent with no
daemon **does not act at all**.

That includes `monitor` mode. An unreachable daemon is an *infrastructure
failure*, not a policy verdict, so it is not downgraded into a silent allow.

This is the deployment trade, stated rather than hidden: a Python process must be
deployed beside the JS agent, and "is the daemon up?" becomes a hard availability
dependency. If that trade is wrong for you, this package is wrong for you.

## Install

```bash
npm install interlock-guard
```

Not yet published to npm; from the monorepo it builds in place (see
[Development](#development)). Requires Node ≥20 and the Python `interlock`
package for the daemon — `pip install interlock-guard`.

Zero runtime dependencies. `tsc` is the only build tool and `node:test` the only
test runner.

## Start the daemon

The daemon ships in the Python package:

```bash
interlock-sidecar \
  --rules my_service.policies:RULES \
  --socket /tmp/il-guard.sock
```

`--rules` is a `module:attribute` naming the rule set to load. A non-empty rule
set is **required**: `get_engine()` lazily *creates* an empty engine, and an empty
engine allows everything, so inheriting that default would be a guard that looks
healthy while enforcing nothing. The socket is created `0600` inside a `0700`
directory; the path is part of the trust boundary.

## Quickstart

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { BlockedError, RemoteEngine, guardMcpSession } from "interlock-guard";

const engine = new RemoteEngine("/tmp/il-guard.sock", { timeout: 5 });
const client = new Client({ name: "my-agent", version: "1.0.0" });

guardMcpSession(client, { engine });

await client.callTool({ name: "echo", arguments: { text: "hi" } });
// the policy allowed it; the call reached the server

await client.callTool({ name: "read_file", arguments: { path: "/etc/passwd" } });
// throws BlockedError - the server never heard the call
```

`guardMcpSession` duck-types `.callTool`; it never imports the MCP SDK. The
official `@modelcontextprotocol/sdk` `Client` drops in unchanged, and so does any
client exposing the same `callTool({ name, arguments })` shape.

For a transport other than MCP, the pair underneath it is exported directly:

```ts
import { enforceToolCall, enforceToolResult } from "interlock-guard";

const safeArgs = await enforceToolCall("shell", { cmd }, { engine });   // MODIFY merges
const output   = await enforceToolResult("shell", result, { engine });  // MODIFY replaces
```

`enforceToolCall` returns a **copy** of the arguments with any `modified_args`
merged in — the caller's object is never mutated. `enforceToolResult` returns the
*original* result on ALLOW (the `{ result: … }` payload it shows the policy is a
view, never the value that leaks out) and replaces it only on MODIFY.

Both throw `BlockedError`, which carries the whole `Decision` — so a caller that
already catches it can read `policy_id` and `attributed_to` without a second
channel.

## Subpath exports

| Import | What |
|---|---|
| `interlock-guard` | everything |
| `interlock-guard/wire` | the protocol: canonical JSON, the value codec, frames, `WireError` |
| `interlock-guard/mcp` | `enforceToolCall`, `enforceToolResult`, `guardMcpSession` |

## Documented limits

- **Async only.** Node has no synchronous unix-socket client, so
  `RemoteEngine.evaluate(event)` returns a `Promise<Decision>`. The honest
  consequence: **a synchronous JS tool call cannot be guarded**, because there is
  no synchronous transport to guard it with. MCP's `callTool` is already async, so
  the interceptor fits.
- **One connection, serialized.** A request/response exchange on a stream socket
  cannot be interleaved, so concurrent guarded calls queue behind one another on
  the single connection rather than racing on it. One `RemoteEngine` is one
  round trip in flight.
- **A round trip plus two JSON encodes per guarded call.** `npm run bench` prints
  it: on the development machine, a guarded call measured ~47 µs/call against a
  ~0.4 µs no-guard baseline (and ~26 µs on an earlier, less loaded run — the
  number is a smoke figure, not a stated methodology; R12 owns the methodology
  and the regression gate).
- **Some JS values are refused, not coerced.** `undefined`, `NaN`/`±Infinity`, a
  `bigint`, a `Map`/`Date`/class instance, and a `Symbol`-keyed object raise
  `Unrepresentable`. These are the values `JSON.stringify` would silently *drop*
  or *corrupt* — handing the engine an event with no opinion, which allows.
  Refusing turns a silent allow into a loud block. Bytes (`Buffer`/`Uint8Array`)
  and `Set`s cross the wire; everything else is strict JSON.
- **No receipt is emitted.** The Python interceptor signs an execution receipt;
  here the *daemon* already recorded the decision when it answered. A JS receipt
  would double-record one decision into a chain this side cannot sign.
- **ESM only**, no CJS build. Not yet published to npm.

## Development

```bash
npm install
npm run build          # tsc -p tsconfig.build.json   -> dist/
npm test               # tsc -p tsconfig.test.json && node --test -> dist-test/
npm run bench          # the guarded round-trip smoke number
```

`npm test` spawns the **real** Python daemon and, if it cannot start one, **fails**
with the daemon's stderr rather than skipping — a skipped conformance test is a
green suite that proves nothing. Override the interpreter with `PYTHON=…` (the
default is `python3`).

The suite's centre of gravity is `test/corpus.test.ts`, which replays
[`tests/conformance/events.json`](../tests/conformance/events.json) — the same
frozen corpus the Python suite replays. It is the interface between the two
languages: 13 cases and 9 protocol negatives, each asserting that this client's
view of a decision matches the engine's. `test/mcp_sdk.test.ts` goes the other
way and wraps a real `@modelcontextprotocol/sdk` `Client` over an in-memory
transport.

## License

Apache-2.0. See [LICENSE](../LICENSE).
