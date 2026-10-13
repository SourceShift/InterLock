# Sidecar reference

`interlock-sidecar` is a small daemon that serves one Python `PolicyEngine` over a
unix socket. Agents written in other languages ask it for a verdict before each
tool call, so they are governed by the same rules as your Python code. Nothing is
reimplemented on the other side, so there is no second rule engine to drift.

The client side, the `interlock-guard` npm package, is documented in
[`js/README.md`](https://github.com/SourceShift/InterLock/blob/main/js/README.md). This page covers the daemon, its trust
boundary, the Python client, and the wire protocol.

## Quick start

Put your rules in an importable module:

```python
# my_service/policies.py
from interlock import deny_tool
from interlock.detectors import network_egress_guard

RULES = [
    deny_tool("shell_exec"),
    network_egress_guard(allowed_hosts=["api.internal"]),
]
```

Check that the daemon can load them, then start it:

```bash
interlock-sidecar --rules my_service.policies:RULES --check
# interlock-sidecar: 2 rules loaded from my_service.policies:RULES

interlock-sidecar --rules my_service.policies:RULES --socket "$XDG_RUNTIME_DIR/interlock/guard.sock"
```

The module must be importable by the daemon's Python, so run it from your project
or set `PYTHONPATH`.

## Command line

```
interlock-sidecar --rules MODULE:ATTR [--socket SOCKET] [--receipts PATH] [--key-file PATH]
                  [--fallback-policy FILE] [--scope-document PATH] [--admin HOST:PORT] [--check]
```

| Flag | Meaning |
|---|---|
| `--rules MODULE:ATTR` | **Required.** The rule set to serve: an attribute holding a `PolicyEngine` or a list/tuple of rules. It must contain at least one rule (see below). |
| `--socket PATH` | Where to listen. Default: `$XDG_RUNTIME_DIR/interlock/guard.sock`, or `~/.interlock/guard.sock` when `XDG_RUNTIME_DIR` is unset. |
| `--receipts PATH` | Append a signed receipt for every decision to `PATH`. Default: no receipts. |
| `--key-file PATH` | The receipt signing key: a file holding 64 hex characters, or raw bytes. A trailing newline is stripped. Without it, a random per-process key is used, which only this daemon run can verify (it prints a warning). |
| `--fallback-policy FILE` | Publish this offline policy, signed with `--key-file`, as `<socket>.fallback.json` for clients running with `unreachable="degraded"` (below). Needs `--key-file`. The file must use the offline subset of the [policy language](../guides/policies.md). |
| `--scope-document PATH` | Serve a per-principal [scoped engine](../guides/scopes.md) from the signed scope document at `PATH`. An existing `PATH` is read and verified (its MAC must check under `--key-file`); a missing `PATH` is published there from the rules module's `scope_document`, signed the same way, like `--fallback-policy`. The rules module must export the `templates` the document binds (see [Scoped engines](#scoped-engines) below). |
| `--admin HOST:PORT` | Serve `/healthz`, `/stats`, `/metrics` (Prometheus) and `/config` (rule ids, epoch) on a loopback address. Non-loopback addresses are refused. See the [production checklist](../guides/production.md#watch-it-in-production). |
| `--check` | Load and validate the rules, print how many there are, and exit without touching the socket or reading the key file. Use it in CI or before a deploy. |

**The rule set must not be empty.** An empty engine allows every call, so a daemon
serving one would look healthy while guarding nothing. The daemon refuses to
start instead.

**Only a `PolicyEngine` or a list of rules is accepted.** A `ScopedEngine` is
refused with `expected a PolicyEngine or a list of rules`; to serve per-tenant
[scopes](../guides/scopes.md), describe them in a scope document and pass it
with `--scope-document` (below) rather than exporting a `ScopedEngine`.

### Scoped engines

`--scope-document` serves the per-principal decisions of a `ScopedEngine` over
the same socket. The document is pure data - which scope binds which template,
with which params:

```json
{"version": 1, "default_scope": [], "allow_unscoped": false,
 "bindings": {"acme": [{"template": "shell_allowlist", "params": {"allow": ["ls", "pwd"]}}],
              "acme/agent1": [{"template": "shell_allowlist", "params": {"allow": ["ls"]}}]}}
```

The templates it names are code, and stay in the rules module, which must export
a `templates` mapping (`{template_id: interlock.policy.scopes.Template}`). A
binding that names a template the module does not declare is a refusal at
startup, not a silently dropped rule. To publish the document, the module also
declares it under a `scope_document` attribute (a mapping, or a callable
returning one), so a daemon pointed at a not-yet-written `PATH` writes the
signed document there - the same publish step `--fallback-policy` performs.

The document is signed like the fallback policy: an envelope of
`version`/`written_at`/`policy`/`mac`, where `policy` is the document as a
canonical-JSON string and `mac` is an HMAC-SHA256 over `"<written_at>\n<policy>"`.
An existing `PATH` whose MAC does not verify under the key is refused (exit `2`).
The scope document the daemon serves is recorded in every
[receipt](python-api.md#receipts-interlocksink-and-interlockreceipt)'s
`scope_document` provenance field as its `"<written_at>:<mac>"` identity - a name,
never the policy content.

Startup messages and errors go to stderr. Stop the daemon with `SIGINT` or
`SIGTERM`. It removes its socket file on the way out.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | `--check` passed, or the daemon shut down cleanly. |
| `2` | A configuration the daemon refuses: bad rules (a malformed `MODULE:ATTR`, an import error, a missing attribute, the wrong type, or an empty rule set), a key file that is missing, unreadable, or empty, a receipts file that can't be read or ends in a damaged line, or an unsafe socket directory (see below). Each is reported as one line on stderr, never a traceback. |
| `3` | Another daemon is already serving that socket. |
| `4` | The daemon could not listen on the socket (binding or setting its permissions failed). |

`--check` validates the rules only. It doesn't read the key file or touch the
socket, so a bad `--key-file` shows up when the daemon actually starts:

```text
$ interlock-sidecar --rules my_service.policies:RULES --key-file /missing/key
interlock-sidecar: cannot read key file /missing/key: No such file or directory
```

## Choosing a socket path

The socket carries tool arguments in cleartext, so its directory is part of the
security boundary. On startup the daemon checks the socket's directory:

| The directory... | What the daemon does |
|---|---|
| doesn't exist | Creates it with mode `0700`. |
| is shared: world-writable or sticky-bit, like `/tmp` | Refuses to start (exit `2`) and **never changes it**. |
| belongs to another user | Refuses to start (exit `2`). |
| belongs to you and isn't shared | Tightens it to `0700` if it was more open. |

Then it refuses to start if another daemon answers on the socket (exit `3`),
removes a stale socket file left by a crash, binds the socket, and sets it to
`0600`.

Use a directory that belongs to the user running the daemon, such as the default
`$XDG_RUNTIME_DIR/interlock/`, `~/.interlock/`, or a dedicated `/run/<service>/`.
Pointing the socket straight into `/tmp` is refused with a hint:

```text
$ interlock-sidecar --rules my_service.policies:RULES --socket /tmp/guard.sock
interlock-sidecar: socket directory /tmp is shared (world-writable or sticky), so the daemon will not use or modify it; put the socket in a private directory instead, e.g. --socket /tmp/<you>-interlock/guard.sock
```

A daemon run as root used to be able to lock every other user out of `/tmp` this
way. Refusing shared directories outright closes that.

## Trust boundary

- **File permissions are the main control.** The socket is `0600` inside a `0700`
  directory, so only its owner can connect.
- **Peer check.** Where the OS reports the connecting process's user (Linux
  `SO_PEERCRED`, macOS `LOCAL_PEERCRED`), connections from any other uid are
  refused. Where it can't tell, the file permissions are the only check.
- **No core dumps.** The daemon disables core files so a crash can't write
  arguments held in memory to disk.
- **Logs.** The daemon never logs argument values itself. If a rule raises, the
  traceback is logged to stderr, and an exception message can quote whatever
  argument the rule choked on. Treat the daemon's stderr as sensitive.

## How the daemon decides

The daemon runs exactly the same `PolicyEngine.evaluate` as in-process code, with
two differences:

- **A rule that raises is a block,** with the reason
  `rule error, denied fail-closed: <ExceptionType>`. (In-process, the exception
  reaches the caller instead.) The message is left out of the reason so that an
  argument value never ends up in a receipt.
- **The daemon writes the receipts.** With `--receipts`, every decision it makes
  is appended to one chain, shared across connections by threads in one process.
  Clients write none. Restarting the daemon with the same `--receipts` file
  continues the chain from the last receipt in it, so one file can span restarts
  as long as `--key-file` stays the same. If the file's last line isn't a readable
  receipt (a crash mid-write, say), the daemon refuses to start rather than chain
  new receipts onto damage. It exits `2` with
  `interlock-sidecar: cannot use receipts file <path>: <path>: the last line is not a readable receipt ...`.
  Move the file aside to start a new log. Don't let two
  daemons write the same file at once: their receipts fork the chain, and
  verification reports the fork as a break.

## When the daemon is down

By default clients fail closed. If the daemon isn't running, can't be reached,
dies mid-session, or answers with an error, **every guarded call is denied**.
That includes monitor mode: an unreachable guard is an infrastructure failure,
not a policy decision, so it is never treated as an allow.

That makes the daemon an availability dependency. A client can choose what an
*unreachable* daemon (no socket, refused, timed out, hung up) means:

| `unreachable` | When the daemon can't be reached |
|---|---|
| `"deny"` (default) | every guarded call is blocked |
| `"degraded"` | the call is decided by the daemon's signed **fallback policy**; a missing, unsigned, tampered or stale (over 7 days) file blocks |
| `"allow"` | every guarded call is allowed unchecked |

```python
RemoteEngine(path, unreachable="degraded", fallback_key=key)   # Python
new RemoteEngine(path, { unreachable: "degraded", fallbackKeyFile: "/etc/interlock/key" })  // Node.js
```

`degraded` and `allow` log a warning on **every** call they decide (Node.js:
`process.emitWarning`, or your `onFallback` callback), and decisions made
without the daemon carry policy id `sidecar_unreachable` or `fallback/<rule>`. A
daemon that is reachable but answers with an error frame is refusing, not
unreachable: that always blocks.

The fallback file stores the policy as a JSON string and signs
`"<written_at>\n<policy>"` with HMAC-SHA256, so the Python and Node.js clients
verify the same bytes. It's limited to what both evaluate identically: `block`
and `escalate` rules whose conditions use `all`/`any`/`not`, `action`, `field`
and `arg` with `eq ne in not_in gt ge lt le contains startswith endswith glob
exists`. No detectors, shell intents, regexes or rewrites. Keep it to the rules
you need standing with the daemon down. It isn't equivalent to your real
policy, which is why `degraded` is never the default.

Deploy the daemon as part of the agent, with the same lifecycle and health checks.

When the daemon shuts down it also closes every open client connection, so a
client that was mid-session gets a closed connection (and blocks) rather than
answers from a daemon that has stopped.

## Python client: `RemoteEngine`

The same protocol is available from Python. That's useful to share one daemon
between several Python processes, or to test a rules module against a real
socket.

```python
from interlock.sidecar import RemoteEngine

RemoteEngine(path, *, timeout=DEFAULT_TIMEOUT)   # DEFAULT_TIMEOUT = 5.0
```

| Member | Meaning |
|---|---|
| `timeout` | Seconds each socket operation (connect, send, waiting for the reply) may take. Defaults to `DEFAULT_TIMEOUT`, 5 seconds, importable from `interlock.sidecar.client`. `None` waits forever. A timeout raises `Blocked` like any other failure, so a hung daemon blocks calls instead of hanging them. |
| `evaluate(event) -> Decision` | Asks the daemon. On any failure (no daemon, timeout, malformed reply, error frame) it raises `Blocked` with a reason such as `guard daemon unreachable at <path>: ...`. |
| `close()` | Closes the connection. Also available as a context manager. |

One `RemoteEngine` holds one connection, and concurrent calls take turns on it.
Because it has an `evaluate` method, you can install it as the process engine:
`interlock.install(engine=RemoteEngine(path))`. Every Python interceptor then asks
the daemon. Don't pass `rules=` alongside it: `RemoteEngine` has no `add_rule`, so
`install` raises `TypeError`.

For tests, `interlock.testing.harness.serve` runs a daemon on a background thread
for the length of a `with` block (see the
[Python API reference](python-api.md#testing-helpers-interlocktesting)).

## Wire protocol

Most users never see this. It matters if you write a client in another language.
The reference implementation is [`interlock/wire.py`](https://github.com/SourceShift/InterLock/blob/main/interlock/wire.py).

### Frames

- One frame per line in both directions: canonical JSON (sorted keys, no
  whitespace, UTF-8), then `\n`.
- A line longer than 8 MiB, or one without a trailing newline, gets a `too_large`
  error and the connection is closed.
- Every frame carries `"v": 1`. Any other version gets `bad_version`.
- **Unknown keys are refused, not ignored.** A misspelled `arg` would otherwise
  leave the engine looking at an event with no arguments, which it would allow.

**Request**

```json
{"event":{"action":"read_file","args":{"path":"/etc/passwd"},"phase":"call","principal":"acme/agent42"},"id":"op-1","v":1}
```

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | Non-empty string. Echoed in the reply. |
| `event.action` | yes | Non-empty string. |
| `event.args` | yes | JSON object. A missing `args` is refused rather than treated as `{}`. |
| `event.phase` | no | `"call"` (default) or `"result"`. |
| `event.principal`, `event.span_id`, `event.parent_principal`, `event.call_id` | no | String or `null`. `call_id` links a call's and its result's events. |
| `event.ts` | no | A finite number. |
| `scope` | no | A signed scope-document overlay (below). When present it must verify under the daemon's key and be the document the daemon serves, or the daemon answers with an error frame. |

**Response**

```json
{"attributed_to":null,"id":"op-1","modified_args":null,"modified_result":null,"policy_id":null,"reason":"no /etc","v":1,"verdict":1}
```

`verdict` is the integer [`Verdict`](python-api.md#verdict): `0` allow, `1`
block, `2` modify, `3` escalate (the client asks its approver; Python
`set_approver`, Node.js `onEscalate`; with none it blocks). A client that
doesn't know a verdict blocks. The other keys mirror [`Decision`](python-api.md#decision). A
`modified_result` of `null` means "no replacement", as in-process.

**Error**

```json
{"error":{"code":"bad_request","message":"event.args is required"},"id":"op-1","v":1}
```

An error frame carries no verdict, so **a client must treat it as a block.**

| Code | Meaning |
|---|---|
| `bad_request` | Not JSON, not UTF-8, unknown or missing keys, or a value of the wrong type. |
| `bad_version` | `v` is not `1`. |
| `too_large` | The line exceeded 8 MiB or wasn't terminated. The connection closes. |
| `unrepresentable` | A value (often a rule's rewrite) can't be encoded. |
| `unauthenticated_scope` | A request's `scope` overlay is unsigned, tampered, or otherwise doesn't verify under the daemon's key. |
| `scope_mismatch` | A request's `scope` overlay verifies, but is not the scope document the daemon serves. |
| `internal` | The daemon produced something it couldn't send. |

### Values

Arguments and rewrites cross as JSON, with these rules:

| Value | On the wire |
|---|---|
| `null`, booleans, integers, strings, lists, objects with string keys | As themselves. |
| Finite floats | As themselves. `NaN` and `±Infinity` are refused. |
| `bytes` | `{"__interlock__": "bytes", "b64": "<base64>"}`, decoded back to bytes on the other side. |
| `set` / `frozenset` | A sorted list. |
| `tuple` | A list. |
| Objects with non-string keys, or any other type | Refused as `unrepresentable`. |

Refusing is deliberate. A value that was silently dropped or coerced could leave a
rule judging something other than what the tool will receive. The Node.js client
applies the same rule to `undefined`, `bigint`, `Map`, `Date`, class instances,
and `Symbol` keys.

The cross-language conformance corpus, `tests/conformance/events.json`, lists 13
events with the decision each must produce and 9 malformed frames with the error
each must produce. A new client is correct when it passes all of them.
