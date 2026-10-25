# Keep an audit log

When something goes wrong, someone will ask what the agent was allowed to do and
what it was stopped from doing. Debug logs are a poor answer: anyone with write
access can edit them, and they often contain the very customer data you were
protecting. interlock's audit log writes one *receipt* per decision. Receipts are
chained and signed, so editing or deleting one is detectable. Arguments are
stored as a hash, never as values.

Receipts are off by default. Turn them on when you need a record you can hand to
someone else: a security review, an incident, a customer asking what happened.

## Turn it on

Pass a sink to `install`. Every enforced decision from then on appends a receipt
to `audit.jsonl`:

```python
import interlock
from interlock import Blocked, deny_tool, enforce_tool_call, span
from interlock.sink import FileSink

KEY = load_your_secret_key()          # 32 random bytes, kept outside the log's reach
sink = FileSink("audit.jsonl", key=KEY)
interlock.install(rules=[deny_tool("drop_table", policy_id="db.v1")], sink=sink)

with span(principal="acme/agent42"):
    enforce_tool_call("read_rows", {"table": "orders"})
    try:
        enforce_tool_call("drop_table", {"table": "orders"})
    except Blocked:
        pass
```

The blocked call's receipt, one JSON object per line:

```json
{"action":"drop_table","args_digest":"98795f398f6036966300c90bc9db03591f1902e5aaafde2fef2c101488bff642","attributed_to":null,"mac":"9acd7b608f4de6fa3ac932035a042b0fb89fe191cea728cb44f24512d9e14fc9","phase":"call","policy_id":"db.v1","prev":"9ce4f86348191b29bb9c6ffbd6098ce38f7f484720ba37d70f6535909d044a3e","principal":"acme/agent42","reason":"tool not permitted","span_id":"1ee1d2cbfd2342cdaf00f0ecaf7bbe49","ts":1790876799.192898,"verdict":"BLOCK"}
```

`interlock.receipt.set_sink(sink)` does the same as `install(sink=...)`.
`install()` never removes a sink. Only `set_sink(None)` turns receipts off again.

Receipts come from the places that enforce decisions: `@guard`,
`enforce_tool_call` and `enforce_tool_result` (and so the MCP and LangChain
adapters), and sandbox launches. Rules never write receipts, so a rule can't
forge one or quietly skip one. Allowed calls get receipts too.

## What a receipt records

| Field | What it holds |
|---|---|
| `ts` | when the call was captured (Unix time) |
| `action` | the tool or function name |
| `verdict` | what was enforced: `ALLOW`, `BLOCK`, `MODIFY`, or `ESCALATE` (handed to an agent's own approval prompt) |
| `reason` | the rule's reason, copied as written |
| `policy_id` | the rule's policy id, if it set one |
| `attributed_to` | the *name* of the argument that triggered the decision |
| `principal` | who was acting |
| `span_id` | the agent run this call belonged to |
| `phase` | `call` or `result` |
| `args_digest` | SHA-256 over the arguments the caller passed |
| `prev` | the previous receipt's `mac` (64 zeros for the first) |
| `mac` | the signature over every other field |
| `observed` | `true` when monitor mode recorded a decision without enforcing it; absent otherwise |
| `call_id` | one guarded call's id, shared by its call, result and outcome receipts |
| `policy_epoch` | which rule set decided (`PolicyEngine.epoch`) |
| `policy_verdict` | what the policy said, when it differs from `verdict` (an approved or refused `ESCALATE`, a rewrite an agent couldn't apply) |
| `approval` | how an escalation was settled: `approved:once`, `reused:session`, `declined`, `no-approver`, `delegated:claude-code`, ... |
| `outcome`, `enforcer` | on `phase="outcome"` receipts for an allowed tool that then failed: `failed`, and `os` (a permission error, which under the sandbox is the sandbox refusing), `policy` (a guard inside the tool) or `tool` |
| `elapsed_us` | how long the policy evaluation took, in microseconds |

Every field below `observed` is optional and left out while empty, so logs
written before it existed verify unchanged. `verdict` never overstates
enforcement: it is what happened. Monitor-mode receipts are the one exception,
kept for compatibility: their `verdict` is the policy's and `observed` says it
wasn't enforced.

The digest proves *which* payload was seen without storing it. If you have the
arguments in hand, you can check them against a receipt:

```python
from interlock.receipt import digest_args
digest_args({"table": "orders"}) == receipt.args_digest    # True for the matching call
```

The digest covers the arguments as passed. If a rule rewrote them, the receipt
still digests the originals.

> **Warning**
> The `reason` field is copied verbatim. interlock's own rules use fixed
> reasons, but if your rule writes an argument value into its reason (an email
> address, a file path), that value ends up in the log. Keep values out of the
> reasons you write.

### Monitor mode

Under `enforcement="monitor"` (or `@monitor()`), a call that a rule would have
blocked goes through anyway. Its receipt still says `BLOCK`, because that was the
decision, and adds `"observed": true` so nobody reads it as enforcement:

```python
from interlock import monitor

@monitor()
def drop_table(table: str) -> str:
    return "dropped " + table

with span(principal="acme/agent42"):
    drop_table(table="orders")          # runs: monitor mode never blocks
```

```json
{"action":"drop_table","args_digest":"98795f398f6036966300c90bc9db03591f1902e5aaafde2fef2c101488bff642","attributed_to":null,"mac":"ee3a23178f3f5fab8bbe0e42a78b81c7eaef94b6722aa83e40165bc51793504b","observed":true,"phase":"call","policy_id":"db.v1","prev":"0000000000000000000000000000000000000000000000000000000000000000","principal":"acme/agent42","reason":"tool not permitted","span_id":"310e33610784493d9893a4403ed795d1","ts":1790944627.908606,"verdict":"BLOCK"}
```

`observed` is covered by the signature like every other field. Receipts for
enforced decisions leave it out, so logs written before it existed verify
unchanged.

## When a write fails

A sink that can't write (a full disk, a revoked permission) doesn't leave a
silent gap. The write raises `Blocked` with policy id `audit_sink`, so the
guarded call doesn't proceed unrecorded, and the next successful write is
preceded by a `receipts.dropped` receipt: "3 receipt(s) could not be written;
last error: OSError". `interlock.receipt.dropped_receipts()` counts the ones not
yet reported.

## Several writers, one log

Each coding-agent hook call is its own process. `FileSink(path, key=...,
shared=True)` makes every write take an exclusive file lock and re-read the
chain head first, so several processes extend one chain instead of forking it.
POSIX only (`fcntl`).

## Summarize the log

```bash
interlock report audit.jsonl --key-file audit.key           # totals, top rules, latency
interlock report audit.jsonl --since 24h --monitor          # what monitor mode would have stopped
interlock report audit.jsonl --json
```

The report verifies the chain first when given the key, and always says whether
it did. Exit code 2 means the chain is broken.

## Verify the log

`verify()` walks the chain. It returns `None` when the log is intact, or a
message naming the first bad receipt:

```python
FileSink("audit.jsonl", key=KEY).verify()
# -> None
FileSink("audit.jsonl", key=b"some other key").verify()
# -> 'receipt 0: MAC mismatch (edited, or verified with a different key)'
```

Here is what tampering looks like. Someone flips the blocked call to `ALLOW`:

```
receipt 1: MAC mismatch (edited, or verified with a different key)
```

Someone deletes that line instead:

```
receipt 1: chain break (prev does not match the preceding receipt's mac)
```

Each receipt carries the previous receipt's signature, and its own signature
covers that link. An edit breaks the edited receipt. A deletion or reordering
breaks the link to the next one.

### Catch receipts cut from the end

Deleting the *last* receipts leaves a shorter chain that still links up, so the
chain alone can't show it. Record the latest signature, `sink.head`, somewhere
the agent's host can't rewrite (another system, a ticket, a log shipper), and
pass it back when you verify:

```python
head = sink.head                       # after the last write you care about
# ... later, someone deletes the final line of audit.jsonl ...
sink.verify()
# -> None                              the chain itself still links up
sink.verify(head=head)
# -> 'chain ends at receipt 1 but the expected head is 173e14001ec82ded...: receipts were cut from the end, or this is not the log that head came from'
```

An auditor without a sink object uses `verify_file`, which reads the file
without opening it for writing:

```python
from interlock.sink import verify_file

verify_file("audit.jsonl", key=KEY, head=head)
```

From the command line, `interlock anchor` records that head for you. Run it
from a scheduled job, with `--out` on storage the log's writer cannot reach:

```bash
interlock anchor /var/log/agent/audit.jsonl --key-file ~/.interlock/receipts.key \
  --out /mnt/worm/audit.anchor          # verify the chain, then record the head
interlock anchor /var/log/agent/audit.jsonl --key-file ~/.interlock/receipts.key \
  --out /mnt/worm/audit.anchor --check  # cron this; exit 2 means the tail is gone
```

The anchor is a small signed JSON file: the receipt count, the head, the log
path and a timestamp. Recorded with the same key as the chain, so editing it
fails unless the attacker also holds the key. Recording refuses to move
backwards - the log must still contain the anchored receipt at the same
position, and cannot be shorter than the anchored count - so a rolled-back log
cannot re-anchor itself and be blessed. `--check` makes the same comparison
without writing and accepts a log that has grown since, reporting how many
receipts arrived after the anchor. Exit codes: 0 it still reaches the anchor,
2 the chain or the anchor is broken, 3 a file could not be read.

## Choose and keep a key

The default key is random and generated fresh for each process. Without your
own key, only the process that wrote a log can verify it, and once it exits
nobody can.

For a log you need to check later, pass a long-lived key:

```python
import os
KEY = bytes.fromhex(os.environ["INTERLOCK_RECEIPT_KEY"])   # 64 hex characters
sink = FileSink(path, key=KEY)
```

Keep the key where the agent's tools can't read it: a secret manager, or an
environment variable the agent's tools never see. Anyone who holds the key can
write receipts that verify, so a key the agent can read protects nothing.

## Restarts

A `FileSink` opened on an existing log continues its chain from the last receipt
in the file, so one `audit.jsonl` can span restarts:

```python
interlock.install(rules=rules, sink=FileSink("audit.jsonl", key=KEY))
enforce_tool_call("read_rows", {"table": "orders"})

# the service restarts and opens the same file
sink = FileSink("audit.jsonl", key=KEY)
interlock.install(rules=rules, sink=sink)
enforce_tool_call("read_rows", {"table": "customers"})
sink.verify()
# -> None
```

Keep the same key across restarts, or the receipts written under the old key
won't verify under the new one.

If the file ends in something that isn't a receipt, for example a line cut short
by a crash mid-write, the sink refuses to open it rather than chaining new
receipts onto damage nobody looked at:

```
ValueError: broken.jsonl: the last line is not a readable receipt (Unterminated string starting at: line 1 column 21 (char 20)); move the file aside or repair it before appending
```

> **Warning**
> One file, one writer at a time. Two sinks open on the same file at once (two
> processes, or two instances in one process) both continue from the same last
> receipt, so their writes fork the chain and `verify()` reports a break. Give
> concurrent processes their own files, for example with the process id in the
> name.

## Test with an in-memory sink

`InMemorySink` keeps receipts in a list, which makes assertions easy:

```python
from interlock.sink import InMemorySink
from interlock.receipt import set_sink

mem = InMemorySink()
interlock.install(rules=[deny_tool("drop_table")], sink=mem)
try:
    enforce_tool_call("drop_table", {"table": "t"})
except Blocked:
    pass

receipt = mem.receipts[0]
receipt.action, receipt.verdict, receipt.reason, mem.verify()
# -> ('drop_table', 'BLOCK', 'tool not permitted', None)

set_sink(None)        # don't leak the sink into other tests
```

Anything with a `write(receipt)` method can be installed as a sink. Subclass
`ChainedSink` (implement `_append` and `_read_back`) to keep the chaining and
signing while storing receipts somewhere else.

## Let others verify without your key

The default signer is HMAC-SHA256: a shared-secret signature. It proves the log
hasn't changed since it was written, by someone who held the key. It doesn't
prove *which* key holder wrote it, and anyone who verifies it needs the key,
which also lets them write receipts that verify.

For a log an outside auditor can check without being able to forge it, sign
with a private key and give the auditor a verifier that holds only the public
key. interlock ships Ed25519 for this (pure Python, no dependency):

```python
from interlock.receipt_ed25519 import (
    ed25519_signer, ed25519_verifier, generate_seed, public_key,
)

seed = generate_seed()                          # keep this on the signing host only
sink = FileSink("signed.jsonl", signer=ed25519_signer, key=seed)
interlock.install(rules=rules, sink=sink)
# ... the agent runs ...

# the auditor's side: no private key anywhere
verify_file("signed.jsonl", verifier=ed25519_verifier(public_key(seed)))
# -> None
verify_file("signed.jsonl", verifier=ed25519_verifier(some_other_public_key))
# -> 'receipt 0: signature rejected by the verifier (edited, or signed with a different key)'
```

A signer is any function `(key, message) -> bytes`; a verifier is any function
`(message, signature) -> bool`, so a HSM or the `cryptography` package's Ed25519
plugs into the same seam. The bundled signer costs a few milliseconds per
receipt; the HMAC default is faster and is the right choice when one party
holds both keys.

`sink.verify(verifier=...)` and `verify_file(..., verifier=..., head=...)` take
the same verifier. The exact bytes each receipt is signed over come from
`interlock.receipt.signing_payload(receipt)`, if you need to check one by hand.

## Receipts from the sidecar

When a Node.js agent uses the [sidecar](../reference/sidecar.md), the daemon
writes the receipts, because it is the process making the decisions:

```bash
interlock-sidecar --rules my_service.policies:RULES \
  --socket "$HOME/.interlock/guard.sock" \
  --receipts audit.jsonl --key-file receipt.key
```

`--key-file` holds 64 hex characters or raw bytes (a trailing newline is
ignored). Without it the daemon signs with a per-process key and prints a
warning, because the log is then verifiable only by that process. The JS client
doesn't write receipts of its own, so each decision is recorded once.

## Export to an OTLP collector

`OtlpSink` keeps the local chained receipt *and* ships a mapped log record to an
OpenTelemetry collector over OTLP/HTTP (JSON). It is an ordinary chained sink
that stores receipts in memory exactly as `InMemorySink` does, plus an export
side-effect:

```python
import interlock
from interlock.sink import OtlpSink

sink = OtlpSink(
    endpoint="http://collector:4318/v1/logs",   # the full logs URL, used as-is
    headers={"Authorization": "Bearer ..."},     # optional
    service_name="interlock",                    # the service.name resource attr
)
interlock.install(rules=rules, sink=sink)
```

Each receipt becomes one OTLP log record. The verdict sets the severity
(`ALLOW`→`INFO`, `MODIFY`→`WARN`, `BLOCK` and `ESCALATE`→`ERROR`; an
unrecognized verdict gets a defined default), and the record's attributes carry
`action`, `principal`, `policy_id`, `reason` and `span_id` — and nothing else.
The arguments the receipt digested (`args_digest`) are **not** exported, so no
argument value ever reaches the collector.

Three things hold by construction, because a receipt is written on the guarded
call's critical path:

- **The export never blocks the call.** `write` only appends to an in-memory
  buffer and wakes a background worker; the POST happens off-thread, with a
  timeout. The guarded call never waits on the collector.
- **The export never raises into the call and never changes a verdict.** A sink
  that raises is fail-closed (see above), so *every* export failure — mapping,
  buffering, the POST — is swallowed and counted instead. `sink.stats()` reports
  `sent`, `failed`, `pending`, `dropped` and `build_failures`; nothing here can
  flip a decision.
- **A collector that is down loses nothing.** A record that fails to POST stays
  at the front of the buffer and is retried until it is accepted, so the buffer
  drains in order once the collector returns. `max_buffer` bounds the queue — a
  record enqueued while it is full is dropped and counted, but a record already
  retained for retry never is.

Stop the worker with `sink.close()`. The thread is a daemon, so a process that
never closes a sink still exits; records still buffered when it exits are left
undelivered and reported by `stats()`.

Some records export an attribute the receipt did not set, as an export-only
fallback (the local receipt is untouched): a decision that named no policy
exports `policy_id="unattributed"`, and a call with no open `span()` exports
`span_id` as the receipt's `call_id`, so the record still correlates with the
local chain.

## Limits

- **A cut tail needs a recorded head.** Deleting the last receipts leaves a
  valid, shorter chain. `verify(head=...)`, or `interlock anchor --check` from
  a scheduled job, catches it only if you kept the head somewhere the agent's
  host can't change. Shipping receipts off the host as they're written does
  the same job.
- **One writer per file.** Restarts continue the chain; two writers open at the
  same time fork it, and `verify()` reports the fork.
- **HMAC proves integrity, not authorship.** Anyone with the key can write
  receipts that verify. Use a public-key signer and `verifier=` when that
  matters.
- **Rewrites aren't recorded in detail.** A `MODIFY` receipt shows that the call
  was rewritten and by which policy, not what the new arguments were.

## Next

- [Production checklist](production.md): where receipts fit in a rollout
- [Python API reference](../reference/python-api.md): `FileSink`, `InMemorySink`, `OtlpSink`, `Receipt`
- [Sidecar reference](../reference/sidecar.md): `--receipts` and `--key-file`
- [Security model](../security-model.md)
