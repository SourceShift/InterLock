# Production checklist

A guard that works on your laptop can still fail you in production. It might be
switched off by accident, block legitimate work, or leave you without a record of
what happened. Work through this list before you rely on interlock for real
traffic. Each item links to the page with the details.

## Before you deploy

- [ ] **Rules are installed at startup, and you check they're there.** With no
  rules, interlock allows everything. Fail loudly instead:

  ```python
  import interlock
  from interlock.posture import require
  from my_service.policies import RULES

  interlock.install(rules=RULES, sink=FileSink(path, key=KEY))
  require()          # raises ProtectionError unless protection is fully on
  ```

  `require()` checks every setting in the security model's "settings that
  weaken protection" table: no rules, monitor-mode guards, `allow_unscoped`, a
  per-process sink key, a soft sandbox backend, a sidecar without a timeout or
  that allows calls when it's down. `require("degraded")` accepts warnings but
  not failures. `interlock.posture.attest()` returns the same report without
  raising. From a shell, `interlock doctor --rules my_service.policies:RULES
  --receipts audit.jsonl --key-file audit.key` checks the policy loads, the
  sidecar answers, and the log's chain verifies.

  With [scopes](scopes.md), a call made outside any `span(principal=...)`
  matches no scope and is blocked. Set `default_scope=("root",)` to apply your
  root policy to such calls instead.

- [ ] **Rules are in a sensible order.** A block from any rule wins, but later
  rules see earlier rewrites, and budgets only count calls that reach them
  ([ordering](writing-rules.md#put-rules-in-the-right-order)).

- [ ] **Every detector you rely on actually sees your tools.** Check each one's
  "Scoped to" column in the [catalog](../reference/detectors.md), and pass your
  tool names or wrap it with `only_for` / `as_action`
  ([detectors guide](detectors.md#check-which-calls-a-detector-looks-at)).

- [ ] **Your policy has tests**, for both what it blocks and what it lets
  through ([writing rules](writing-rules.md#test-your-rules)). Run them in CI.

- [ ] **Every agent run is tagged.** Wrap each run in
  `span(principal="tenant/agent")` so decisions and receipts say who did what.

## Roll out in monitor mode first

New rules always surprise someone. Run them in monitor mode on real traffic,
read what they would have blocked, and enforce once the results look right.
Driving the mode from configuration keeps that a deploy-time switch:

```python
import os
from interlock import guard

ENFORCEMENT = os.environ.get("INTERLOCK_ENFORCEMENT", "blocking")   # "monitor" to observe only

@guard(enforcement=ENFORCEMENT)
def send_email(to: str, subject: str, body: str) -> str: ...
```

`INTERLOCK_ENFORCEMENT` is just a name for your own setting; interlock doesn't
read it. Only the exact value `"monitor"` turns enforcement off. Anything else,
including a typo, enforces, so a misconfiguration fails safe.

Decisions are logged at `DEBUG` on the `interlock` logger:

```text
interlock action=send_email verdict=BLOCK reason=external email span=2b4a2ac5a5b2433c817329101259e728 observed=True attributed_to=None
interlock mcp result action=send_email verdict=ALLOW reason= span=2b4a2ac5a5b2433c817329101259e728 observed=False attributed_to=None
```

`observed=True` means monitor mode recorded it without acting. Route this logger
wherever your logs go. With a receipt sink installed,
`interlock report audit.jsonl --since 24h --monitor` lists what would have been
stopped, by rule and tool.

## Watch it in production

In-process counters track every decision, whether or not a receipt sink is
installed: verdicts by policy, escalations by outcome, masked entities, dropped
receipts and evaluation latency.

```python
from interlock import metrics
metrics.snapshot()            # plain data
metrics.render_prometheus()   # Prometheus text format
```

A sidecar serves them on a loopback admin port:

```bash
interlock-sidecar --rules my_service.policies:RULES --admin 127.0.0.1:19000
curl -s 127.0.0.1:19000/healthz     # ok
curl -s 127.0.0.1:19000/metrics     # interlock_decisions_total{verdict="BLOCK",...}
```

`/stats` and `/config` return JSON. `/config` lists rule ids and the policy
epoch, never patterns. The endpoint binds loopback only, answers only `GET`,
checks the `Host` header, and sends no CORS headers.

## Handle refusals in the agent

- [ ] **A blocked call doesn't crash the agent.** Catch `Blocked` in your tool
  loop and hand the reason back to the model as the tool's result, so it can try
  something else ([example](integrations.md#a-model-sdk-or-any-other-framework)).

- [ ] **Hand-written rules can't crash the call path in surprising ways.** A rule
  that raises stops the call, but the caller gets the rule's exception, not
  `Blocked`. Wrap risky checks in `deny_when`, or catch `Exception` around tool
  calls.

- [ ] **Rewritten arguments are what you use.** `enforce_tool_call` returns the
  arguments to call the tool with. Calling the tool with the original arguments
  throws the rewrite away.

## Keep a record

- [ ] **Receipts are on, with a stable key.** Without `key=`, a random key is
  made per process, and nobody else can verify the log
  ([audit log](audit-log.md)).

- [ ] **One writer per audit file.** A sink reopened after a restart continues
  the file's chain, but two processes appending to the same file at once fork it,
  and `verify()` reports the fork as a break. Give each process its own file.

- [ ] **You actually verify logs, and can tell if the end was cut off.** Record
  `sink.head` somewhere the agent's host can't change, then run
  `verify_file(path, key=KEY, head=recorded_head)` when you archive a file. Alert
  if it returns anything but `None`.

## Contain what you can't inspect

- [ ] **Code the agent writes or downloads runs in the sandbox**, not just behind
  argument checks ([sandbox](sandbox.md)).
- [ ] **You refuse weak sandboxes before anything runs.** Build the sandbox
  with the guarantees you need, `Sandbox(profile, require=("net", "fs-rw"))`, and
  `run()` raises `IsolationUnavailable` without starting the process on a host
  that can't deliver them. Checking `result.enforced` after `run()` is too late:
  the code has already run ([sandbox guide](sandbox.md)).
- [ ] **Memory limits fit your platform.** CPU and memory limits apply on every
  backend, but macOS can't cap memory, so a profile with `memory_mb` raises
  `LimitUnsupported` there. Keep `memory_mb` for Linux hosts.

## Node.js agents

- [ ] **The sidecar runs as a supervised service** (systemd, a container
  sidecar, or your process manager), started before the agent.
- [ ] **The socket lives in a directory the service owns**, not directly in
  `/tmp` ([sidecar reference](../reference/sidecar.md#choosing-a-socket-path)).
- [ ] **`interlock-sidecar --rules ... --check` runs in CI**, so a broken or
  empty rule set fails the build rather than the deploy.
- [ ] **No `RemoteEngine` disables its timeout.** The default is 5 seconds;
  with `timeout: null` a hung daemon hangs every guarded call.
- [ ] **You've accepted the availability trade-off.** If the daemon is down,
  every guarded call is denied.

## Performance

Rules run in your process as ordinary Python, so a call costs roughly what your
rules cost. There's no network hop, and scope lookups are cached per scope.

`scripts/bench_overhead.py` measures what the built-in pack adds over an empty
engine on 70 ordinary coding-agent events: **p50 241 µs, p95 390 µs, p99
442 µs** per decision on a development machine. That excludes process start,
hook-adapter parsing, receipt I/O and sidecar RPC, so treat it as the floor of
what a hook will cost — method, corpus and gate thresholds are in
[`benchmarks/overhead/README.md`](https://github.com/SourceShift/InterLock/blob/main/benchmarks/overhead/README.md).
Measure with your own rules before setting a gate.

The Node.js client adds one local socket round trip per guarded call. Its smoke
benchmark measured tens of microseconds per call on a development machine
(`npm run bench` in `js/`).

## Upgrades

interlock isn't on PyPI yet, so you install it from Git. Pin a commit or tag so
an upgrade is a deliberate change:

```bash
pip install "git+https://github.com/SourceShift/InterLock.git@<commit-or-tag>"
```

## Detect upstream drift

A tool surface is not static: an MCP server you trust today can add, remove or
reshape a tool tomorrow, and nothing about a call changes to tell you. Record
what each covered surface looks like, then diff the live surface against the
record.

- [ ] **Covered surfaces are recorded as a corpus.** Each surface's tool listing,
  and any schema shape you care about, goes in a corpus file:

  ```json
  {"corpus_version": 1,
   "surfaces": [{"name": "demo", "tools": ["read", "write"]}]}
  ```

  A tool entry is a bare name, or an object carrying the name plus the shape you
  recorded (`{"name": "read", "input_schema": {...}}`). `corpus_version` is
  optional.

- [ ] **Drift is diffed against a live surface.** `--live` runs a command and
  reads its standard output as the live tool listing, one tool name per line (or
  one JSON object per line when you record schema shapes):

  ```bash
  interlock drift --corpus corpus.json --live "my-mcp-server --list-tools"
  ```

  Every added tool, removed tool and changed schema shape is reported with a
  severity, and the command exits non-zero on any drift; an unchanged surface
  exits zero. `--surface NAME` picks which recorded surface the live command
  describes when the corpus holds more than one.

- [ ] **Nothing is filed and nothing is rewritten.** `drift` only ever reads the
  corpus - there is no `--fix` and no write-back - so the diff is a report you
  act on, not an action it takes. Record the surface deliberately, when you
  mean to.

- [ ] **The fingerprint is the runtime guard's.** The corpus fingerprint is
  `mcp_server_attestation.listing_digest`, the canonicalization the
  `mcp_server_baseline` rule uses at admission time, so `drift` reporting
  "unchanged" and the guard blocking cannot disagree about the same surface
  ([detectors](../reference/detectors.md)).

- [ ] **A CI job diffs pinned upstreams on a schedule.** Pin the upstream version
  so a diff means *your* surface moved, not someone else's release train;
  `.github/workflows/drift.yml` re-checks each recorded surface weekly and on
  every pull request, and a finding fails the build
  ([workflow](https://github.com/SourceShift/InterLock/blob/main/.github/workflows/drift.yml)).

  ```bash
  interlock drift --corpus corpus.json --live "python -m my_upstream --list-tools"
  ```

## Next

- [Security model](../security-model.md): what's protected and what isn't.
- [Audit log](audit-log.md)
- [Sidecar reference](../reference/sidecar.md)
