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
  from my_service.policies import RULES

  engine = interlock.install(rules=RULES)
  assert len(engine) > 0, "interlock has no rules installed"
  ```

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
interlock mcp result action=send_email verdict=ALLOW observed=True attributed_to=None
```

`observed=True` means monitor mode recorded it without acting. Route this logger
wherever your logs go.

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
rules cost. There's no network hop. Scope lookups are cached per scope. There's no
published benchmark for the Python side yet (one is on the
[roadmap](../../ROADMAP.md)), so measure with your own rules. The Node.js client
adds one local socket round trip per guarded call. Its smoke benchmark measured
tens of microseconds per call on a development machine (`npm run bench` in `js/`).

## Upgrades

interlock isn't on PyPI yet, so you install it from Git. Pin a commit or tag so
an upgrade is a deliberate change:

```bash
pip install "git+https://github.com/SourceShift/InterLock.git@<commit-or-tag>"
```

## Next

- [Security model](../security-model.md): what's protected and what isn't.
- [Audit log](audit-log.md)
- [Sidecar reference](../reference/sidecar.md)
