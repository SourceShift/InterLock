# Guardrail platform gaps — epic set

Eight epics covering the operational-requirements review recorded as R23–R30 in
[`ROADMAP.md`](https://github.com/SourceShift/InterLock/blob/main/ROADMAP.md). Each epic is self-contained, lands in the
interlock repo, and is proved by a **live smoke test** — a real process started on
loopback and exercised over a real socket, never a mock.

**Build status.** All eight are **shipped**. R23, R25 and R27–R30 landed on
`main` via mini-ork, each with its live smoke test passing; R26 shipped too,
delivered by the console's review-queue surface rather than a separate run; and
R24, the last of the second wave, closed the set — `interlock learn` drafts a
policy from observed receipts.

Dependency edges are hard (`depends on:`) unless marked `should follow:` (soft,
ordering only). Every epic carries `recipe: framework-edit`.

**How this doc is consumed.**

- `mini-ork epics ingest docs/epics/guardrail-platform-gaps.md` — each `## <title>`
  becomes an epic; the `depends on:` lines become the dependency graph.
- `mini-ork run epic-runner` with `MINI_ORK_EPIC_DOC` set to this file — the planner
  reads the same `depends_on` edges and computes waves.

Both read the same headings and the same `depends on:` lines, so this one file
serves either handover.

**Target.** `/Volumes/docker-ssd/ps/interlock` (or the worktree mini-ork was given
via `MO_TARGET_CWD`). Python 3.9, standard library only for `interlock/`.

---

## R23 — OTLP event export

- recipe: framework-edit

### Goal

Export every receipt as an OTLP log record over OTLP/HTTP to a collector, in
addition to the local chained receipt, without ever blocking or changing a
verdict and without exporting argument values.

### Scope

`interlock/sink.py` (a new `OtlpSink` alongside `ChainedSink`), `interlock/__init__.py`
export, `docs/guides/audit-log.md`, `tests/test_otlp_sink.py`.

### Deliverables

- `OtlpSink(endpoint, headers=None, service_name="interlock")` that writes the
  local chained receipt **and** POSTs an OTLP/HTTP JSON log record.
- Field mapping: severity from the verdict (ALLOW→INFO, MODIFY→WARN, BLOCK/ESCALATE→ERROR),
  attributes carrying `action`, `principal`, `policy_id`, `reason`, `span_id`.
- Buffered, non-blocking export: a collector outage changes no verdict and the
  buffer flushes on recovery.

### Live smoke test

Start a real OTLP/HTTP receiver on a free loopback port, install the sink at it,
make one guarded call, and assert the receiver got exactly one record whose
severity and attributes map the verdict, correlating to the local receipt by
`span_id`.

```bash
set -euo pipefail
PY="${INTERLOCK_PY:-/Users/admin/micromamba/bin/python3}"
WORK="$(mktemp -d)"; PIDS=""
trap 'for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"' EXIT
PORT="$("$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
"$PY" - "$PORT" "$WORK/got.jsonl" <<'PYEOF' &
import json, sys, http.server, socketserver
port, out = int(sys.argv[1]), sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        open(out, "a").write(self.rfile.read(n).decode("utf-8") + "\n")
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(("127.0.0.1", port), H).serve_forever()
PYEOF
PIDS="$PIDS $!"
sleep 0.5
"$PY" - "$PORT" "$WORK/got.jsonl" <<'PYEOF'
import json, os, sys, time
import interlock
from interlock import guard
from interlock.sink import OtlpSink
port, out = sys.argv[1], sys.argv[2]
sink = OtlpSink(endpoint=f"http://127.0.0.1:{port}/v1/logs")
interlock.install(sink=sink, rules=[lambda e: None])
@guard()
def ping(x: str) -> str: return x
ping("hello")
for _ in range(50):
    if os.path.exists(out) and open(out).read().strip(): break
    time.sleep(0.1)
line = open(out).read().strip().splitlines()[0]
rec = json.loads(line)
rl = rec["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
attrs = {a["key"]: list(a["value"].values())[0] for a in rl["attributes"]}
assert attrs["action"] == "ping", attrs
assert attrs["policy_id"] and attrs["span_id"], attrs
assert "hello" not in line, "argument value leaked into the export"
print("R23 smoke pass")
PYEOF
```

### Done when

The smoke test above prints `R23 smoke pass`; a collector-outage test asserts the
verdict is unchanged and the record flushes on recovery; `tests/test_otlp_sink.py`
passes; the full suite passes.

---

## R24 — Behavioural baseline → policy generator

- recipe: framework-edit
- depends on: r23-otlp-event-export

### Goal

`interlock learn` reads a window of receipts and emits a reviewable declarative
policy that allows the observed envelope and escalates the unseen — deterministic,
never auto-enforced.

### Scope

`interlock/learn.py`, `interlock/cli/learn.py`, `pyproject.toml` console script,
`docs/guides/policies.md`, `tests/test_learn.py`.

### Deliverables

- `interlock learn --receipts FILE --out policy.json` reading a receipt NDJSON log.
- Emits `interlock.policy.declarative` rules with counted evidence per rule.
- Deterministic output (no timestamps, stable ordering).

### Live smoke test

From a real fixture receipt log, run the CLI, load the emitted policy through the
declarative engine, and assert it allows an observed action and blocks a held-out
novel action.

```bash
set -euo pipefail
PY="${INTERLOCK_PY:-/Users/admin/micromamba/bin/python3}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
KEY="$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
KEYHEX="$KEY" "$PY" - "$WORK/receipts.jsonl" <<'PYEOF'
import os, sys, time
from interlock.receipt import Receipt
from interlock.sink import FileSink
sink = FileSink(sys.argv[1], key=bytes.fromhex(os.environ["KEYHEX"]))
for a in ["search_web", "search_web", "read_file", "search_web"]:
    sink.write(Receipt(ts=time.time(), action=a, verdict="ALLOW", reason="observed",
                       policy_id="monitor", principal="agent-1", args_digest="0"*64))
PYEOF
"$PY" -m interlock learn --receipts "$WORK/receipts.jsonl" --out "$WORK/policy.json"
"$PY" -m interlock learn --receipts "$WORK/receipts.jsonl" --out "$WORK/policy2.json"
cmp "$WORK/policy.json" "$WORK/policy2.json"   # deterministic
"$PY" - "$WORK/policy.json" <<'PYEOF'
import json, sys
from interlock.event import SensorEvent
from interlock.enforce import Verdict
from interlock.policy.declarative import load_policy
doc = json.load(open(sys.argv[1]))
engine = load_policy(doc)
assert engine.evaluate(SensorEvent(action="search_web", args={})).verdict == Verdict.ALLOW
assert engine.evaluate(SensorEvent(action="delete_everything", args={})).verdict != Verdict.ALLOW
print("R24 smoke pass")
PYEOF
```

### Done when

The smoke test prints `R24 smoke pass`; the emitted policy loads without
validation error; `tests/test_learn.py` passes; the full suite passes.

---

## R25 — Token accounting in the budget guard

- recipe: framework-edit

### Goal

A dependency-free token estimator and a `token_budget_guard` that caps estimated
input+output tokens per principal over a window, with the estimator's error
reported as a documented bound.

### Scope

`interlock/detectors/token_budget_guard.py`, `interlock/tokens.py` (estimator),
`scripts/gen_detector_catalog.py` (regenerate the catalog), `docs/reference/detectors.md`.

### Deliverables

- `estimate_tokens(text, model=None) -> int` — a chars-per-token heuristic with a
  per-model table, dependency-free.
- `token_budget_guard(limit, window_s, refill=None)` accumulating per principal.
- Receipts carry the token estimate so `interlock report` can surface it.

### Live smoke test

Run a real loop of calls through the guard and assert it trips at the ceiling;
check the estimate against a measured sample and assert the documented error
bound holds.

```bash
set -euo pipefail
PY="${INTERLOCK_PY:-/Users/admin/micromamba/bin/python3}"
"$PY" - <<'PYEOF'
import interlock
from interlock import guard, Blocked
from interlock.detectors.token_budget_guard import token_budget_guard
from interlock.tokens import estimate_tokens
interlock.install(rules=[token_budget_guard(limit=200, window_s=3600)])
@guard()
def call(prompt: str) -> str: return prompt
tripped = False
for i in range(100):
    try:
        call("x" * 50)
    except Blocked:
        tripped = True
        break
assert tripped, "guard never tripped"
# error bound: estimator within a documented factor of a rough word-count sample
sample = "the quick brown fox " * 40
est = estimate_tokens(sample)
assert 0.5 * len(sample) / 4 <= est <= 2.0 * len(sample) / 4, est
print("R25 smoke pass")
PYEOF
```

### Done when

The smoke test prints `R25 smoke pass`; `scripts/gen_detector_catalog.py --check`
is clean after regenerating the catalog; the full suite passes.

---

## R26 — Console approval workflow

- recipe: framework-edit

### Goal

The console lists pending escalations from the review queue, and approve/deny
releases the identical retry — loopback-only, digest-checked, opt-in.

### Scope

`interlock/console/approvals.py`, `interlock/console/server.py` (routes),
`web/src/Approvals.tsx`, `docs/guides/console.md`, `tests/test_console_approvals.py`.

### Deliverables

- `GET /api/approvals` (pending rows), `POST /api/approvals/{id}/approve|deny`.
- Reuse the review-queue DB (`interlock.reviews`); exactly-once release.
- Refuse a request whose `args_digest` no longer matches or that has expired (400).
- The approve route is opt-in and loopback-enforced.

### Live smoke test

Start the console against a seeded review-queue DB, GET the pending list, approve
one, and assert the identical retry is released exactly as the CLI would.

```bash
set -euo pipefail
PY="${INTERLOCK_PY:-/Users/admin/micromamba/bin/python3}"
WORK="$(mktemp -d)"; PIDS=""
trap 'for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"' EXIT
PORT="$("$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
BASE="http://127.0.0.1:$PORT"
INTERLOCK_REVIEWS_DB="$WORK/reviews.db" "$PY" -m interlock.console --port "$PORT" --approvals >"$WORK/out" 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 1 50); do curl -fsS "$BASE/api/health" >/dev/null 2>&1 && break; sleep 0.2; done
INTERLOCK_REVIEWS_DB="$WORK/reviews.db" "$PY" - <<'PYEOF'
from interlock.approval import ApprovalRequest
from interlock.reviews import ReviewQueue, binding_hash
req = ApprovalRequest(request_id="rq1", action="run_shell", phase="call",
                      args_digest="a"*64, reason="needs a human", principal="agent-1")
ReviewQueue().lookup_or_file(binding_hash(req), req)
PYEOF
curl -fsS "$BASE/api/approvals" >"$WORK/pending"
"$PY" - "$WORK/pending" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["approvals"] and d["approvals"][0]["action"] == "run_shell", d
print(d["approvals"][0]["id"])
PYEOF
```

### Done when

The smoke test lists the pending escalation; an approve POST releases the retry
once; a second approve is refused; an expired/digest-mismatched row is refused
with 400; `tests/test_console_approvals.py` passes; the full suite passes.

**Precondition:** the console must be present on the target branch. If
`interlock/console/` is absent, this epic is blocked, not failed.

---

## R27 — Framework sensor adapters

- recipe: framework-edit

### Goal

Thin adapters that route an SDK tool loop, LiteLLM, CrewAI and Google ADK through
the existing `enforce_tool_call` / `enforce_tool_result` core, degrading to a
reported "uncovered" state — never a silent pass.

### Scope

`interlock/interceptors/openai.py`, `litellm.py`, `crewai.py`, `google_adk.py`,
`docs/guides/integrations.md`, `tests/test_framework_adapters.py`.

### Deliverables

- One adapter per framework, optional-import, dependency-free at runtime.
- Each wraps the framework's public tool-runner entrypoint through the shared core.
- `interlock doctor` reports detected frameworks and uncovered surfaces.

### Live smoke test

Drive a tool call through a stub public loop for each adapter and assert the
interlock verdict is honoured (block, rewrite, result-check).

```bash
set -euo pipefail
PY="${INTERLOCK_PY:-/Users/admin/micromamba/bin/python3}"
"$PY" - <<'PYEOF'
import interlock
from interlock import Blocked, Decision
from interlock.interceptors.openai import guard_tool_loop
interlock.install(rules=[lambda e: None])
def tool(name, args):
    return f"ran {name}"
guarded = guard_tool_loop(tool)
assert guarded("search", {"q": "ok"}) == "ran search"
interlock.install(rules=[lambda e: Decision.block(reason="nope")])
try:
    guarded("search", {"q": "ok"}); raise AssertionError("not blocked")
except Blocked:
    pass
print("R27 smoke pass")
PYEOF
```

### Done when

The smoke test prints `R27 smoke pass` for each shipped adapter; `interlock doctor`
names the detected frameworks; `tests/test_framework_adapters.py` passes; the full
suite passes.

---

## R28 — A2A policy dimension

- recipe: framework-edit

### Goal

A policy condition and detector family for agent-to-agent traffic: allowlist
reachable peers, match agent-card name/description/skills, flag a changed card
against its baseline.

### Scope

`interlock/detectors/a2a_policy.py`, `interlock/policy/declarative.py` (a new
condition), `docs/guides/policies.md`, `tests/test_a2a_policy.py`.

### Deliverables

- `a2a_peer_allowlist(allowed=...)` and `a2a_card_guard(...)`.
- An `a2a` condition usable in declarative rules.
- The peer identity recorded in `attributed_to`.

### Live smoke test

Evaluate a synthetic A2A call against the guard through the real engine and assert
a non-allowlisted peer is blocked with a reason naming it.

```bash
set -euo pipefail
PY="${INTERLOCK_PY:-/Users/admin/micromamba/bin/python3}"
"$PY" - <<'PYEOF'
import interlock
from interlock.event import SensorEvent
from interlock.enforce import Verdict
from interlock.detectors.a2a_policy import a2a_peer_allowlist
interlock.install(rules=[a2a_peer_allowlist(allowed=["peer://trusted.example"])])
engine = interlock.get_engine()
blocked = engine.evaluate(SensorEvent(action="a2a_send", args={"peer": "peer://evil.example"}))
assert blocked.verdict == Verdict.BLOCK and "evil.example" in blocked.reason, blocked
ok = engine.evaluate(SensorEvent(action="a2a_send", args={"peer": "peer://trusted.example"}))
assert ok.verdict == Verdict.ALLOW, ok
print("R28 smoke pass")
PYEOF
```

### Done when

The smoke test prints `R28 smoke pass`; the declarative `a2a` condition loads;
`tests/test_a2a_policy.py` passes; the full suite passes.

---

## R29 — MCP transport controls and scoped engine over the sidecar

- recipe: framework-edit

### Goal

Refuse a whole MCP transport (HTTP/SSE/stdio) per policy, and let the sidecar
carry a scope document so a remote client gets the same per-principal decision as
an in-process `ScopedEngine`.

### Scope

`interlock/detectors/mcp_transport_guard.py`, `interlock/wire.py`,
`interlock/sidecar/server.py`, `js/src/`, `docs/reference/sidecar.md`,
`tests/test_mcp_transport_guard.py`, `tests/test_sidecar_scopes.py`.

### Deliverables

- `mcp_transport_guard(allow=..., stdio_exceptions=[...])`.
- The sidecar wire carries a signed scope document; an unsigned overlay is refused.
- The scope document is recorded in the receipt's policy provenance.

### Live smoke test

Start a real sidecar on a unix socket with a scope document, send one event over
the wire, and assert the decision equals the in-process `ScopedEngine` for the
same event.

```bash
set -euo pipefail
PY="${INTERLOCK_PY:-/Users/admin/micromamba/bin/python3}"
WORK="$(mktemp -d)"; PIDS=""
trap 'for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"' EXIT
SOCK="$WORK/sidecar.sock"
"$PY" -m interlock.sidecar --socket "$SOCK" --rules tests.fixtures.rules:rules \
       --scope-document "$WORK/scope.json" >"$WORK/out" 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.2; done
"$PY" - "$SOCK" <<'PYEOF'
import socket, sys
from interlock.event import SensorEvent
from interlock.wire import encode_frame, request_frame
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
ev = SensorEvent(action="run_shell", args={"cmd": "ls"}, principal="acme/agent1")
s.sendall(encode_frame(request_frame("op-1", ev)))
reply = s.recv(65536)
assert b"verdict" in reply, reply
print("R29 smoke pass")
PYEOF
```

### Done when

The smoke test prints `R29 smoke pass`; a stdio server off the exception list is
refused before launch; a denied HTTP transport is refused with a transport-named
reason; `tests/test_mcp_transport_guard.py` and `tests/test_sidecar_scopes.py`
pass; the full suite passes.

---

## R30 — Upstream-drift detector

- recipe: framework-edit
- depends on: r23-otlp-event-export

### Goal

Record each covered surface's shape as a corpus, and add `interlock drift` that
diffs a live surface against it and reports additions, removals and changes with a
severity. Files nothing automatically.

### Scope

`interlock/drift.py`, `interlock/cli/drift.py`, `.github/workflows/drift.yml`,
`docs/guides/production.md`, `tests/test_drift.py`.

### Deliverables

- A corpus format recording tool-listing fingerprints and schema shapes.
- `interlock drift --corpus FILE --live CMD` printing a diff and exiting non-zero
  on a change.
- A CI job running it against pinned upstream versions.

### Live smoke test

Write a corpus, point `interlock drift` at a live MCP server whose tool set
changed, and assert it reports the added/removed tools and exits non-zero; an
unchanged surface exits zero.

```bash
set -euo pipefail
PY="${INTERLOCK_PY:-/Users/admin/micromamba/bin/python3}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
"$PY" - "$WORK/corpus.json" <<'PYEOF'
import json, sys
json.dump({"surfaces": [{"name": "demo", "tools": ["read", "write"]}]}, open(sys.argv[1], "w"))
PYEOF
"$PY" - "$WORK/server.py" <<'PYEOF'
import sys
sys.stdout.write("\n".join(["read", "write", "exec"]))
PYEOF
set +e
"$PY" -m interlock drift --corpus "$WORK/corpus.json" --live "$PY $WORK/server.py" >"$WORK/report" 2>&1
RC=$?
set -e
[ "$RC" -ne 0 ] || { echo "drift did not report a change"; cat "$WORK/report"; exit 1; }
grep -q "exec" "$WORK/report"
print_ok="R30 smoke pass"
echo "$print_ok"
```

### Done when

The smoke test prints `R30 smoke pass`; an unchanged surface exits zero;
`tests/test_drift.py` passes; the full suite passes.

---

## Dependency summary (ignore)

| Epic | Hard deps | Soft |
|---|---|---|
| R23 OTLP event export | — | — |
| R24 baseline → policy generator | R23 | — |
| R25 token accounting | — | — |
| R26 console approval workflow | — | console on `main` |
| R27 framework sensor adapters | — | — |
| R28 A2A policy dimension | — | — |
| R29 MCP transport + scoped sidecar | — | — |
| R30 upstream-drift detector | R23 | R27 |

Wave 0: R23, R25, R26, R27, R28, R29. Wave 1: R24, R30.
