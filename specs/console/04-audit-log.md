# Audit log viewer with live tail

Depends on: 01-console-server

interlock records every enforced decision as a receipt in an append-only,
hash-chained log (`interlock.sink.FileSink`; the sidecar writes one with
`--receipts PATH --key-file PATH`). Each receipt holds the action, verdict,
reason, policy id, principal, phase and an argument digest, never the arguments
themselves; `prev` and `mac` chain the receipts so an edit, a deletion or a
reorder is detectable. This spec lets the console open one receipt log, show it
as a table, verify its chain with the operator's key, and stream new receipts
live while an agent or the sidecar keeps writing.

## Inputs

- Command line: `--receipts PATH` (a receipt log) and `--key-file PATH` (the
  MAC key, in the sidecar's format: 64 hex characters, or raw bytes; trailing
  newlines stripped). Both are fixed at startup.
- `GET /api/receipts` with optional query parameters `offset` (default 0),
  `limit` (default 100, clamped to 1..500), `verdict` (`ALLOW`, `BLOCK`, `MODIFY`),
  `action` (exact match) and `order` (`desc`, the default, or `asc`).
- `GET /api/receipts/verify`.
- `GET /api/receipts/stream` (Server-Sent Events).
- In the web app: the route `#/audit`.

## Outputs

- `GET /api/receipts` answers 200 with
  `{"total", "count_all", "receipts": [...]}`: `total` counts the receipts matching the
  filters, `count_all` counts every receipt in the file. Each receipt object carries
  `index` (its 0-based line position in the file) and the receipt fields
  `ts`, `action`, `verdict`, `reason`, `policy_id`, `attributed_to`, `principal`,
  `span_id`, `phase`, `args_digest`, `observed`, `prev`, `mac`. With `order=desc` the
  newest receipt comes first.
- A line that cannot be parsed as a receipt appears as `{"index": i, "unreadable": true}`
  instead of failing the page.
- `GET /api/receipts/verify` answers 200 with `{"status", "problem", "count", "head"}`:
  `status` is `intact` when `interlock.sink.verify_file(path, key=key)` returns None,
  `broken` with that message as `problem` otherwise, and `unverified` with a `problem`
  saying no key was configured when the console has no key. `head` is the `mac` of the last receipt.
- `GET /api/receipts/stream` answers `Content-Type: text/event-stream`. It sends
  `event: hello` with `{"count": N}` first, then one `event: receipt` whose `data` is
  the receipt object (with its `index`) for every receipt appended after the
  connection opened, within 1 second of the append. It sends a `: keepalive` comment
  every 15 seconds. When the file shrinks (truncated or replaced) it sends `event: reset`.
- `/api/health` gains `"receipts": true|false` and `"verify": true|false`.

## Errors

- Every `/api/receipts` route answers 404 with code `receipts_not_configured` when
  the console was started without `--receipts`.
- A `verdict` or `order` value outside the listed ones answers 400 with code `bad_query`.
- More than 8 open streams answers 503 with code `too_many_streams`.
- `--key-file` that is missing, unreadable or empty: the process exits with status 2
  and one line on stderr, before binding, like the sidecar.

## Edge cases

- The receipt file does not exist yet: the table is empty, `count_all` is 0, verify
  reports `intact` with count 0, and the stream starts sending receipts once the file appears.
- A receipt appended by another process while a page is being read appears in
  the next request; a partially written last line is not reported until it ends with a newline.
- The stream survives the browser reconnecting (EventSource retry) without duplicating
  receipts it already sent on the same connection.

## Constraints

- The key never leaves the server: no API response, stream event, log line or
  error message contains the key or any part of it.
- No API accepts a file path; the console reads only the path given at startup.
- The console only reads the receipt log; it never writes, truncates or rotates it.
- The key file is read with the sidecar's existing reader so the two accept the
  same formats.
- Standard library only; Python 3.9. Do not edit existing tests,
  `interlock/sink.py`, `interlock/receipt.py` or the sidecar.

## Architecture

- `interlock/console/audit.py` holds reading, filtering, verification and the
  stream generator; routes are registered through the route table from spec 01.
- Streams run on the server's request threads and poll the file size at most
  once per second; a stream ends when the client disconnects or the server stops.
- Tests live in `tests/test_console_audit.py`.
- `docs/guides/console.md` gains a section showing the console watching the log a
  running sidecar writes.

## Audit page

- `#/audit` shows a table with one `data-testid="receipt-row"` per receipt,
  newest first: local time, action (monospace), a verdict badge with the verdict
  name as its text, reason, policy id, principal, phase, and a marker for
  `observed` (monitor-mode) receipts. The argument digest is shown shortened.
- `data-testid="chain-status"` reads `intact`, `broken: <problem>` or `unverified`.
- `data-testid="verdict-filter"` is a select with options `ALL`, `ALLOW`, `BLOCK`, `MODIFY`.
- A live tail is on by default: new receipts appear at the top of the table
  without a reload, `data-testid="live-indicator"` reads `live` while the stream
  is connected, and `data-testid="live-toggle"` turns it off and on.
- When the console has no receipt log, the page shows `data-testid="audit-empty"`
  explaining the `--receipts` and `--key-file` flags.

- The page ships a sibling `*.test.tsx` (Vitest and Testing Library) that renders it against mocked `/api/receipts` and `/api/receipts/verify` responses and checks the filter.
## Delivery order

- D1: `interlock/console/audit.py`, the CLI flags, the three routes, health keys, and their tests.
- D2: the audit page and the docs section.

## Acceptance criteria

- AC1: with a 3-receipt log and its key, `GET /api/receipts` reports `total` and `count_all` 3, newest first (`search`, `http_post`, `run_shell`), with indexes 2, 1, 0 and a 64-hex `mac` on each.
- AC2: `GET /api/receipts/verify` reports `intact`, count 3, and `head` equal to the last receipt's `mac`.
- AC3: after the second line's `reason` is edited in the file, verify reports `broken` with a `problem` containing `receipt 1`.
- AC4: started with `--receipts` and no `--key-file`, verify reports `unverified`.
- AC5: `verdict=BLOCK` returns exactly the `run_shell` receipt; `action=search` returns exactly the `search` receipt; `order=asc` puts `run_shell` first; `verdict=MAYBE` answers 400 `bad_query`.
- AC6: a stream opened before a receipt is appended receives `event: hello` and then an `event: receipt` carrying the appended action, with `Content-Type: text/event-stream`, and verify still reports `intact` after the append.
- AC7: started without `--receipts`, `GET /api/receipts` answers 404 `receipts_not_configured` and `/api/health` reports `"receipts": false`.
- AC8: the key's hex text appears in none of `/api/health`, `/api/receipts`, `/api/receipts/verify`, or the console's own output; a missing `--key-file` path exits with status 2.
- AC9: `python -m pytest -q tests/test_console_audit.py` passes with at least 8 tests.
- AC10 (UI): `#/audit` shows 3 `receipt-row` elements and `chain-status` containing `intact`.
- AC11 (UI): a receipt appended while the page is open appears as a 4th `receipt-row` within 6 seconds, and `live-indicator` reads `live`.
- AC12 (UI): choosing `BLOCK` in `verdict-filter` leaves 1 `receipt-row`.
- AC13 (UI): with no receipt log configured, `#/audit` shows `audit-empty`.

## Verify

```bash
set -euo pipefail
PY="${INTERLOCK_PY:-/Users/admin/micromamba/bin/python3}"
cd "${MO_TARGET_CWD:-/Volumes/docker-ssd/ps/interlock-console}"
WORK="$(mktemp -d)"; PIDS=""
trap 'for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"' EXIT
KEYHEX="c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff"
free_port() { "$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
start_console() {
  PORT="$(free_port)"; BASE="http://127.0.0.1:$PORT"
  "$PY" -m interlock.console --port "$PORT" "$@" >"$WORK/console-$PORT.log" 2>&1 &
  PIDS="$PIDS $!"
  for _ in $(seq 1 50); do curl -fsS "$BASE/api/health" >/dev/null 2>&1 && return 0; sleep 0.2; done
  echo "console did not come up"; cat "$WORK/console-$PORT.log"; return 1
}
mkfixture() {
  printf '%s\n' "$KEYHEX" >"$WORK/key.hex"
  KEYHEX="$KEYHEX" "$PY" - "$WORK/receipts.jsonl" <<'PYEOF'
import os, sys, time
from interlock.receipt import Receipt
from interlock.sink import FileSink
sink = FileSink(sys.argv[1], key=bytes.fromhex(os.environ["KEYHEX"]))
for action, verdict in [("run_shell", "BLOCK"), ("http_post", "MODIFY"), ("search", "ALLOW")]:
    sink.write(Receipt(ts=time.time(), action=action, verdict=verdict, reason="fixture " + action,
                       policy_id="fixture", principal="agent-1", args_digest="0" * 64))
PYEOF
}
append_receipt() {
  KEYHEX="$KEYHEX" "$PY" - "$WORK/receipts.jsonl" "$1" <<'PYEOF'
import os, sys, time
from interlock.receipt import Receipt
from interlock.sink import FileSink
FileSink(sys.argv[1], key=bytes.fromhex(os.environ["KEYHEX"])).write(
    Receipt(ts=time.time(), action=sys.argv[2], verdict="ALLOW", reason="appended", principal="agent-1"))
PYEOF
}
jcheck() { B="$WORK/b" "$PY" -c "import json,os; d=json.load(open(os.environ['B'])); $1"; }
mkfixture
# AC1
start_console --receipts "$WORK/receipts.jsonl" --key-file "$WORK/key.hex"
curl -fsS -o "$WORK/b" "$BASE/api/receipts"
B="$WORK/b" "$PY" - <<'PYEOF'
import json, os, re
d = json.load(open(os.environ["B"]))
assert d["total"] == 3 and d["count_all"] == 3, d
r = d["receipts"]
assert [x["action"] for x in r] == ["search", "http_post", "run_shell"], [x["action"] for x in r]
assert [x["index"] for x in r] == [2, 1, 0], [x["index"] for x in r]
assert all(re.fullmatch(r"[0-9a-f]{64}", x["mac"]) for x in r), r
for k in ("ts", "verdict", "reason", "policy_id", "principal", "phase", "args_digest", "prev"):
    assert k in r[0], k
PYEOF
echo "AC1 pass"
# AC2
start_console --receipts "$WORK/receipts.jsonl" --key-file "$WORK/key.hex"
curl -fsS -o "$WORK/b" "$BASE/api/receipts/verify"
LAST="$(tail -1 "$WORK/receipts.jsonl" | "$PY" -c 'import json,sys; print(json.loads(sys.stdin.read())["mac"])')"
LAST="$LAST" jcheck 'assert d["status"] == "intact" and d["count"] == 3 and d["head"] == os.environ["LAST"], d'
echo "AC2 pass"
# AC3
"$PY" - "$WORK/receipts.jsonl" <<'PYEOF'
import sys
p = sys.argv[1]
lines = open(p).read().splitlines()
lines[1] = lines[1].replace("fixture http_post", "tampered")
open(p, "w").write("\n".join(lines) + "\n")
PYEOF
start_console --receipts "$WORK/receipts.jsonl" --key-file "$WORK/key.hex"
curl -fsS -o "$WORK/b" "$BASE/api/receipts/verify"
jcheck 'assert d["status"] == "broken" and "receipt 1" in (d["problem"] or ""), d'
echo "AC3 pass"
# AC4
start_console --receipts "$WORK/receipts.jsonl"
curl -fsS -o "$WORK/b" "$BASE/api/receipts/verify"
jcheck 'assert d["status"] == "unverified", d'
echo "AC4 pass"
# AC5
start_console --receipts "$WORK/receipts.jsonl" --key-file "$WORK/key.hex"
curl -fsS -o "$WORK/b" "$BASE/api/receipts?verdict=BLOCK"
jcheck 'assert d["total"] == 1 and [x["action"] for x in d["receipts"]] == ["run_shell"], d'
curl -fsS -o "$WORK/b" "$BASE/api/receipts?action=search"
jcheck 'assert d["total"] == 1 and [x["action"] for x in d["receipts"]] == ["search"], d'
curl -fsS -o "$WORK/b" "$BASE/api/receipts?order=asc"
jcheck 'assert d["receipts"][0]["action"] == "run_shell", d'
CODE="$(curl -sS -o "$WORK/b" -w '%{http_code}' "$BASE/api/receipts?verdict=MAYBE")"
[ "$CODE" = "400" ]
jcheck 'assert d["error"]["code"] == "bad_query", d'
echo "AC5 pass"
# AC6
start_console --receipts "$WORK/receipts.jsonl" --key-file "$WORK/key.hex"
curl -sN --max-time 6 -D "$WORK/sse-h" -o "$WORK/sse" "$BASE/api/receipts/stream" &
CURL_PID=$!
sleep 1.5
append_receipt live_probe_action
wait "$CURL_PID" || true
grep -qi '^content-type: text/event-stream' "$WORK/sse-h"
grep -q '^event: hello' "$WORK/sse"
grep -q '^event: receipt' "$WORK/sse"
grep -q 'live_probe_action' "$WORK/sse"
curl -fsS -o "$WORK/b" "$BASE/api/receipts/verify"
jcheck 'assert d["status"] == "intact" and d["count"] == 4, d'
echo "AC6 pass"
# AC7
start_console
CODE="$(curl -sS -o "$WORK/b" -w '%{http_code}' "$BASE/api/receipts")"
[ "$CODE" = "404" ]
jcheck 'assert d["error"]["code"] == "receipts_not_configured", d'
curl -fsS -o "$WORK/b" "$BASE/api/health"
jcheck 'assert d["receipts"] is False, d'
echo "AC7 pass"
# AC8
start_console --receipts "$WORK/receipts.jsonl" --key-file "$WORK/key.hex"
for P in /api/health /api/receipts /api/receipts/verify "/api/receipts?order=asc"; do
  curl -fsS "$BASE$P" >>"$WORK/all"
done
cat "$WORK"/console-*.log >>"$WORK/all"
if grep -qi "${KEYHEX:0:16}" "$WORK/all"; then echo "key material leaked"; exit 1; fi
PORT2="$(free_port)"
set +e
timeout 5 "$PY" -m interlock.console --port "$PORT2" --receipts "$WORK/receipts.jsonl" --key-file "$WORK/no-such-key" >/dev/null 2>"$WORK/err"
RC=$?
set -e
[ "$RC" -eq 2 ] || { echo "exit status $RC"; cat "$WORK/err"; exit 1; }
echo "AC8 pass"
# AC9
"$PY" -m pytest -q -p no:cacheprovider tests/test_console_audit.py >"$WORK/t" 2>&1 || { tail -30 "$WORK/t"; exit 1; }
T="$WORK/t" "$PY" - <<'PYEOF'
import os, re
out = open(os.environ["T"]).read()
m = re.search(r"(\d+) passed", out)
assert m and int(m.group(1)) >= 8, out[-400:]
assert not re.search(r"\b\d+ (failed|errors?)\b", out), out[-400:]
PYEOF
echo "AC9 pass"
```

```bash
set -euo pipefail
PY="${INTERLOCK_PY:-/Users/admin/micromamba/bin/python3}"
cd "${MO_TARGET_CWD:-/Volumes/docker-ssd/ps/interlock-console}"
WORK="$(mktemp -d)"; PIDS=""; ABS="sdd-audit-$$"
trap 'agent-browser --session "$ABS" close >/dev/null 2>&1 || true; for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"' EXIT
KEYHEX="c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff"
[ -d web/node_modules ] || npm --prefix web ci --no-audit --no-fund >"$WORK/npm" 2>&1
npm --prefix web run build >"$WORK/build" 2>&1 || { tail -30 "$WORK/build"; exit 1; }
printf '%s\n' "$KEYHEX" >"$WORK/key.hex"
KEYHEX="$KEYHEX" "$PY" - "$WORK/receipts.jsonl" <<'PYEOF'
import os, sys, time
from interlock.receipt import Receipt
from interlock.sink import FileSink
sink = FileSink(sys.argv[1], key=bytes.fromhex(os.environ["KEYHEX"]))
for action, verdict in [("run_shell", "BLOCK"), ("http_post", "MODIFY"), ("search", "ALLOW")]:
    sink.write(Receipt(ts=time.time(), action=action, verdict=verdict, reason="fixture " + action,
                       policy_id="fixture", principal="agent-1", args_digest="0" * 64))
PYEOF
free_port() { "$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
start_console() {
  PORT="$(free_port)"; BASE="http://127.0.0.1:$PORT"
  "$PY" -m interlock.console --port "$PORT" "$@" >"$WORK/console-$PORT.log" 2>&1 &
  PIDS="$PIDS $!"
  for _ in $(seq 1 50); do curl -fsS "$BASE/api/health" >/dev/null 2>&1 && return 0; sleep 0.2; done
  echo "console did not come up"; cat "$WORK/console-$PORT.log"; return 1
}
start_console --receipts "$WORK/receipts.jsonl" --key-file "$WORK/key.hex"
AB="agent-browser --session $ABS"
$AB open "$BASE/#/audit" >/dev/null
$AB wait '[data-testid="receipt-row"]' >/dev/null
# AC10
for _ in $(seq 1 25); do N="$($AB get count '[data-testid="receipt-row"]')"; [ "$N" -eq 3 ] && break; sleep 0.2; done
[ "$N" -eq 3 ] || { echo "rows: $N"; exit 1; }
S="$($AB get text '[data-testid="chain-status"]')"
case "$S" in *intact*) ;; *) echo "chain-status: $S"; exit 1;; esac
echo "AC10 pass"
# AC11
sleep 1
KEYHEX="$KEYHEX" "$PY" - "$WORK/receipts.jsonl" <<'PYEOF'
import os, sys, time
from interlock.receipt import Receipt
from interlock.sink import FileSink
FileSink(sys.argv[1], key=bytes.fromhex(os.environ["KEYHEX"])).write(
    Receipt(ts=time.time(), action="live_probe_action", verdict="ALLOW", reason="appended", principal="agent-1"))
PYEOF
for _ in $(seq 1 30); do N="$($AB get count '[data-testid="receipt-row"]')"; [ "$N" -eq 4 ] && break; sleep 0.2; done
[ "$N" -eq 4 ] || { echo "rows after append: $N"; exit 1; }
L="$($AB get text '[data-testid="live-indicator"]')"
case "$L" in *live*) ;; *) echo "live-indicator: $L"; exit 1;; esac
echo "AC11 pass"
# AC12
$AB select '[data-testid="verdict-filter"]' BLOCK >/dev/null
for _ in $(seq 1 25); do N="$($AB get count '[data-testid="receipt-row"]')"; [ "$N" -eq 1 ] && break; sleep 0.2; done
[ "$N" -eq 1 ] || { echo "filtered rows: $N"; exit 1; }
echo "AC12 pass"
# AC13
start_console
$AB open "$BASE/#/audit" >/dev/null
$AB wait '[data-testid="audit-empty"]' >/dev/null
echo "AC13 pass"
```
