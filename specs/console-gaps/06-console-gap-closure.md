# Console gap closure

Depends on: none

Specs 01 to 05 delivered the interlock console, but their acceptance gates did
not cover every requirement the specs state, and a requirements audit found
those uncovered requirements partly or wholly unmet. This spec restates each
open requirement with its own executable gate. It changes only the console
(`interlock/console/`, `web/`, `tests/test_console_*.py`, `docs/guides/console.md`)
and keeps every gate of specs 01 to 05 passing.

Where specs 01 to 05 conflict, this spec decides: the live-tail delivery bound
("within 1 second of the append") wins over spec 04's "poll at most once per
second" line, so the poll interval stays below one second.

## Inputs

- The console CLI: `python -m interlock.console [--host] [--port] [--static] [--receipts] [--key-file]`.
- HTTP requests to `/api/*` and to static paths; signals SIGINT and SIGTERM.
- Receipt logs written by `interlock.sink.FileSink`, including damaged ones.

## Outputs

- Startup: once the socket is bound, exactly one line on stdout,
  `interlock console listening on http://<host>:<port>`, flushed immediately.
- Access log: one line on stderr per request, `<METHOD> <path without query> <status> <duration> ms`,
  and nothing else from that request: no query string, header value or body ever reaches stderr or stdout.
- `/api/health` carries every key its feature modules contribute: `status`, `version`,
  `detectors` (the catalog count), `receipts` and `verify`. Feature modules add keys through a
  contributor list in `server.py`; none of them replaces the health route.
- Every HTML response (the bundle's `index.html`, and the not-built page) carries
  `X-Frame-Options: DENY` and a `Content-Security-Policy` whose `default-src` is `'self'`.
- With a missing static directory, `GET /` answers 200 `text/html; charset=utf-8` and names
  the command `npm --prefix web run build`.
- Each catalog row shows one verdict chip per verdict, `data-testid="verdict-chip"`, whose text is the verdict name.
- Each page that loads from the API (overview, catalog, playground, audit, inspector) shows an API
  error's message in `data-testid="api-error"`.
- After a resolve, the inspector labels its two token lists visibly: `enforced-tokens` as "Enforced" and
  `not-enforced-tokens` as "Not enforced" (inside the element, through `aria-label`/`aria-labelledby`,
  or in the element just before it).
- The playground has the detector picker spec 03 requires: `data-testid="add-rule-select"` lists one option
  `module / factory` per catalog factory, and choosing one appends `{"detector", "factory", "kwargs": {}}`
  to the rules editor's JSON array.

## Errors

- Every error under `/api/`, including ones the standard library raises itself (501 unknown
  method, 400 malformed request line) and an unexpected exception in a handler (500
  `internal_error`), answers with the JSON error shape `{"error": {"code", "message"}}`;
  a handler exception never drops the connection.
- Every POST route reads its body through one shared reader in `server.py`: Content-Length above
  1048576 answers 413 `payload_too_large` without reading the body; a Content-Type other than
  `application/json` answers 415 `unsupported_media_type`; an unparseable body answers 400 `bad_json`.
- Port already in use: exit status 1 and exactly one stderr line, naming the port.
- A ninth concurrent receipt stream answers 503 `too_many_streams` in the JSON error shape.

## Edge cases

- SIGINT and SIGTERM stop the server and the process exits 0 with no traceback. The CLI installs its own
  handlers for both signals, so this holds even when it was started in the background with SIGINT ignored.
- A receipt-log line that is not valid UTF-8 is reported as `{"index": i, "unreadable": true}`;
  `/api/receipts`, `/api/receipts/verify` and the stream keep answering, and verify reports `broken`.
- A trailing line without a newline is invisible until it is terminated: it is neither counted,
  listed as unreadable, nor fed to verify.
- A stream whose client has gone away releases its slot within 2 seconds, so a reloaded audit
  page never meets a 503 from its own dead streams. A stream also ends when the server shuts down.
- At 390x844 no page scrolls sideways; a wide table scrolls inside its own container.
- A playground rewrite too deep or cyclic for the wire codec (it raises `RecursionError`) answers that
  event BLOCK with `policy_id` `console.unrepresentable` and `modified_args` null, like any other
  unrepresentable rewrite; later events are still evaluated.
- A playground rule with `"kwargs": null` answers 400 `bad_kwargs`: null is not an object (omit the
  key to mean no keyword arguments).
- An inspector scope document must carry both `templates` and `bindings`. Every `bindings` key, and every
  non-null `delegated_from`, is one or more non-empty segments joined by `/`; an empty key, or one with a
  leading, trailing or doubled `/`, answers 400 `bad_document` instead of being normalised (today `/root`
  silently replaces the `root` binding list).
- Inspector param values the scope library or `compile_profile` cannot handle (non-integer or oversized
  `cpu_seconds`/`memory_mb`, union params holding lists, objects or mixed types) answer 400 `bad_document`
  with a message; they never drop the connection.

## Constraints

- The console reads `--key-file` through `interlock.sidecar.__main__._read_key` (a `RulesError`
  becomes exit status 2) and keeps no copy of that reader.
- Standard library only; Python 3.9. Do not edit existing tests outside `tests/test_console_*.py`,
  and do not edit `interlock/sink.py`, `interlock/receipt.py`, the sidecar, or `specs/`.
- Every gate of specs 01 to 05 keeps passing.

## Architecture

- `interlock/console/inspector.py` builds every rule template through the playground's rule builder (a
  `playground` function whose name contains `build_rule`) and keeps no copy of its own
  `inspect.signature` binding.
- `server.py` owns the shared pieces: the JSON body reader, the error shape for standard-library
  errors, HTML security headers, the access log, and the health contributor list.
- `docs/guides/console.md` has one row per CLI flag (`--host`, `--port`, `--static`, `--receipts`,
  `--key-file`) and describes the startup line and the not-built page as they behave.
- The published docs site lists guides explicitly in `zensical.toml`'s `nav`; the console guide gets an
  entry there next to the other guides, so it is not an orphan page on the site.

## Delivery order

- D1: server envelope (startup line, access log, error shape, body reader, HTML headers,
  not-built page, port-in-use, signals, health contributors) and its tests.
- D2: audit robustness (shared key reader, non-UTF-8 lines, partial last line, stream cap,
  prompt slot release) and its tests.
- D3: playground and inspector robustness (codec recursion, null kwargs, scope-document validation,
  unhandled param values, shared rule builder) and their tests.
- D4: web fixes (verdict chips, detector picker, API error display, narrow-viewport layout) and the docs flags table.

## Acceptance criteria

- AC1: the startup line appears on stdout, exactly as specified, while the server is still running.
- AC2: `FOO /api/health` answers 501 with the JSON error shape and `application/json`, and a malformed request line (`GARBAGE`) is answered with a JSON error-shape body.
- AC3: `POST /api/evaluate` and `POST /api/scopes/resolve` each answer 413 `payload_too_large` to a declared 2000000-byte body, 415 `unsupported_media_type` to `text/plain`, and 400 `bad_json` to `{bad`.
- AC4: `GET /` carries `X-Frame-Options: DENY` and a CSP with `default-src 'self'`, both with a static directory holding an `index.html` and with a missing static directory; the latter answers 200 `text/html` naming `npm --prefix web run build`.
- AC5: with the port already bound by another process, the console exits 1 with exactly one stderr line containing the port number.
- AC6: SIGINT and SIGTERM each make the console exit 0 with no `Traceback` on stderr.
- AC7: a request carrying a query string and a header holding a marker value writes one stderr line matching `GET /api/health 200 <number> ms`, and the marker appears nowhere in the console's output.
- AC8: `/api/health` reports `detectors` equal to `/api/detectors` `count` and also `status`, `version`, `receipts` and `verify`.
- AC9: the console uses the sidecar's `_read_key`, defines no key reader of its own, and verifies a log signed with a raw (non-hex) key file.
- AC10: after a non-UTF-8 line is appended to a 3-receipt log, `/api/receipts` lists it as `{"index": 3, "unreadable": true}`, verify answers 200 with `broken`, and a stream still opens.
- AC11: a trailing line without a newline leaves `count_all` at 3 and verify `intact` with count 3.
- AC12: with 8 streams open, a ninth answers 503 `too_many_streams`.
- AC13: after 8 streams are opened and their clients close, 8 new streams all open within 3 seconds of the close with no 503, and with those 8 live a ninth is still refused with 503.
- AC14 (UI): `#/catalog` shows as many `verdict-chip` elements as the API reports verdicts in total.
- AC15 (UI): at 390x844 none of `#/`, `#/catalog`, `#/playground`, `#/audit` (with a 3-receipt log) and `#/inspector` scrolls sideways.
- AC16: every page module (`Overview`, `Catalog`, `Playground`, `Audit`, `Inspector`) renders `data-testid="api-error"`, a web test asserts an API error message is shown, and `npm --prefix web test` passes.
- AC17: `docs/guides/console.md` has a flags-table row for each of `--host`, `--port`, `--static`, `--receipts`, `--key-file`.
- AC18 (precondition, passes before work starts): the full test suite has no failures.
- AC19: a `pii_redaction_guard` evaluation whose body is nested 600 lists deep answers 200, with the first event BLOCK `console.unrepresentable` (`modified_args` null) and the second ALLOW.
- AC20: a rule with `"kwargs": null` answers 400 `bad_kwargs`.
- AC21: `tests/test_console_server.py` has a test in which a registered route raises and the reply is 500 `internal_error` in the JSON error shape, and that file passes.
- AC23: `zensical.toml`'s `nav` has an entry for `guides/console.md`.
- AC24: inspector `bindings` keys `root//acme`, `""`, `/root` and `root/` each answer 400 `bad_document`.
- AC25: a binding whose `delegated_from` is `""`, `root//acme`, `/root/acme` or `root/acme/` answers 400 `bad_document`.
- AC26: documents `{}`, `{"templates": {}}` and `{"bindings": {}}` answer 400 `bad_document`, and `{"templates": {}, "bindings": {}}` still resolves 200.
- AC27: inspector rule templates are built by the playground's rule builder (observed in-process), `inspector.py` makes no `signature()` call, and `bad_kwargs` / `factory_failed` still come back over HTTP.
- AC28: the seven unhandled param shapes (`cpu_seconds` `"abc"`, `[1]`, `2**70`; `memory_mb` `{}`; union values `[["n"]]`, `[{"h": 1}]`, `[1, "b"]`) each answer 400 `bad_document` with a message.
- AC29 (UI): after a resolve, `not-enforced-tokens` carries a visible "Not enforced" label and `enforced-tokens` an "Enforced" label.
- AC22 (UI): `add-rule-select` lists as many `module / factory` options as `/api/detectors` has factories, and choosing `execution_guard / execution_guard` after preset `egress` leaves 2 rules, the last being `{"detector": "execution_guard", "factory": "execution_guard", "kwargs": {}}`.

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
  "$PY" -m interlock.console --port "$PORT" "$@" >"$WORK/out-$PORT" 2>"$WORK/err-$PORT" &
  PIDS="$PIDS $!"; CPID=$!
  for _ in $(seq 1 50); do curl -fsS "$BASE/api/health" >/dev/null 2>&1 && return 0; sleep 0.2; done
  echo "console did not come up"; cat "$WORK/err-$PORT"; return 1
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
jcheck() { B="$WORK/b" "$PY" -c "import json,os; d=json.load(open(os.environ['B'])); $1"; }
# AC1
start_console
grep -qx "interlock console listening on http://127.0.0.1:$PORT" "$WORK/out-$PORT" || { echo "stdout: $(cat "$WORK/out-$PORT")"; exit 1; }
echo "AC1 pass"
# AC2
start_console
CODE="$(curl -sS -o "$WORK/b" -w '%{http_code} %{content_type}' -X FOO "$BASE/api/health")"
case "$CODE" in "501 application/json"*) ;; *) echo "FOO -> $CODE"; exit 1;; esac
jcheck 'assert d["error"]["code"] and d["error"]["message"], d'
PORT="$PORT" "$PY" - <<'PYEOF'
import json, os, socket
s = socket.create_connection(("127.0.0.1", int(os.environ["PORT"])), timeout=5)
s.sendall(b"GARBAGE\r\n\r\n")
data = b""
while True:
    chunk = s.recv(65536)
    if not chunk:
        break
    data += chunk
# The standard library answers an unparseable request line HTTP/0.9-style, with
# no status line or headers, so only the body's shape is asserted here.
body = data.partition(b"\r\n\r\n")[2] if data.startswith(b"HTTP/") else data
assert json.loads(body)["error"]["code"], data[:200]
PYEOF
echo "AC2 pass"
# AC3
start_console
for ROUTE in /api/evaluate /api/scopes/resolve; do
  ROUTE="$ROUTE" PORT="$PORT" "$PY" - <<'PYEOF'
import http.client, json, os
port, route = int(os.environ["PORT"]), os.environ["ROUTE"]
def post(body, ctype, clen=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.putrequest("POST", route, skip_host=True)
    c.putheader("Host", "127.0.0.1:%d" % port)
    c.putheader("Content-Type", ctype)
    c.putheader("Content-Length", str(len(body) if clen is None else clen))
    c.endheaders()
    c.send(body)
    r = c.getresponse()
    return r.status, json.loads(r.read())["error"]["code"]
assert post(b"{}", "application/json", 2000000) == (413, "payload_too_large"), route
assert post(b"{}", "text/plain") == (415, "unsupported_media_type"), route
assert post(b"{bad", "application/json") == (400, "bad_json"), route
PYEOF
done
echo "AC3 pass"
# AC4
mkdir -p "$WORK/static"; printf '<!doctype html><title>x</title>\n' >"$WORK/static/index.html"
for STATIC in "$WORK/static" "$WORK/no-such-dir"; do
  start_console --static "$STATIC"
  curl -sS -D "$WORK/h" -o "$WORK/b" "$BASE/"
  grep -qi '^x-frame-options: deny' "$WORK/h" || { echo "no XFO for $STATIC"; cat "$WORK/h"; exit 1; }
  grep -qi "^content-security-policy:.*default-src 'self'" "$WORK/h" || { echo "no CSP for $STATIC"; cat "$WORK/h"; exit 1; }
done
head -1 "$WORK/h" | grep -q ' 200 '
grep -qi '^content-type: text/html' "$WORK/h"
grep -q 'npm --prefix web run build' "$WORK/b"
echo "AC4 pass"
# AC5
PORT="$(free_port)"
"$PY" -c "import socket,time; s=socket.socket(); s.bind(('127.0.0.1', $PORT)); s.listen(); time.sleep(8)" &
PIDS="$PIDS $!"
sleep 0.5
set +e
timeout 6 "$PY" -m interlock.console --port "$PORT" >/dev/null 2>"$WORK/err"
RC=$?
set -e
[ "$RC" -eq 1 ] || { echo "exit $RC"; cat "$WORK/err"; exit 1; }
[ "$(grep -c . "$WORK/err")" -eq 1 ] || { echo "stderr lines:"; cat "$WORK/err"; exit 1; }
grep -q "$PORT" "$WORK/err"
echo "AC5 pass"
# AC6
for SIG in INT TERM; do
  start_console
  kill -"$SIG" "$CPID"
  for _ in $(seq 1 50); do kill -0 "$CPID" 2>/dev/null || break; sleep 0.1; done
  if kill -0 "$CPID" 2>/dev/null; then kill -9 "$CPID"; echo "still running 5s after SIG$SIG"; exit 1; fi
  set +e
  wait "$CPID"; RC=$?
  set -e
  [ "$RC" -eq 0 ] || { echo "SIG$SIG exit $RC"; exit 1; }
  if grep -q Traceback "$WORK/err-$PORT"; then echo "traceback on SIG$SIG"; exit 1; fi
done
echo "AC6 pass"
# AC7
start_console
curl -fsS "$BASE/api/health?token=QMARKER123" -H 'X-Probe: HMARKER456' >/dev/null
sleep 0.3
grep -Eq '^GET /api/health 200 [0-9]+(\.[0-9]+)? ?ms$' "$WORK/err-$PORT" || { echo "stderr:"; cat "$WORK/err-$PORT"; exit 1; }
if grep -q 'MARKER' "$WORK/err-$PORT" "$WORK/out-$PORT"; then echo "marker leaked"; exit 1; fi
echo "AC7 pass"
# AC8
mkfixture
start_console --receipts "$WORK/receipts.jsonl" --key-file "$WORK/key.hex"
curl -fsS -o "$WORK/cat" "$BASE/api/detectors"
curl -fsS -o "$WORK/b" "$BASE/api/health"
CAT="$WORK/cat" jcheck 'c=json.load(open(os.environ["CAT"]))["count"]; assert d.get("detectors") == c and {"status","version","receipts","verify"} <= set(d), d'
echo "AC8 pass"
# AC9
grep -Eq 'from (interlock|\.\.)\.sidecar\.__main__ import [^#]*_read_key|from (interlock|\.\.)\.sidecar import __main__' interlock/console/*.py
if grep -Eq 'def [a-z_]*read_key' interlock/console/*.py; then echo "console keeps its own key reader"; exit 1; fi
printf 'not-hex-raw-key-material' >"$WORK/raw.key"
"$PY" - "$WORK/raw.jsonl" <<'PYEOF'
import sys, time
from interlock.receipt import Receipt
from interlock.sink import FileSink
FileSink(sys.argv[1], key=b"not-hex-raw-key-material").write(Receipt(ts=time.time(), action="raw_key", verdict="ALLOW"))
PYEOF
start_console --receipts "$WORK/raw.jsonl" --key-file "$WORK/raw.key"
curl -fsS -o "$WORK/b" "$BASE/api/receipts/verify"
jcheck 'assert d["status"] == "intact" and d["count"] == 1, d'
echo "AC9 pass"
# AC10
mkfixture
printf '\xff\xfe not utf-8\n' >>"$WORK/receipts.jsonl"
start_console --receipts "$WORK/receipts.jsonl" --key-file "$WORK/key.hex"
curl -fsS -o "$WORK/b" "$BASE/api/receipts?order=asc"
jcheck 'assert {"index": 3, "unreadable": True} in d["receipts"], d["receipts"]'
CODE="$(curl -sS -o "$WORK/b" -w '%{http_code}' "$BASE/api/receipts/verify")"
[ "$CODE" = "200" ]
jcheck 'assert d["status"] == "broken", d'
curl -sN --max-time 2 -o "$WORK/sse" "$BASE/api/receipts/stream" || true
grep -q '^event: hello' "$WORK/sse"
echo "AC10 pass"
# AC11
mkfixture
printf '{"ts": 1.0, "action": "half_writ' >>"$WORK/receipts.jsonl"
start_console --receipts "$WORK/receipts.jsonl" --key-file "$WORK/key.hex"
curl -fsS -o "$WORK/b" "$BASE/api/receipts"
jcheck 'assert d["count_all"] == 3 and not any(r.get("unreadable") for r in d["receipts"]), d'
curl -fsS -o "$WORK/b" "$BASE/api/receipts/verify"
jcheck 'assert d["status"] == "intact" and d["count"] == 3, d'
echo "AC11 pass"
# AC12
mkfixture
start_console --receipts "$WORK/receipts.jsonl" --key-file "$WORK/key.hex"
CURLS=""
for i in 1 2 3 4 5 6 7 8; do curl -sN --max-time 6 -o /dev/null "$BASE/api/receipts/stream" & CURLS="$CURLS $!"; done
sleep 1.5
CODE="$(curl -sS --max-time 3 -o "$WORK/b" -w '%{http_code}' "$BASE/api/receipts/stream" || true)"
[ "$CODE" = "503" ] || { echo "ninth stream -> $CODE"; exit 1; }
jcheck 'assert d["error"]["code"] == "too_many_streams", d'
for c in $CURLS; do wait "$c" || true; done
echo "AC12 pass"
# AC13
mkfixture
start_console --receipts "$WORK/receipts.jsonl" --key-file "$WORK/key.hex"
CURLS=""
for i in 1 2 3 4 5 6 7 8; do curl -sN --max-time 2 -o /dev/null "$BASE/api/receipts/stream" & CURLS="$CURLS $!"; done
for c in $CURLS; do wait "$c" || true; done
sleep 3
CURLS=""
for i in 1 2 3 4 5 6 7 8; do
  curl -sN --max-time 2 -D "$WORK/h$i" -o /dev/null "$BASE/api/receipts/stream" & CURLS="$CURLS $!"
done
for c in $CURLS; do wait "$c" || true; done
for i in 1 2 3 4 5 6 7 8; do head -1 "$WORK/h$i" | grep -q ' 200 ' || { echo "stream $i: $(head -1 "$WORK/h$i")"; exit 1; }; done
# The refill only proves release if the cap is real: with 8 live streams a ninth must still be refused.
CURLS=""
for i in 1 2 3 4 5 6 7 8; do curl -sN --max-time 6 -o /dev/null "$BASE/api/receipts/stream" & CURLS="$CURLS $!"; done
sleep 1.5
CODE="$(curl -sS --max-time 3 -o /dev/null -w '%{http_code}' "$BASE/api/receipts/stream" || true)"
for c in $CURLS; do wait "$c" || true; done
[ "$CODE" = "503" ] || { echo "ninth stream after refill -> $CODE"; exit 1; }
echo "AC13 pass"
# AC16
for P in Overview Catalog Playground Audit Inspector; do
  F="$(ls web/src | grep -E "^$P\.tsx$" || true)"
  [ -n "$F" ] || { echo "no web/src/$P.tsx"; exit 1; }
  grep -q 'data-testid="api-error"' "web/src/$F" || { echo "$P has no api-error element"; exit 1; }
done
grep -lq 'api-error' web/src/*.test.tsx
[ -d web/node_modules ] || npm --prefix web ci --no-audit --no-fund >"$WORK/npm" 2>&1
npm --prefix web test >"$WORK/vt" 2>&1 || { tail -30 "$WORK/vt"; exit 1; }
echo "AC16 pass"
# AC17
for FLAG in --host --port --static --receipts --key-file; do
  grep -Eq "^\| \`$FLAG" docs/guides/console.md || { echo "no row for $FLAG"; exit 1; }
done
echo "AC17 pass"
# AC19
start_console
"$PY" - "$WORK/req" <<'PYEOF'
import json, sys
body = "Card on file: 4111 1111 1111 1111"
for _ in range(600):
    body = [body]
json.dump({"rules": [{"detector": "data_egress", "factory": "pii_redaction_guard"}],
           "events": [{"action": "http_post", "args": {"url": "https://api.acme.com/notes", "body": body}},
                      {"action": "http_post", "args": {"body": "weekly report"}}]}, open(sys.argv[1], "w"))
PYEOF
CODE="$(curl -sS -o "$WORK/b" -w '%{http_code}' -H 'Content-Type: application/json' --data-binary @"$WORK/req" "$BASE/api/evaluate" || true)"
[ "$CODE" = "200" ] || { echo "deep rewrite -> HTTP $CODE"; exit 1; }
jcheck 'r = d["results"]; assert (r[0]["verdict"], r[0]["policy_id"], r[0]["modified_args"]) == ("BLOCK", "console.unrepresentable", None), r[0]; assert r[1]["verdict"] == "ALLOW", r[1]'
echo "AC19 pass"
# AC20
start_console
echo '{"rules": [{"detector": "execution_guard", "factory": "execution_guard", "kwargs": null}], "events": [{"action": "x"}]}' >"$WORK/req"
CODE="$(curl -sS -o "$WORK/b" -w '%{http_code}' -H 'Content-Type: application/json' --data-binary @"$WORK/req" "$BASE/api/evaluate")"
[ "$CODE" = "400" ] || { echo "null kwargs -> $CODE"; exit 1; }
jcheck 'assert d["error"]["code"] == "bad_kwargs", d'
echo "AC20 pass"
# AC21
grep -q 'internal_error' tests/test_console_server.py || { echo "no internal_error test in tests/test_console_server.py"; exit 1; }
"$PY" -m pytest -q -p no:cacheprovider tests/test_console_server.py >"$WORK/t" 2>&1 || { tail -30 "$WORK/t"; exit 1; }
echo "AC21 pass"
# AC23
grep -Eq '"guides/console\.md"' zensical.toml || { echo "zensical.toml nav has no guides/console.md"; exit 1; }
echo "AC23 pass"
# AC24
start_console
PORT="$PORT" "$PY" - <<'PYEOF'
import http.client, json, os
def resolve(doc, principal):
    c = http.client.HTTPConnection("127.0.0.1", int(os.environ["PORT"]), timeout=10)
    c.request("POST", "/api/scopes/resolve", json.dumps({"document": doc, "principal": principal}), {"Content-Type": "application/json"})
    r = c.getresponse(); return r.status, json.loads(r.read())
EG = {"detector": "data_egress", "factory": "network_egress_guard", "union_params": ["allowed_hosts"]}
bind = lambda h: [{"template_id": "egress_allowlist", "params": {"allowed_hosts": [h]}}]
fails = []
for key in ["root//acme", "", "/root", "root/"]:
    st, b = resolve({"templates": {"egress_allowlist": EG}, "bindings": {"root": bind("a.example"), key: bind("b.example")}}, "root/acme")
    if st != 400 or b.get("error", {}).get("code") != "bad_document":
        fails.append((key, st, b.get("error") or b.get("resolved")))
assert not fails, "malformed scope path keys accepted: %r" % fails
PYEOF
echo "AC24 pass"
# AC25
start_console
PORT="$PORT" "$PY" - <<'PYEOF'
import http.client, json, os
def call(method, path, body=None):
    c = http.client.HTTPConnection("127.0.0.1", int(os.environ["PORT"]), timeout=10)
    c.request(method, path, None if body is None else json.dumps(body), {"Content-Type": "application/json"})
    r = c.getresponse(); return r.status, json.loads(r.read())
fails = []
for df in ["", "root//acme", "/root/acme", "root/acme/"]:
    doc = call("GET", "/api/scopes/example")[1]["document"]
    doc["bindings"]["root/acme/agent42"].append({"template_id": "egress_allowlist", "params": {"allowed_hosts": ["api.acme.com"]}, "delegated_from": df})
    st, b = call("POST", "/api/scopes/resolve", {"document": doc, "principal": "root/acme/agent42"})
    if st != 400 or b.get("error", {}).get("code") != "bad_document":
        fails.append((df, st, (b.get("error") or {}).get("code", "200 ok")))
assert not fails, "malformed delegated_from accepted or misreported: %r" % fails
PYEOF
echo "AC25 pass"
# AC26
start_console
PORT="$PORT" "$PY" - <<'PYEOF'
import http.client, json, os
def resolve(doc, principal):
    c = http.client.HTTPConnection("127.0.0.1", int(os.environ["PORT"]), timeout=10)
    c.request("POST", "/api/scopes/resolve", json.dumps({"document": doc, "principal": principal}), {"Content-Type": "application/json"})
    r = c.getresponse(); return r.status, json.loads(r.read())
fails = [(doc, st) for doc in [{}, {"templates": {}}, {"bindings": {}}]
         for st, b in [resolve(doc, "root")] if st != 400 or b.get("error", {}).get("code") != "bad_document"]
assert resolve({"templates": {}, "bindings": {}}, "root")[0] == 200, "the minimal complete document must still resolve"
assert not fails, "incomplete documents accepted: %r" % fails
PYEOF
echo "AC26 pass"
# AC27
start_console
PORT="$PORT" "$PY" - <<'PYEOF'
import http.client, json, os
def resolve(doc):
    c = http.client.HTTPConnection("127.0.0.1", int(os.environ["PORT"]), timeout=10)
    c.request("POST", "/api/scopes/resolve", json.dumps({"document": doc, "principal": "root"}), {"Content-Type": "application/json"})
    r = c.getresponse(); return r.status, json.loads(r.read())
EG = {"detector": "data_egress", "factory": "network_egress_guard"}
for params, code in [({"allowed_hosts": ["a"], "bogus": 1}, "bad_kwargs"), ({"allowed_hosts": 42}, "factory_failed")]:
    st, b = resolve({"templates": {"t": EG}, "bindings": {"root": [{"template_id": "t", "params": params}]}})
    assert st == 400 and b["error"]["code"] == code, (params, st, b)
PYEOF
PYTHONPATH="$PWD" "$PY" - <<'PYEOF'
import ast, copy, inspect as _inspect
import interlock.console.playground as pg
import interlock.console.inspector as ins
calls = []
for mod in (pg, ins):
    for name in [n for n in dir(mod) if "build_rule" in n.lower() and callable(getattr(mod, n))]:
        if getattr(getattr(mod, name), "__module__", "") != pg.__name__:
            continue
        orig = getattr(mod, name)
        def wrapper(*a, _o=orig, **k):
            calls.append(1)
            return _o(*a, **k)
        setattr(mod, name, wrapper)
ins.resolve_scope(copy.deepcopy(ins.EXAMPLE_DOCUMENT), "root/acme/agent42", None)
sig_calls = [n.lineno for n in ast.walk(ast.parse(_inspect.getsource(ins)))
             if isinstance(n, ast.Call) and getattr(n.func, "attr", getattr(n.func, "id", "")) == "signature"]
assert calls, "resolve_scope built its rule templates without the playground's rule builder"
assert not sig_calls, "inspector.py still calls signature() itself at line(s) %r" % sig_calls
PYEOF
echo "AC27 pass"
# AC28
start_console
PORT="$PORT" "$PY" - <<'PYEOF'
import http.client, json, os
def resolve(doc, principal):
    c = http.client.HTTPConnection("127.0.0.1", int(os.environ["PORT"]), timeout=10)
    try:
        c.request("POST", "/api/scopes/resolve", json.dumps({"document": doc, "principal": principal}), {"Content-Type": "application/json"})
        r = c.getresponse(); return r.status, json.loads(r.read())
    except Exception as e:
        return "no response", repr(e)
EG = {"detector": "data_egress", "factory": "network_egress_guard", "union_params": ["allowed_hosts"]}
limits = lambda p: {"templates": {"sandbox_limits": {"containment": True}}, "bindings": {"root": [{"template_id": "sandbox_limits", "params": p}]}}
hosts = lambda v: {"templates": {"egress_allowlist": EG}, "bindings": {"root": [{"template_id": "egress_allowlist", "params": {"allowed_hosts": ["a"]}}],
                                                                      "root/x": [{"template_id": "egress_allowlist", "params": {"allowed_hosts": v}}]}}
cases = {"cpu_seconds 'abc'": (limits({"cpu_seconds": "abc"}), "root"), "cpu_seconds [1]": (limits({"cpu_seconds": [1]}), "root"),
         "memory_mb {}": (limits({"memory_mb": {}}), "root"), "cpu_seconds 2**70": (limits({"cpu_seconds": 2 ** 70}), "root"),
         "union list of lists": (hosts([["n"]]), "root/x"), "union list of objects": (hosts([{"h": 1}]), "root/x"),
         "union mixed int/str": (hosts([1, "b"]), "root/x")}
fails = []
for name, (doc, principal) in cases.items():
    st, b = resolve(doc, principal)
    if not (st == 400 and isinstance(b, dict) and b.get("error", {}).get("code") == "bad_document" and b["error"].get("message")):
        fails.append((name, st, b if not isinstance(b, dict) else b.get("error")))
assert not fails, "\n".join(map(repr, fails))
PYEOF
echo "AC28 pass"
# AC18 precondition
"$PY" -m pytest -q -p no:cacheprovider --ignore=rsi >"$WORK/full" 2>&1 || { tail -30 "$WORK/full"; exit 1; }
echo "AC18 pass"
```

```bash
set -euo pipefail
PY="${INTERLOCK_PY:-/Users/admin/micromamba/bin/python3}"
cd "${MO_TARGET_CWD:-/Volumes/docker-ssd/ps/interlock-console}"
WORK="$(mktemp -d)"; PIDS=""; ABS="sdd-gaps-$$"
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
    sink.write(Receipt(ts=time.time(), action=action, verdict=verdict, reason="fixture " + action + " with a deliberately long reason that would widen an unwrapped table cell",
                       policy_id="fixture", principal="agent-1", args_digest="0" * 64))
PYEOF
PORT="$("$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
BASE="http://127.0.0.1:$PORT"
"$PY" -m interlock.console --port "$PORT" --receipts "$WORK/receipts.jsonl" --key-file "$WORK/key.hex" >"$WORK/console.log" 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 1 50); do curl -fsS "$BASE/api/health" >/dev/null 2>&1 && break; sleep 0.2; done
curl -fsS "$BASE/api/health" >/dev/null
AB="agent-browser --session $ABS"
# AC14
WANT="$(curl -fsS "$BASE/api/detectors" | "$PY" -c 'import json,sys; print(sum(len(x["verdicts"]) for x in json.load(sys.stdin)["detectors"]))')"
$AB open "$BASE/#/catalog" >/dev/null
$AB wait '[data-testid="verdict-chip"]' >/dev/null
N="$($AB get count '[data-testid="detector-row"] [data-testid="verdict-chip"]')"
[ "$N" -eq "$WANT" ] || { echo "chips $N != $WANT"; exit 1; }
echo "AC14 pass"
# AC15
$AB set viewport 390 844 >/dev/null
for ROUTE in "#/" "#/catalog" "#/playground" "#/audit" "#/inspector"; do
  $AB open "$BASE/$ROUTE" >/dev/null
  sleep 1.5
  R="$($AB eval '(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth && [...document.querySelectorAll("main")].every(m => m.scrollWidth <= m.clientWidth))()')"
  case "$R" in *true*) ;; *) echo "$ROUTE scrolls sideways ($R)"; exit 1;; esac
done
echo "AC15 pass"
# AC22
WANT="$(curl -fsS "$BASE/api/detectors" | "$PY" -c 'import json,sys; print(sum(len(d["factories"]) for d in json.load(sys.stdin)["detectors"]))')"
$AB set viewport 1280 800 >/dev/null
$AB open "$BASE/#/playground" >/dev/null
$AB wait '[data-testid="add-rule-select"]' >/dev/null
sleep 1
N="$($AB eval '[...document.querySelectorAll("[data-testid=add-rule-select] option")].filter(o => / \/ /.test(o.textContent)).length')"; N="${N//\"/}"
[ "$N" = "$WANT" ] || { echo "add-rule-select lists $N options, want $WANT"; exit 1; }
$AB select '[data-testid="preset-select"]' egress >/dev/null
VAL="$($AB eval '(() => { const o = [...document.querySelectorAll("[data-testid=add-rule-select] option")].find(o => o.textContent.trim() === "execution_guard / execution_guard"); return o ? o.value : ""; })()')"; VAL="${VAL//\"/}"
[ -n "$VAL" ] || { echo "no execution_guard / execution_guard option"; exit 1; }
$AB select '[data-testid="add-rule-select"]' "$VAL" >/dev/null
sleep 0.5
$AB get value '[data-testid="rules-editor"]' >"$WORK/rules"
"$PY" - "$WORK/rules" <<'PYEOF'
import json, sys
rules = json.loads(open(sys.argv[1]).read().strip())
if isinstance(rules, str):
    rules = json.loads(rules)
assert len(rules) == 2 and rules[0]["factory"] == "network_egress_guard", rules
assert rules[-1] == {"detector": "execution_guard", "factory": "execution_guard", "kwargs": {}}, rules[-1]
PYEOF
echo "AC22 pass"
# AC29
$AB set viewport 1280 800 >/dev/null
$AB open "$BASE/#/inspector" >/dev/null
$AB wait '[data-testid="resolve-button"]' >/dev/null
for _ in $(seq 1 25); do D="$($AB get value '[data-testid="scope-doc-editor"]')"; case "$D" in *egress_allowlist*) break;; esac; sleep 0.2; done
$AB click '[data-testid="resolve-button"]' >/dev/null
$AB wait '[data-testid="not-enforced-tokens"]' >/dev/null
label_of() {
  $AB eval "(() => { const el = document.querySelector('[data-testid=\"$1\"]'); const by = el.getAttribute('aria-labelledby'); return [el.textContent, el.getAttribute('aria-label') || '', by ? (document.getElementById(by) || {}).textContent || '' : '', el.previousElementSibling ? el.previousElementSibling.textContent : ''].join(' | ').toLowerCase(); })()"
}
NE="$(label_of not-enforced-tokens)"; EN="$(label_of enforced-tokens)"
case "$NE" in *"not enforced"*) ;; *) echo "not-enforced-tokens has no 'not enforced' label: $NE"; exit 1;; esac
case "$EN" in *enforced*) ;; *) echo "enforced-tokens has no 'enforced' label: $EN"; exit 1;; esac
echo "AC29 pass"
```
