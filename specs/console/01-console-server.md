# Console server and web shell

Depends on: none

interlock is an in-process library with no network surface of its own. The
console gives an operator a local web UI over it: a small HTTP server built on
the Python standard library (`interlock/console/`) that serves a JSON API under
`/api/` and a React single-page app (`web/`) built with Vite. This spec delivers
the server skeleton, the security envelope every later endpoint inherits, and
the web shell (layout, navigation, overview page). Feature pages arrive in
specs 02 to 05.

## Inputs

- Command line: `python -m interlock.console [--host HOST] [--port PORT] [--static DIR]`,
  and the same through a console script named `interlock-console`.
- `--host` defaults to `127.0.0.1`. `--port` defaults to `7878`.
- `--static` defaults to `<repo root>/web/dist`, resolved from the location of
  the `interlock` package (`Path(interlock.__file__).resolve().parent.parent / "web" / "dist"`).
- HTTP requests from a browser on the same machine.

## Outputs

- On start, one line on stdout: `interlock console listening on http://<host>:<port>`.
- `GET /api/health` returns 200 with JSON `{"status": "ok", "version": <interlock.__version__>}`.
  Later specs add keys to this object; existing keys keep their meaning.
- Every `/api/` response is JSON with `Content-Type: application/json; charset=utf-8`,
  `Cache-Control: no-store`, and `X-Content-Type-Options: nosniff`.
- Errors use one shape: `{"error": {"code": "<snake_case_code>", "message": "<one sentence>"}}`.
- Any path outside `/api/` is served from the static directory. `/` serves
  `index.html`. HTML responses carry `X-Frame-Options: DENY` and a
  `Content-Security-Policy` whose `default-src` is `'self'`.
- When the static directory does not exist, `/` returns 200 `text/html` with a
  short page that says the web bundle is not built and names the command
  `npm --prefix web run build`.

## Errors

- Unknown `/api/` path: 404, code `not_found`.
- Known API path with a method it does not support: 405, code `method_not_allowed`.
- Request body larger than 1 MiB (1048576 bytes): 413, code `payload_too_large`,
  answered without reading the whole body.
- A `POST` whose `Content-Type` is not `application/json`: 415, code `unsupported_media_type`.
- A `POST` body that is not valid JSON: 400, code `bad_json`.
- A request whose `Host` header is not `127.0.0.1:<port>`, `localhost:<port>` or
  `[::1]:<port>`: 403, code `forbidden_host` (DNS-rebinding defence).
- `--host` set to anything other than `127.0.0.1`, `localhost` or `::1`: the
  process exits with status 2 before binding, and prints one line to stderr
  that contains the word `loopback`.

## Edge cases

- A static path that resolves outside the static directory (`/../pyproject.toml`,
  `/..%2f..%2fpyproject.toml`, symlinks pointing out) answers 404 and never
  returns the file.
- A static path that does not exist answers 404.
- Port already in use: exit status 1 with one line on stderr naming the port.
- `SIGINT` or `SIGTERM` shuts the server down and exits 0.

## Constraints

- The server uses only the Python standard library (`http.server.ThreadingHTTPServer`)
  and runs on Python 3.9. `[project] dependencies` in `pyproject.toml` stays `[]`.
- The server never binds a non-loopback address.
- No response carries CORS headers (`Access-Control-Allow-Origin` and friends);
  the API is same-origin only.
- Access log lines never contain request bodies, query strings or header values;
  method, path without query, status and duration only.
- Do not edit existing tests or existing modules under `interlock/` outside
  `interlock/console/`, except `pyproject.toml` (the console script) and the
  docs named below.
- The web app makes no request to any host other than the page's own origin:
  no CDN scripts, fonts or images. Everything is bundled.

## Architecture

- Package `interlock/console/` with `__init__.py`, `__main__.py` (CLI, `main(argv=None) -> int`)
  and `server.py` (request routing, JSON helpers, static serving, the error shape).
  Later specs add one module per feature and register their routes through a
  small route table in `server.py`, so a feature module never edits the request
  handler class.
- `pyproject.toml` `[project.scripts]` gains `interlock-console = "interlock.console.__main__:main"`.
- `web/` is a Vite + React 18 + TypeScript app with a committed `package-lock.json`.
  `package.json` scripts: `dev`, `build` (output `web/dist/`), `typecheck` (`tsc --noEmit`).
  The Vite dev server proxies `/api` to `http://127.0.0.1:7878`.
- Component tests use Vitest with jsdom and `@testing-library/react`. Every module under
  `web/src` that renders UI ships a sibling `<Name>.test.tsx`; the `test` script is `vitest run`.
- Routing is hash based: `#/` overview, `#/catalog`, `#/playground`, `#/audit`,
  `#/inspector`. Routes whose spec has not landed render a placeholder.
- `web/src/api.ts` holds the typed fetch helpers; an API error body is turned
  into a message the page shows to the user.
- Tests live in `tests/test_console_server.py`.
- Docs: `docs/guides/console.md` explains how to build the web bundle, launch the
  console and what every flag does; `docs/README.md` links to it.

## Look and feel

- A security console: dense, calm, readable. System font stack for text, a
  monospace stack for code, JSON and identifiers.
- The navigation bar has four links with `data-testid` values `nav-catalog`,
  `nav-playground`, `nav-audit` and `nav-inspector`; each is reachable by
  keyboard and shows a visible focus ring.
- The layout has no horizontal scrolling at 1280x800 or at 390x844.
- The overview page shows the API health in an element with
  `data-testid="health-status"`: its text contains `ok` and the version once
  `/api/health` answers, and contains `unreachable` when the request fails.

## Delivery order

- D1: the server, CLI, security envelope, console script and its tests.
- D2: the web shell (layout, navigation, overview, placeholder routes) and the docs page.

## Acceptance criteria

- AC1: `GET /api/health` answers 200 with `status == "ok"`, `version` equal to
  `interlock.__version__`, and the three JSON headers from Outputs.
- AC2: `--host 0.0.0.0` exits with status 2 within 5 seconds, stderr contains
  `loopback`, and the requested port accepts no connection.
- AC3: an unknown API path answers 404 with error code `not_found`, and `DELETE /api/health` answers 405 with code `method_not_allowed`.
- AC4: a request with `Host: evil.example` answers 403 with code `forbidden_host`.
- AC5: `/../pyproject.toml` and `/..%2f..%2fpyproject.toml` (sent with `curl --path-as-is`) answer 404 and the body never contains `[project]`.
- AC6: `python -m pytest -q tests/test_console_server.py` passes with at least 8 tests.
- AC7: `pyproject.toml` declares `interlock-console = "interlock.console.__main__:main"` and still declares `dependencies = []`.
- AC8: `npm --prefix web ci`, `npm --prefix web run typecheck` and `npm --prefix web run build` succeed and produce `web/dist/index.html`, and `web/dist/index.html` loads no script or stylesheet from an `http://` or `https://` URL.
- AC9 (UI): with the bundle built, the overview at `/#/` shows `data-testid="health-status"` containing `ok`, and the four nav links are present.
- AC11: `npm --prefix web test` passes with at least 3 tests.
- AC10 (precondition, passes before work starts): the full test suite shows no failure other than the three known pre-existing ones (`tests/test_scopes.py::test_unknown_template_is_ignored`, `tests/test_scopes.py::test_scoped_engine_allows_when_no_scope_and_no_default`, `tests/test_sidecar.py::test_a_second_writer_starts_a_new_chain`).

## Verify

```bash
set -euo pipefail
PY="${INTERLOCK_PY:-/Users/admin/micromamba/bin/python3}"
cd "${MO_TARGET_CWD:-/Volumes/docker-ssd/ps/interlock-console}"
WORK="$(mktemp -d)"; PIDS=""
trap 'for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"' EXIT
free_port() { "$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
start_console() {
  PORT="$(free_port)"; BASE="http://127.0.0.1:$PORT"
  "$PY" -m interlock.console --port "$PORT" "$@" >"$WORK/console-$PORT.log" 2>&1 &
  PIDS="$PIDS $!"
  for _ in $(seq 1 50); do curl -fsS "$BASE/api/health" >/dev/null 2>&1 && return 0; sleep 0.2; done
  echo "console did not come up"; cat "$WORK/console-$PORT.log"; return 1
}
# AC1
start_console
curl -sS -D "$WORK/h" -o "$WORK/b" "$BASE/api/health"
H="$WORK/h" B="$WORK/b" "$PY" - <<'PYEOF'
import json, os
import interlock
head = open(os.environ["H"]).read().lower()
body = json.load(open(os.environ["B"]))
assert head.startswith("http/1") and " 200 " in head.splitlines()[0], head.splitlines()[0]
assert "content-type: application/json; charset=utf-8" in head, head
assert "cache-control: no-store" in head, head
assert "x-content-type-options: nosniff" in head, head
assert body["status"] == "ok", body
assert body["version"] == interlock.__version__, body
PYEOF
echo "AC1 pass"
# AC2
PORT="$(free_port)"
set +e
timeout 5 "$PY" -m interlock.console --host 0.0.0.0 --port "$PORT" >"$WORK/out" 2>"$WORK/err"
RC=$?
set -e
[ "$RC" -eq 2 ] || { echo "exit status $RC"; cat "$WORK/err"; exit 1; }
grep -qi loopback "$WORK/err"
if curl -s --max-time 1 "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then echo "port answered"; exit 1; fi
echo "AC2 pass"
# AC3
start_console
CODE="$(curl -sS -o "$WORK/b" -w '%{http_code}' "$BASE/api/does-not-exist")"
[ "$CODE" = "404" ]
B="$WORK/b" "$PY" -c 'import json,os; assert json.load(open(os.environ["B"]))["error"]["code"] == "not_found"'
CODE="$(curl -sS -o "$WORK/b" -w '%{http_code}' -X DELETE "$BASE/api/health")"
[ "$CODE" = "405" ]
B="$WORK/b" "$PY" -c 'import json,os; assert json.load(open(os.environ["B"]))["error"]["code"] == "method_not_allowed"'
echo "AC3 pass"
# AC4
start_console
CODE="$(curl -sS -o "$WORK/b" -w '%{http_code}' -H 'Host: evil.example' "$BASE/api/health")"
[ "$CODE" = "403" ]
B="$WORK/b" "$PY" -c 'import json,os; assert json.load(open(os.environ["B"]))["error"]["code"] == "forbidden_host"'
echo "AC4 pass"
# AC5
start_console
for P in "/../pyproject.toml" "/..%2f..%2fpyproject.toml" "/%2e%2e/%2e%2e/pyproject.toml"; do
  CODE="$(curl -sS --path-as-is -o "$WORK/b" -w '%{http_code}' "$BASE$P")"
  [ "$CODE" = "404" ] || { echo "$P -> $CODE"; exit 1; }
  if grep -q '\[project\]' "$WORK/b"; then echo "$P leaked pyproject.toml"; exit 1; fi
done
echo "AC5 pass"
# AC6
"$PY" -m pytest -q -p no:cacheprovider tests/test_console_server.py >"$WORK/t" 2>&1 || { tail -30 "$WORK/t"; exit 1; }
T="$WORK/t" "$PY" - <<'PYEOF'
import os, re
out = open(os.environ["T"]).read()
m = re.search(r"(\d+) passed", out)
assert m and int(m.group(1)) >= 8, out[-400:]
assert not re.search(r"\b\d+ (failed|errors?)\b", out), out[-400:]
PYEOF
echo "AC6 pass"
# AC7
grep -Eq '^interlock-console = "interlock\.console\.__main__:main"$' pyproject.toml
grep -Eq '^dependencies = \[\]$' pyproject.toml
echo "AC7 pass"
# AC8
npm --prefix web ci --no-audit --no-fund >"$WORK/npm" 2>&1 || { tail -30 "$WORK/npm"; exit 1; }
npm --prefix web run typecheck >"$WORK/tc" 2>&1 || { tail -30 "$WORK/tc"; exit 1; }
npm --prefix web run build >"$WORK/build" 2>&1 || { tail -30 "$WORK/build"; exit 1; }
test -f web/dist/index.html
if grep -Eq '(src|href)="https?://' web/dist/index.html; then echo "external asset in index.html"; exit 1; fi
echo "AC8 pass"
# AC11
[ -d web/node_modules ] || npm --prefix web ci --no-audit --no-fund >"$WORK/npm" 2>&1
npm --prefix web test >"$WORK/vt" 2>&1 || { tail -30 "$WORK/vt"; exit 1; }
VT="$WORK/vt" "$PY" - <<'PYEOF'
import os, re
out = re.sub(r"\x1b\[[0-9;]*m", "", open(os.environ["VT"]).read())
m = re.search(r"Tests\s+(\d+) passed", out)
assert m and int(m.group(1)) >= 3, out[-400:]
assert not re.search(r"Tests\s+.*\d+ failed", out), out[-400:]
PYEOF
echo "AC11 pass"
# AC10 precondition
"$PY" -m pytest -q -p no:cacheprovider --ignore=rsi >"$WORK/full" 2>&1 || true
FULL="$WORK/full" "$PY" - <<'PYEOF'
import os, re
out = open(os.environ["FULL"]).read()
known = {
    "tests/test_scopes.py::test_unknown_template_is_ignored",
    "tests/test_scopes.py::test_scoped_engine_allows_when_no_scope_and_no_default",
    "tests/test_sidecar.py::test_a_second_writer_starts_a_new_chain",
}
failed = set(re.findall(r"^(?:FAILED|ERROR) (\S+?)(?: - .*)?$", out, re.M))
new = sorted(failed - known)
assert re.search(r"\d+ passed", out), out[-600:]
assert not new, "new failures: %s" % new
PYEOF
echo "AC10 pass"
```

```bash
set -euo pipefail
PY="${INTERLOCK_PY:-/Users/admin/micromamba/bin/python3}"
cd "${MO_TARGET_CWD:-/Volumes/docker-ssd/ps/interlock-console}"
WORK="$(mktemp -d)"; PIDS=""; ABS="sdd-shell-$$"
trap 'agent-browser --session "$ABS" close >/dev/null 2>&1 || true; for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"' EXIT
[ -d web/node_modules ] || npm --prefix web ci --no-audit --no-fund >"$WORK/npm" 2>&1
npm --prefix web run build >"$WORK/build" 2>&1 || { tail -30 "$WORK/build"; exit 1; }
PORT="$("$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
BASE="http://127.0.0.1:$PORT"
"$PY" -m interlock.console --port "$PORT" >"$WORK/console.log" 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 1 50); do curl -fsS "$BASE/api/health" >/dev/null 2>&1 && break; sleep 0.2; done
curl -fsS "$BASE/api/health" >/dev/null
AB="agent-browser --session $ABS"
# AC9
$AB open "$BASE/#/" >/dev/null
$AB wait '[data-testid="health-status"]' >/dev/null
for _ in $(seq 1 25); do TXT="$($AB get text '[data-testid="health-status"]')"; case "$TXT" in *ok*) break;; esac; sleep 0.2; done
case "$TXT" in *ok*) ;; *) echo "health-status text: $TXT"; exit 1;; esac
for T in nav-catalog nav-playground nav-audit nav-inspector; do
  N="$($AB get count "[data-testid=\"$T\"]")"; [ "$N" -ge 1 ] || { echo "missing $T"; exit 1; }
done
echo "AC9 pass"
```
