# Detector catalog

Depends on: 01-console-server

interlock ships one detector module per attack family under
`interlock/detectors/` (105 today). `scripts/gen_detector_catalog.py` already
reads them (docstring summary, rule factories and their signatures, the verdicts
each can return, the action names it is scoped to, its category) and renders
`docs/reference/detectors.md`. This spec moves that introspection into one
package module, serves it as JSON, and adds a catalog page to the console where
an operator browses, searches and reads every detector.

## Inputs

- `GET /api/detectors`.
- `GET /api/detectors/<module>`, where `<module>` is a detector module name.
- In the web app: the route `#/catalog`, a search box, and clicks on detector rows.

## Outputs

- `GET /api/detectors` answers 200 with:
  `{"count": N, "categories": [{"name", "description", "modules": [...]}], "detectors": [...]}`.
  `categories` are in the order the docs page lists them. `detectors` are in the
  order the docs page lists them.
- Each detector object: `{"module", "category", "summary", "factories", "verdicts", "scope", "configurable"}`.
  - `summary`: the first sentence of the module docstring, as the docs page shows it.
  - `factories`: one object per rule factory, `{"name", "signature", "params"}`. A rule
    factory is a public function defined in that module whose return annotation names `Rule`,
    the same definition the docs generator uses. `signature` is `str(inspect.signature(fn))`.
    `params` lists `{"name", "kind", "required", "default", "annotation"}`; `kind` is the
    `inspect.Parameter` kind name; `default` is the JSON value for a default that is
    `None`, a bool, int, float, str, or a list/tuple of those, otherwise its `repr()`
    string with `"default_repr": true` added to that param.
  - `verdicts`: the verdict names the module can return (`ALLOW`, `BLOCK`, `MODIFY`).
  - `scope`: the "Scoped to" text the docs page shows.
  - `configurable`: whether a factory takes a parameter that overrides its action names.
- `GET /api/detectors/<module>` answers 200 with the same detector object plus
  `"doc"`: the full module docstring (`inspect.getdoc(module)`).
- `/api/health` gains `"detectors": N`.

## Errors

- `GET /api/detectors/<module>` for a name that is not a detector module answers
  404 with code `unknown_detector`. A name that does not match `^[a-z0-9_]+$` is
  refused with the same 404 before any import is attempted.

## Edge cases

- The catalog never imports anything outside `interlock.detectors`; the module
  name from the URL is only ever compared against the list of detector modules.
- The catalog is built once per process and reused.
- A detector whose module docstring is missing still appears, with an empty summary.

## Constraints

- One implementation of the category table and of the per-module facts, used
  by both the console and `scripts/gen_detector_catalog.py`, so the docs page
  and the console cannot drift. Regenerating the docs page after this change
  produces no diff: `python scripts/gen_detector_catalog.py --check` exits 0.
- Standard library only; Python 3.9.
- Do not edit existing tests, detector modules, or `docs/reference/detectors.md`.

## Architecture

- `interlock/console/catalog.py` holds the category table and the introspection,
  and exposes `build_catalog() -> dict` (the `/api/detectors` body) and
  `detector_detail(module_name) -> dict` (raises `KeyError` for an unknown name).
- `scripts/gen_detector_catalog.py` imports its category table and per-module
  facts from `interlock.console.catalog` and keeps only the Markdown rendering.
- Routes are registered through the route table from spec 01.
- Tests live in `tests/test_console_catalog.py`.

## Catalog page

- `#/catalog` renders one row per detector module with `data-testid="detector-row"`,
  grouped under one header per category with `data-testid="category-header"`.
- Each row shows the module name in monospace, its summary, and one chip per
  verdict whose text is the verdict name.
- A search box with `data-testid="catalog-search"` filters rows, case-insensitive,
  by module name, summary, or factory name. Category headers with no matching row are hidden.
- Clicking a row opens a detail panel with `data-testid="detector-detail"` showing
  every factory signature (each in an element with `data-testid="factory-signature"`),
  the verdicts, the scope text, and the full docstring.

- The page ships a sibling `*.test.tsx` (Vitest and Testing Library) that renders it against a mocked `/api/detectors` and checks search filtering.
## Delivery order

- D1: `interlock/console/catalog.py`, the docs generator refactor, the two routes, and their tests.
- D2: the catalog page.

## Acceptance criteria

- AC1: `GET /api/detectors` reports `count` equal to the number of modules in `interlock/detectors` and lists exactly those modules.
- AC2: every detector has a non-empty summary, at least one factory whose `signature` starts with `(`, verdicts drawn only from `ALLOW`, `BLOCK`, `MODIFY`, and a category that is one of the listed category names; `shell_injection_guard` lists a factory named `shell_injection_guard`.
- AC3: the category names equal the `##` headings that follow `## Categories` in `docs/reference/detectors.md`, in order, and every detector module appears in exactly one category.
- AC4: `GET /api/detectors/shell_injection_guard` answers 200 with `doc` equal to that module's `inspect.getdoc` text; `GET /api/detectors/os` and `GET /api/detectors/..%2fsink` answer 404 with code `unknown_detector`.
- AC5 (precondition, passes before work starts): `python scripts/gen_detector_catalog.py --check` exits 0.
- AC6: `scripts/gen_detector_catalog.py` imports from `interlock.console.catalog`, and `python -m pytest -q tests/test_console_catalog.py` passes with at least 5 tests.
- AC7 (UI): `#/catalog` shows as many `detector-row` elements as the API `count`, and as many `category-header` elements as there are categories.
- AC8 (UI): typing `shell_injection` into `catalog-search` leaves at least 1 and fewer than `count` rows, and the first remaining row contains `shell_injection`.
- AC9 (UI): clicking the first `detector-row` shows `detector-detail` with at least one `factory-signature` containing `(`.

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
curl -fsS -o "$WORK/b" "$BASE/api/detectors"
B="$WORK/b" "$PY" - <<'PYEOF'
import json, os, pkgutil
import interlock.detectors as pkg
mods = sorted(m.name for m in pkgutil.iter_modules(pkg.__path__) if not m.name.startswith("_"))
d = json.load(open(os.environ["B"]))
assert d["count"] == len(mods) == len(d["detectors"]), (d["count"], len(mods), len(d["detectors"]))
assert sorted(x["module"] for x in d["detectors"]) == mods
PYEOF
echo "AC1 pass"
# AC2
start_console
curl -fsS -o "$WORK/b" "$BASE/api/detectors"
B="$WORK/b" "$PY" - <<'PYEOF'
import json, os
d = json.load(open(os.environ["B"]))
names = {c["name"] for c in d["categories"]}
for x in d["detectors"]:
    assert x["summary"].strip(), x["module"]
    assert x["factories"], x["module"]
    for f in x["factories"]:
        assert f["name"] and f["signature"].startswith("("), (x["module"], f)
    assert set(x["verdicts"]) <= {"ALLOW", "BLOCK", "MODIFY"}, (x["module"], x["verdicts"])
    assert x["category"] in names, (x["module"], x["category"])
sig = [x for x in d["detectors"] if x["module"] == "shell_injection_guard"]
assert sig and "shell_injection_guard" in [f["name"] for f in sig[0]["factories"]]
PYEOF
echo "AC2 pass"
# AC3
start_console
curl -fsS -o "$WORK/b" "$BASE/api/detectors"
B="$WORK/b" "$PY" - <<'PYEOF'
import json, os, re
d = json.load(open(os.environ["B"]))
text = open("docs/reference/detectors.md").read()
after = text.split("\n## Categories\n", 1)[1]
headings = re.findall(r"^## (.+)$", after, re.M)
assert [c["name"] for c in d["categories"]] == headings, ([c["name"] for c in d["categories"]], headings)
seen = {}
for c in d["categories"]:
    for m in c["modules"]:
        seen[m] = seen.get(m, 0) + 1
mods = {x["module"] for x in d["detectors"]}
assert set(seen) == mods, sorted(mods ^ set(seen))
assert all(v == 1 for v in seen.values()), [k for k, v in seen.items() if v != 1]
PYEOF
echo "AC3 pass"
# AC4
start_console
curl -fsS -o "$WORK/b" "$BASE/api/detectors/shell_injection_guard"
B="$WORK/b" "$PY" - <<'PYEOF'
import importlib, inspect, json, os
d = json.load(open(os.environ["B"]))
mod = importlib.import_module("interlock.detectors.shell_injection_guard")
assert d["module"] == "shell_injection_guard"
assert d["doc"] == inspect.getdoc(mod), "doc differs"
PYEOF
for P in "/api/detectors/os" "/api/detectors/..%2fsink"; do
  CODE="$(curl -sS --path-as-is -o "$WORK/b" -w '%{http_code}' "$BASE$P")"
  [ "$CODE" = "404" ] || { echo "$P -> $CODE"; exit 1; }
  B="$WORK/b" "$PY" -c 'import json,os; assert json.load(open(os.environ["B"]))["error"]["code"] == "unknown_detector"'
done
echo "AC4 pass"
# AC5 precondition
"$PY" scripts/gen_detector_catalog.py --check
echo "AC5 pass"
# AC6
grep -Eq '^(from interlock\.console\.catalog import|from interlock\.console import catalog|import interlock\.console\.catalog)' scripts/gen_detector_catalog.py
"$PY" -m pytest -q -p no:cacheprovider tests/test_console_catalog.py >"$WORK/t" 2>&1 || { tail -30 "$WORK/t"; exit 1; }
T="$WORK/t" "$PY" - <<'PYEOF'
import os, re
out = open(os.environ["T"]).read()
m = re.search(r"(\d+) passed", out)
assert m and int(m.group(1)) >= 5, out[-400:]
assert not re.search(r"\b\d+ (failed|errors?)\b", out), out[-400:]
PYEOF
echo "AC6 pass"
```

```bash
set -euo pipefail
PY="${INTERLOCK_PY:-/Users/admin/micromamba/bin/python3}"
cd "${MO_TARGET_CWD:-/Volumes/docker-ssd/ps/interlock-console}"
WORK="$(mktemp -d)"; PIDS=""; ABS="sdd-catalog-$$"
trap 'agent-browser --session "$ABS" close >/dev/null 2>&1 || true; for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"' EXIT
[ -d web/node_modules ] || npm --prefix web ci --no-audit --no-fund >"$WORK/npm" 2>&1
npm --prefix web run build >"$WORK/build" 2>&1 || { tail -30 "$WORK/build"; exit 1; }
PORT="$("$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
BASE="http://127.0.0.1:$PORT"
"$PY" -m interlock.console --port "$PORT" >"$WORK/console.log" 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 1 50); do curl -fsS "$BASE/api/health" >/dev/null 2>&1 && break; sleep 0.2; done
curl -fsS -o "$WORK/cat.json" "$BASE/api/detectors"
TOTAL="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["count"])' "$WORK/cat.json")"
NCAT="$("$PY" -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["categories"]))' "$WORK/cat.json")"
AB="agent-browser --session $ABS"
$AB open "$BASE/#/catalog" >/dev/null
$AB wait '[data-testid="detector-row"]' >/dev/null
# AC7
N="$($AB get count '[data-testid="detector-row"]')"
[ "$N" -eq "$TOTAL" ] || { echo "rows $N != $TOTAL"; exit 1; }
C="$($AB get count '[data-testid="category-header"]')"
[ "$C" -eq "$NCAT" ] || { echo "headers $C != $NCAT"; exit 1; }
echo "AC7 pass"
# AC8
$AB fill '[data-testid="catalog-search"]' 'shell_injection' >/dev/null
for _ in $(seq 1 25); do N="$($AB get count '[data-testid="detector-row"]')"; [ "$N" -lt "$TOTAL" ] && break; sleep 0.2; done
[ "$N" -ge 1 ] && [ "$N" -lt "$TOTAL" ] || { echo "filtered rows: $N"; exit 1; }
FIRST="$($AB get text '[data-testid="detector-row"]')"
case "$FIRST" in *shell_injection*) ;; *) echo "first row: $FIRST"; exit 1;; esac
echo "AC8 pass"
# AC9
$AB click '[data-testid="detector-row"]' >/dev/null
$AB wait '[data-testid="detector-detail"]' >/dev/null
SIG="$($AB get text '[data-testid="factory-signature"]')"
case "$SIG" in *"("*) ;; *) echo "signature: $SIG"; exit 1;; esac
echo "AC9 pass"
```
