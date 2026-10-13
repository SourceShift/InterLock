# Scopes and sandbox inspector

Depends on: 03-policy-playground

interlock's scopes give each tenant and agent its own policy: templates (rule
factories) are bound at nodes of a scope tree such as `root/acme/agent42`, some
parameters union down the tree (allowlists), the rest are overridden by the more
specific binding, and a delegated binding may never grant more than its
delegator holds. BRACE then compiles the same resolved policy into a sandbox
profile for the subprocesses an agent launches. This spec lets an operator paste
a scope document, pick a principal, and see the resolved policy, the sandbox
profile it compiles to, which confinement tokens this host's backend actually
enforces for it, and optionally the verdict for one event under that scope.

## Inputs

- `POST /api/scopes/resolve` with JSON `{"document": {...}, "principal": "<a/b/c>", "event": {...}}`;
  `event` is optional and has the playground's event shape (spec 03).
- The document:
  `{"templates": {"<template_id>": template, ...}, "bindings": {"<scope path>": [binding, ...], ...}}`.
  - A template is either `{"detector": "<module>", "factory": "<name>", "union_params": ["..."]}`
    (a rule template, validated exactly as the playground validates a rule, with the
    binding's `params` passed as the factory's keyword arguments), or
    `{"containment": true, "union_params": [...]}`: a containment-only template that adds no
    rule and whose params only feed the sandbox profile (BRACE reads the template ids
    `egress_allowlist`, `sandbox_fs` and `sandbox_limits`). `union_params` is optional.
  - A scope path is segments joined by `/`, for example `root/acme`.
  - A binding is `{"template_id", "params", "enabled", "delegated_from"}`; `params` defaults
    to `{}`, `enabled` to true, `delegated_from` to null or a scope path.
- `GET /api/scopes/example` and `GET /api/sandbox`.
- In the web app: the route `#/inspector`.

## Outputs

- `POST /api/scopes/resolve` answers 200 with:
  - `scope`: the principal split on `/`.
  - `scope_backend`: `interlock.policy.scopes.SCOPE_BACKEND`.
  - `resolved`: `{template_id: {param: value}}` from `ScopeRegistry.resolve`, with every
    set or frozenset value rendered as a sorted list.
  - `sandbox`: `{"profile", "backend", "enforced", "not_enforced", "available_backends"}`.
    `profile` is the `interlock.brace.compile_profile(resolved)` result as an object with
    `read_paths`, `write_paths`, `allow_network`, `allowed_hosts` (sorted), `env_keys`
    (the environment's variable names only, sorted), `cpu_seconds`, `memory_mb`,
    `unshare_pid`, `workdir`. `backend` is `interlock.brace.select_backend().name`.
    `enforced` is `select_backend().wrap(profile, ["/usr/bin/true"]).enforced`, sorted;
    `not_enforced` is the sorted rest of `interlock.brace.KNOWN_TOKENS`.
  - `decision`: when an event was given, the playground's result object for that event
    evaluated by the engine compiled for this scope, with the event's principal set to the
    request's principal; otherwise null.
- `GET /api/scopes/example` answers 200 with `{"document", "principal", "event"}`: the
  example below, principal `root/acme/agent42`, and an `http_post` event to
  `https://evil.example/collect`.
- `GET /api/sandbox` answers 200 with `{"available_backends", "selected", "known_tokens"}`
  (`known_tokens` sorted).

The example document:

```json
{
  "templates": {
    "egress_allowlist": {"detector": "data_egress", "factory": "network_egress_guard", "union_params": ["allowed_hosts"]},
    "sandbox_limits": {"containment": true}
  },
  "bindings": {
    "root": [{"template_id": "egress_allowlist", "params": {"allowed_hosts": ["api.internal"]}}],
    "root/acme": [{"template_id": "egress_allowlist", "params": {"allowed_hosts": ["api.acme.com"]}}],
    "root/acme/agent42": [{"template_id": "sandbox_limits", "params": {"cpu_seconds": 5}}],
    "root/globex/bot1": []
  }
}
```

## Errors

Every error answers 400 with the shared error shape:

- `bad_document`: the document, a template or a binding is not the shape above, has a
  key outside that shape, has more than 64 scope paths or more than 32 templates.
- `bad_principal`: the principal is empty, has an empty segment, or more than 16 segments.
- `unknown_template`: a binding names a template id the document does not define
  (`interlock.policy.scopes.UnknownTemplate`).
- `delegation_over_grant` (`DelegationOverGrant`) and `delegation_depth_exceeded`
  (`DelegationDepthExceeded`), with the library's message.
- `unknown_detector`, `unknown_factory`, `bad_kwargs`, `factory_failed` and `bad_event`,
  exactly as the playground defines them.

## Edge cases

- A principal whose path has no bindings resolves to what its ancestors bind; a
  principal with no containment bindings gets the locked profile (no network, no paths).
- `enabled: false` removes an inherited binding at and below that node, as the library defines.
- The inspector computes a sandbox plan and never starts a process: no call to
  `subprocess`, `os.fork`, `os.exec*` or `Sandbox.run` happens while answering a request.

## Constraints

- Template rules come only from factories the detector catalog lists, validated
  by the playground's code; no other module is imported.
- Standard library only; Python 3.9. Do not edit existing tests, `interlock/policy/`
  or `interlock/brace/`.

## Architecture

- `interlock/console/inspector.py` builds the `ScopeTree` and `ScopeRegistry` from
  the document, reuses `interlock/console/playground.py` for rule validation and
  result encoding, and computes the sandbox plan. Routes are registered through
  the route table from spec 01.
- Tests live in `tests/test_console_inspector.py`; one of them replaces
  `subprocess.Popen` and `os.fork` with functions that fail the test, then resolves
  the example, to pin the never-spawn rule.

## Inspector page

- `#/inspector` loads `/api/scopes/example` into a JSON editor
  `data-testid="scope-doc-editor"`, the principal into `data-testid="principal-input"`
  and the event into `data-testid="scope-event-editor"`.
- `data-testid="resolve-button"` posts them. The result shows one
  `data-testid="resolved-template"` row per resolved template inside
  `data-testid="resolved-params"`; the sandbox profile inside
  `data-testid="sandbox-profile"` (network on or off and the allowed hosts, paths,
  limits); the backend name in `data-testid="backend-name"`; the enforced tokens in
  `data-testid="enforced-tokens"` and the tokens this backend does not enforce in
  `data-testid="not-enforced-tokens"`, so a missing guarantee is visible rather than implied;
  and, when an event was given, the verdict in `data-testid="scope-verdict"` using the
  playground's verdict badge.
- An API error shows `data-testid="scope-error"` with the error code and message.

- The page ships a sibling `*.test.tsx` (Vitest and Testing Library) that renders it against mocked `/api/scopes/example` and `/api/scopes/resolve` responses and checks the error display.
## Delivery order

- D1: `interlock/console/inspector.py`, the three routes, and their tests.
- D2: the inspector page.

## Acceptance criteria

- AC1: resolving the example for `root/acme/agent42` yields `allowed_hosts` `["api.acme.com", "api.internal"]` for `egress_allowlist` and `cpu_seconds` 5 for `sandbox_limits`.
- AC2: the same response's sandbox profile has `allow_network` true, `allowed_hosts` `["api.acme.com", "api.internal"]` and `cpu_seconds` 5; `backend`, `enforced` and `not_enforced` equal what `interlock.brace` computes for that profile on this host.
- AC3: resolving the example for `root/globex/bot1` yields `allowed_hosts` `["api.internal"]` and a profile with `cpu_seconds` null.
- AC4: under the example, an `http_post` to `https://evil.example/collect` as `root/acme/agent42` answers BLOCK, to `https://api.acme.com/notes` as `root/acme/agent42` answers ALLOW, and to `https://api.acme.com/notes` as `root/globex/bot1` answers BLOCK.
- AC5: adding an `egress_allowlist` binding for `exfil.example` at `root/acme/agent42` with `delegated_from` `root/globex` answers `delegation_over_grant`; a binding to template `nope` answers `unknown_template`; principal `""` answers `bad_principal`; a binding with key `param` answers `bad_document`.
- AC6: `GET /api/sandbox` reports `available_backends`, `selected` and `known_tokens` equal to what `interlock.brace` reports on this host.
- AC7: `python -m pytest -q tests/test_console_inspector.py` passes with at least 8 tests.
- AC8 (UI): on `#/inspector`, pressing resolve with the prefilled example shows 2 `resolved-template` rows and a `backend-name` equal to the host's selected backend.
- AC9 (UI): changing `principal-input` to `root/globex/bot1` and pressing resolve shows a `sandbox-profile` containing `api.internal` and not `api.acme.com`.
- AC10 (UI): pressing resolve with the over-grant document from AC5 shows `scope-error` containing `delegation_over_grant`.

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
cat >"$WORK/doc.json" <<'JSON'
{"templates": {"egress_allowlist": {"detector": "data_egress", "factory": "network_egress_guard", "union_params": ["allowed_hosts"]},
               "sandbox_limits": {"containment": true}},
 "bindings": {"root": [{"template_id": "egress_allowlist", "params": {"allowed_hosts": ["api.internal"]}}],
              "root/acme": [{"template_id": "egress_allowlist", "params": {"allowed_hosts": ["api.acme.com"]}}],
              "root/acme/agent42": [{"template_id": "sandbox_limits", "params": {"cpu_seconds": 5}}],
              "root/globex/bot1": []}}
JSON
resolve() {  # principal [event-json] -> CODE, body in $WORK/b
  DOC="$WORK/doc.json" PRINCIPAL="$1" EVENT="${2:-}" "$PY" - >"$WORK/req" <<'PYEOF'
import json, os
body = {"document": json.load(open(os.environ["DOC"])), "principal": os.environ["PRINCIPAL"]}
if os.environ["EVENT"]:
    body["event"] = json.loads(os.environ["EVENT"])
print(json.dumps(body))
PYEOF
  CODE="$(curl -sS -o "$WORK/b" -w '%{http_code}' -H 'Content-Type: application/json' --data-binary @"$WORK/req" "$BASE/api/scopes/resolve")"
}
start_console
# AC1
resolve root/acme/agent42; [ "$CODE" = "200" ] || { cat "$WORK/b"; exit 1; }
B="$WORK/b" "$PY" - <<'PYEOF'
import json, os
d = json.load(open(os.environ["B"]))
assert d["scope"] == ["root", "acme", "agent42"], d["scope"]
assert d["resolved"]["egress_allowlist"]["allowed_hosts"] == ["api.acme.com", "api.internal"], d["resolved"]
assert d["resolved"]["sandbox_limits"]["cpu_seconds"] == 5, d["resolved"]
PYEOF
echo "AC1 pass"
# AC2
resolve root/acme/agent42; [ "$CODE" = "200" ] || { cat "$WORK/b"; exit 1; }
B="$WORK/b" "$PY" - <<'PYEOF'
import json, os
from interlock.brace import KNOWN_TOKENS, compile_profile, select_backend
d = json.load(open(os.environ["B"]))
s = d["sandbox"]
p = s["profile"]
assert p["allow_network"] is True and p["allowed_hosts"] == ["api.acme.com", "api.internal"] and p["cpu_seconds"] == 5, p
backend = select_backend()
profile = compile_profile({"egress_allowlist": {"allowed_hosts": {"api.acme.com", "api.internal"}}, "sandbox_limits": {"cpu_seconds": 5}})
enforced = sorted(backend.wrap(profile, ["/usr/bin/true"]).enforced)
assert s["backend"] == backend.name, s["backend"]
assert s["enforced"] == enforced, (s["enforced"], enforced)
assert s["not_enforced"] == sorted(set(KNOWN_TOKENS) - set(enforced)), s["not_enforced"]
PYEOF
echo "AC2 pass"
# AC3
resolve root/globex/bot1; [ "$CODE" = "200" ] || { cat "$WORK/b"; exit 1; }
B="$WORK/b" "$PY" - <<'PYEOF'
import json, os
d = json.load(open(os.environ["B"]))
assert d["resolved"]["egress_allowlist"]["allowed_hosts"] == ["api.internal"], d["resolved"]
assert d["sandbox"]["profile"]["cpu_seconds"] is None, d["sandbox"]["profile"]
PYEOF
echo "AC3 pass"
# AC4
check_verdict() {  # principal url expected
  resolve "$1" "{\"action\": \"http_post\", \"args\": {\"url\": \"$2\", \"body\": \"hi\"}}"
  [ "$CODE" = "200" ] || { cat "$WORK/b"; exit 1; }
  WANT="$3" B="$WORK/b" "$PY" -c 'import json,os; d=json.load(open(os.environ["B"])); assert d["decision"]["verdict"] == os.environ["WANT"], d["decision"]'
}
check_verdict root/acme/agent42 https://evil.example/collect BLOCK
check_verdict root/acme/agent42 https://api.acme.com/notes ALLOW
check_verdict root/globex/bot1 https://api.acme.com/notes BLOCK
echo "AC4 pass"
# AC5
expect_error() {  # code
  [ "$CODE" = "400" ] || { echo "status $CODE"; cat "$WORK/b"; exit 1; }
  WANT="$1" B="$WORK/b" "$PY" -c 'import json,os; e=json.load(open(os.environ["B"]))["error"]; assert e["code"] == os.environ["WANT"], e'
}
"$PY" - "$WORK/doc.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["bindings"]["root/acme/agent42"].append({"template_id": "egress_allowlist", "params": {"allowed_hosts": ["exfil.example"]}, "delegated_from": "root/globex"})
json.dump(d, open(sys.argv[1], "w"))
PYEOF
resolve root/acme/agent42; expect_error delegation_over_grant
"$PY" - "$WORK/doc.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["bindings"]["root/acme/agent42"] = [{"template_id": "nope", "params": {}}]
json.dump(d, open(sys.argv[1], "w"))
PYEOF
resolve root/acme/agent42; expect_error unknown_template
"$PY" - "$WORK/doc.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["bindings"]["root/acme/agent42"] = [{"template_id": "sandbox_limits", "param": {"cpu_seconds": 5}}]
json.dump(d, open(sys.argv[1], "w"))
PYEOF
resolve root/acme/agent42; expect_error bad_document
resolve ""; expect_error bad_principal
echo "AC5 pass"
# AC6
curl -fsS -o "$WORK/b" "$BASE/api/sandbox"
B="$WORK/b" "$PY" - <<'PYEOF'
import json, os
from interlock.brace import KNOWN_TOKENS, available_backends, select_backend
d = json.load(open(os.environ["B"]))
assert d["available_backends"] == available_backends(), d
assert d["selected"] == select_backend().name, d
assert d["known_tokens"] == sorted(KNOWN_TOKENS), d
PYEOF
echo "AC6 pass"
# AC7
"$PY" -m pytest -q -p no:cacheprovider tests/test_console_inspector.py >"$WORK/t" 2>&1 || { tail -30 "$WORK/t"; exit 1; }
T="$WORK/t" "$PY" - <<'PYEOF'
import os, re
out = open(os.environ["T"]).read()
m = re.search(r"(\d+) passed", out)
assert m and int(m.group(1)) >= 8, out[-400:]
assert not re.search(r"\b\d+ (failed|errors?)\b", out), out[-400:]
PYEOF
echo "AC7 pass"
```

```bash
set -euo pipefail
PY="${INTERLOCK_PY:-/Users/admin/micromamba/bin/python3}"
cd "${MO_TARGET_CWD:-/Volumes/docker-ssd/ps/interlock-console}"
WORK="$(mktemp -d)"; PIDS=""; ABS="sdd-inspector-$$"
trap 'agent-browser --session "$ABS" close >/dev/null 2>&1 || true; for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"' EXIT
[ -d web/node_modules ] || npm --prefix web ci --no-audit --no-fund >"$WORK/npm" 2>&1
npm --prefix web run build >"$WORK/build" 2>&1 || { tail -30 "$WORK/build"; exit 1; }
PORT="$("$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
BASE="http://127.0.0.1:$PORT"
"$PY" -m interlock.console --port "$PORT" >"$WORK/console.log" 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 1 50); do curl -fsS "$BASE/api/health" >/dev/null 2>&1 && break; sleep 0.2; done
curl -fsS "$BASE/api/health" >/dev/null
SELECTED="$("$PY" -c 'from interlock.brace import select_backend; print(select_backend().name)')"
AB="agent-browser --session $ABS"
$AB open "$BASE/#/inspector" >/dev/null
$AB wait '[data-testid="resolve-button"]' >/dev/null
for _ in $(seq 1 25); do D="$($AB get value '[data-testid="scope-doc-editor"]')"; case "$D" in *egress_allowlist*) break;; esac; sleep 0.2; done
# AC8
$AB click '[data-testid="resolve-button"]' >/dev/null
$AB wait '[data-testid="resolved-template"]' >/dev/null
N="$($AB get count '[data-testid="resolved-template"]')"
[ "$N" -eq 2 ] || { echo "resolved templates: $N"; exit 1; }
B="$($AB get text '[data-testid="backend-name"]')"
case "$B" in *"$SELECTED"*) ;; *) echo "backend-name: $B, wanted $SELECTED"; exit 1;; esac
echo "AC8 pass"
# AC9
$AB fill '[data-testid="principal-input"]' 'root/globex/bot1' >/dev/null
$AB click '[data-testid="resolve-button"]' >/dev/null
for _ in $(seq 1 25); do P="$($AB get text '[data-testid="sandbox-profile"]' 2>/dev/null || true)"; case "$P" in *api.acme.com*) sleep 0.2;; *api.internal*) break;; *) sleep 0.2;; esac; done
case "$P" in *api.acme.com*) echo "profile still lists api.acme.com: $P"; exit 1;; *api.internal*) ;; *) echo "profile: $P"; exit 1;; esac
echo "AC9 pass"
# AC10
cat >"$WORK/overgrant.json" <<'JSON'
{"templates": {"egress_allowlist": {"detector": "data_egress", "factory": "network_egress_guard", "union_params": ["allowed_hosts"]}},
 "bindings": {"root": [{"template_id": "egress_allowlist", "params": {"allowed_hosts": ["api.internal"]}}],
              "root/acme/agent42": [{"template_id": "egress_allowlist", "params": {"allowed_hosts": ["exfil.example"]}, "delegated_from": "root/globex"}]}}
JSON
$AB fill '[data-testid="scope-doc-editor"]' "$(cat "$WORK/overgrant.json")" >/dev/null
$AB fill '[data-testid="principal-input"]' 'root/acme/agent42' >/dev/null
$AB click '[data-testid="resolve-button"]' >/dev/null
$AB wait '[data-testid="scope-error"]' >/dev/null
E="$($AB get text '[data-testid="scope-error"]')"
case "$E" in *delegation_over_grant*) ;; *) echo "scope-error: $E"; exit 1;; esac
echo "AC10 pass"
```
