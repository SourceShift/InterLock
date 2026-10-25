# Security model known gaps — audit and work queue

Created: 2026-10-25T18:22:01+02:00
Source: [`docs/security-model.md`](../security-model.md) "Known gaps" (17 bullets,
last written in `c09c6df`, 2026-10-24 20:09).

Each gap was checked against the code on `origin/main` @ `8b481a7`. Verdicts:
**open** (limitation still real), **partial** (limitation real but the text is
stale or a mitigation shipped), **closed** (no longer true — doc fix only).

## Audit summary

| # | Gap (short) | Verdict | Evidence |
|---|---|---|---|
| 1 | Python import-time hooks | **open** | no `sys.meta_path`/`sitecustomize`; `ROADMAP.md:65` R11 not started |
| 2 | MCP trust labels depend on adapter | **closed** | `92eeced` — labels ride `SensorEvent.labels`; reserved keys stripped at every boundary |
| 3 | Approvals run in the agent's process | **partial** | in-process `set_approver` unchanged; review queue + console approval shipped |
| 4 | Review queue trusts its file | **partial** | still unsigned SQLite; `0o700/0o600` + path guard added |
| 5 | Shell parsing best-effort | **partial** | ANSI-C `$'\x..'` now decoded; base64 + staged download still pass; "add-only" claim is false |
| 6 | SQL analysis + masking best-effort | **open** | `interlock/sql/lexer.py`, no AST dep; `interlock/masking.py:35` |
| 7 | Coding-agent hooks cooperative | **open** | `interlock/adapters/base.py:25-27` capability matrix |
| 8 | No measured false-positive rate | **partial** | closed for the default pack by T07 (committed corpus, 0/70, CI gate); other policies still unmeasured |
| 9 | Per-host egress needs root | **open** | no backend exists between bwrap all-or-none and root nftables |
| 10 | macOS can't confine reads / visibility / memory | **open** | `sandbox_exec.py:109,122`; `limits.py:59-67` |
| 11 | `setsid()` descendant survives timeout kill | **partial** | bwrap `--unshare-pid` + `--die-with-parent` reclaims it; Windows still direct child only |
| 12 | Write confinement differs by backend | **open (accurate)** | `sandbox.py:155-191`; `python-api.md:1036` contradicts the scratch exception |
| 13 | CPU/memory reported only by `soft` | **open** | `tests/test_brace_limits.py:73-79` pins the absence |
| 14 | Truncated tail needs an outside record | **open** | `head=` exists (`sink.py:89-108`); no automatic anchor |
| 15 | Receipts prove integrity, not authorship | **open** | `verifier=` seam exists; no bundled public-key signer for receipts |
| 16 | Node.js unguardable shapes | **open** | `js/src/install.ts:43-81` still lists `*Sync`, stream openers, `spawn` |
| 17 | Node.js depends on a sidecar | **open (by design)** | `deny` default; `degraded`/`allow` are documented weakenings |

---

## T01 — Correct the MCP trust-label gap text

**Status:** not started

- **Rewrite the bullet in `docs/security-model.md`**
  - status: not started
  - last worked on: 2026-10-25 (validation)
  - remaining: delete/replace the "never copy those keys from model-generated
    arguments" bullet. New text: trust facts live on `SensorEvent.labels`;
    reserved `__*__` keys are stripped at every model-facing boundary
    (`interlock/interceptors/mcp.py:77,154`, `interlock/event.py:19-28`);
    only trusted code can set a label.
- **Fix the stale caveat in `docs/guides/mcp.md:533`**
  - status: not started
  - last worked on: —
  - remaining: "Labels are trusted as given" contradicts `92eeced`; keep the
    hand-built-event caveat but state that reserved keys are stripped and a
    caller must pass `labels=`, not `args`.

## T02 — Correct the shell-parsing gap and the add-only claim

**Status:** not started

- **Update the gap bullet** (`docs/security-model.md:92-96`)
  - status: not started
  - last worked on: 2026-10-25
  - remaining: remove `$'\x72\x6d'` from the "gets past it" list — ANSI-C
    quoting is decoded (`interlock/shell/parser.py:226-232,295-300,830-883`,
    `tests/test_redteam_regressions.py:117-122`). Keep base64 and downloaded
    scripts as live evasions.
- **Decide and document the add-only invariant**
  - status: not started
  - last worked on: —
  - remaining: `destructive_command_guard.py:188-201` discards a raw-text
    match when a complete parse finds no destructive intent (`echo rm -rf /`
    is allowed, `test_rt_027`). Either say "the parse may clear a raw match
    when the command is a pure print" in the guard docstring and security
    model, or make the union truly add-only. Pick one; today code and docs
    disagree.
- **Sweep duplicate stale claims**
  - status: not started
  - last worked on: —
  - remaining: `docs/guides/coding-agents.md:227-228`,
    `docs/guides/detectors.md:388-389`, `interlock/shell/parser.py:34-36`,
    `interlock/detectors/command_intent_guard.py:34-36`.

## T03 — Correct the sandbox timeout and scratch-removal text

**Status:** not started

- **Qualify the `setsid()` sentence**
  - status: not started
  - last worked on: 2026-10-25
  - remaining: note that under bubblewrap `--unshare-pid` + `--die-with-parent`
    (`interlock/brace/backends/bubblewrap.py:60-74`) the kernel reaps a
    `setsid()` escapee when bwrap dies; the escape is live for `sandbox-exec`,
    `soft`, and Windows. Fix `docs/guides/sandbox.md:64-67` and
    `docs/security-model.md:123-127`.
- **Fix the scratch-removal contradiction**
  - status: not started
  - last worked on: —
  - remaining: `docs/reference/python-api.md:1036` says `run()` "removes it on
    every exit path"; the code deliberately leaves the scratch when an escaped
    descendant still holds it (`interlock/brace/sandbox.py:189-191,255-261`).

## T04 — Reconcile the false-positive measurement story

**Status:** not started

- **Update the gap bullet** (`docs/security-model.md:111-114`)
  - status: not started
  - last worked on: 2026-10-25
  - remaining: "a harness is planned" is stale — `interlock mesh harness`
    exists (`interlock/mesh/harness.py`, `CHANGELOG.md:48-50`). Restate the
    real gap: no committed benign corpus, no published per-detector number,
    no CI regression gate.
- **Fix README/ROADMAP self-contradiction**
  - status: not started
  - last worked on: —
  - remaining: `README.md:291-293` lists the harness as future work while
    `ROADMAP.md:1434` calls it shipped; `ROADMAP.md:375-376` says 767 cases
    across six categories, files hold 774 across seven.

## T05 — Update the approvals gap to include the review queue

**Status:** not started

- **Rewrite the bullet** (`docs/security-model.md:88-91`)
  - status: not started
  - last worked on: 2026-10-25
  - remaining: keep the in-process `set_approver` limit, but state that the
    durable queue (`interlock/reviews.py`) and the opt-in console route
    (`interlock/console/reviews_api.py`) let a human decide from another
    process; `docs/guides/approvals.md:117-124` omits the queue entirely.

## T06 — Close shell evasion: encoded payloads and staged downloads

**Status:** not started

- **Decode base64 payloads before intent analysis**
  - status: not started
  - last worked on: —
  - remaining: `echo cm0gLXJmIC8= | base64 -d | sh` yields no critical
    intent. `base64_payload_scan` decodes but only for injection markers
    (`interlock/detectors/base64_payload_scan.py:42-66`). Reuse the decoder in
    the shell intent path; cap decoded size.
- **Track a fetched script that is executed later**
  - status: not started
  - last worked on: —
  - remaining: `_fetch_exec` only fires on a same-pipeline pipe
    (`interlock/shell/intents.py:531-550`); `curl -o /tmp/x.sh …; bash /tmp/x.sh`
    yields only `net.fetch`. Options: flag fetch-to-file followed by exec of
    the same literal path within one command string, or accept and document.
  - **Decision needed:** extending cross-command taint adds state to a
    stateless parser — confirm before building.

## T07 — Publish a false-positive number and gate it

**Status:** done (2026-10-25)

- **Commit a benign agent-traffic corpus**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `benchmarks/fp/benign.jsonl`, 70 events across file,
    git, build/test, search, fetch and MCP tools, call and result phases.
- **Publish per-detector FP + latency**
  - status: done (pack-level, not per-detector)
  - last worked on: 2026-10-25
  - remaining: none for the default pack — `scripts/fp_baseline.py` measures
    `builtin:coding-agent` at 0 false positives / 70 events, p95 ~2 ms; the
    table and its limits are in `benchmarks/fp/README.md` and the
    false-positive bullet of `docs/security-model.md`. Per-detector numbers for
    *other* policies are still not published; the harness measures them on
    demand.
- **Add a CI regression gate**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `tests/test_fp_baseline.py` asserts zero false positives
    and runs the harness gate, so the existing pytest CI job enforces it. The
    latency bound is widened 5x there to keep a slow runner from flaking.

## T08 — Bundle a public-key receipt signer

**Status:** not started

- **Wire Ed25519 into the receipt sink**
  - status: not started
  - last worked on: —
  - remaining: `verify(verifier=...)` seam exists (`interlock/receipt.py:305-354`)
    but no signer ships; HMAC stays the default. `interlock/mesh/ed25519.py`
    already implements the primitive for mesh metadata — extract it and offer
    `FileSink(key=..., signer="ed25519")`.
- **Document the key distribution model**
  - status: not started
  - last worked on: —
  - remaining: `docs/guides/audit-log.md:280-324` — who holds the private key,
    what a third party verifies.

## T09 — Give the review queue integrity and an owner

**Status:** not started — **decision needed**

- **Decide the threat model first**
  - status: not started
  - last worked on: —
  - remaining: today any writer can publish a row and `approve()` accepts a
    free-form `--as` (`interlock/reviews.py`, `docs/guides/reviews.md:110`).
    Directory is `0o700`, file `0o600`, and the coding-agent policy blocks
    writes to `~/.interlock` (`interlock/policy/packs.py:103-115`) — but that
    is access narrowing, not integrity.
  - **Options:** (a) HMAC the queue with a key the agent process lacks;
    (b) bind an approval row to a principal signature; (c) accept the file as
    trusted-by-location and say so in the gap text. Pick before coding.

## T10 — Contain Windows sandbox descendants

**Status:** not started

- **Kill the tree, not the child**
  - status: not started
  - last worked on: —
  - remaining: `interlock/brace/sandbox.py:274-291` uses `proc.kill()` on
    win32; the comment at `:277-279` names the fix — a Job Object with
    `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, or `taskkill /T`.

## T11 — Report `rlimit` from the OS backends

**Status:** not started

- **Join the guarantee matrix**
  - status: not started
  - last worked on: —
  - remaining: bwrap and Seatbelt apply CPU/memory limits but leave `rlimit`
    out of `enforced` (`backends/bubblewrap.py:70,118-120`,
    `backends/sandbox_exec.py:122,159-164`). Add the rows to
    `tests/integration/test_brace_token_matrix.py:286-305`, then append the
    token. Until then the doc is right and no change is needed — this task is
    only worth doing if the matrix grows a Linux/macOS rlimit row.

## T12 — Python import-time hooks (ROADMAP R11)

**Status:** not started — large

- **Design the import hook surface**
  - status: not started
  - last worked on: —
  - remaining: `ROADMAP.md:811-839` carries the design (one attach point for
    MCP clients and model SDKs). No `sys.meta_path` finder, no
    `sitecustomize`, no SDK monkey-patch exists; `interlock/__init__.py:102`
    is a placeholder and the `wrapt` extra is never imported.
  - Remaining parts: opt-in activation, double-wrap protection, an
    `uncovered` report like the Node client's, tests proving the same decision
    reaches a wrapped vs. hook-intercepted call.

## T13 — Node.js: report ESM named imports as uncovered

**Status:** not started

- **Add the missing entry**
  - status: not started
  - last worked on: —
  - remaining: ESM named imports (`import { readFile } from "node:fs/promises"`)
    are a proven bypass in `js/test/fs.test.ts:150` and documented in
    `js/README.md:274-291`, but are not an action name in
    `installInterceptors().uncovered` (`js/src/install.ts:43-81`). Adding the
    entry makes the hole machine-visible; the gap itself is unclosable.

## T14 — Register the accepted limitations

**Status:** not started

- **Mark four gaps as accepted, not queued**
  - status: not started
  - last worked on: 2026-10-25
  - remaining: SQL/masking semantics (T6 in the table), macOS read
    confinement, per-host egress without root, and Node's unguardable shapes
    are architectural, not backlog. Add a one-line "accepted" marker in
    `docs/security-model.md` so future audits do not re-open them. The
    coding-agent-hook cooperativeness gap is likewise inherent — the hooks
    are an in-agent adapter by definition.

## T15 — Memoize intent analysis per event (found during T07)

**Status:** not started

- **Stop re-parsing one Bash command once per intent rule**
  - status: not started
  - last worked on: 2026-10-25
  - remaining: `BuiltinEngine.evaluate` runs each rule in turn, and every rule
    with an `intent` condition calls `intents.analyze(event)`, which calls
    `parse()` again (`interlock/policy/declarative.py:1034` →
    `interlock/shell/intents.py:81`). A Bash event pays for ~12 parses; that is
    1.26 ms p50 versus 0.04 ms for a file tool, measured in
    `benchmarks/fp/README.md`. Cache `analyze(command, cwd)` for the length of
    one `evaluate()` call (an `lru_cache` keyed on both, or a per-engine
    memo cleared at entry). Near-zero behavioural risk if `cwd` is part of the
    key; expected to cut Bash cost by an order of magnitude.
