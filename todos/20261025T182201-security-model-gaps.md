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
| 1 | Python import-time hooks | **partial** | MCP attached at import (`interlock/attach.py`, T12); model SDKs stay adapter-guarded — no class seam to wrap |
| 2 | MCP trust labels depend on adapter | **closed** | `92eeced` — labels ride `SensorEvent.labels`; reserved keys stripped at every boundary |
| 3 | Approvals run in the agent's process | **partial** | in-process `set_approver` unchanged; review queue + console approval shipped |
| 4 | Review queue trusts its file | **closed** | rows HMAC-signed with a key beside the DB (T09, `1547afc`) and a signed high-water mark refuses rollback replay (T19); a restore of database, key and mark together stays out of reach |
| 5 | Shell parsing best-effort | **closed for the two named evasions** | ANSI-C quoting, a base64 payload piped to a shell, and a staged fetched script are decoded/followed (T06, `192b6a8`); other encodings remain; "not add-only" is now documented |
| 6 | SQL analysis + masking best-effort | **open (accepted)** | `interlock/sql/lexer.py`, no AST dep; `interlock/masking.py:35`; T14 marks it accepted |
| 7 | Coding-agent hooks cooperative | **open (accepted)** | `interlock/adapters/base.py:25-27` capability matrix; inherent to an in-agent adapter (T14) |
| 8 | No measured false-positive rate | **closed for the default pack** | T07 + T17: two corpora (0/70 and 0/20 held-out), per-rule and per-detector tables, induced blocking 0/560, stress gate — all in CI; other policies are measured on demand |
| 9 | Per-host egress needs root | **open (accepted)** | no backend exists between bwrap all-or-none and root nftables (T14) |
| 10 | macOS can't confine reads / visibility / memory | **open (accepted)** | `sandbox_exec.py:109,122`; `limits.py:59-67`; Seatbelt cannot express these (T14) |
| 11 | `setsid()` descendant survives timeout kill | **partial** | bwrap `--unshare-pid` + `--die-with-parent`; Windows `taskkill /T /F` walks the tree (T10); a reparented process can still escape |
| 12 | Write confinement differs by backend | **open (accurate)** | `sandbox.py:155-191`; the scratch exception is now documented in `python-api.md` (T03) |
| 13 | CPU/memory reported only by `soft` | **closed** | every backend claims `rlimit` when a ceiling is set (T11); the token matrix carries an escape row for each |
| 14 | Truncated tail needs an outside record | **closed** | `head=` exists (`sink.py:89-108`) and `interlock anchor` records it outside the log, refusing to move backwards (T20) |
| 15 | Receipts prove integrity, not authorship | **closed** | `interlock/receipt_ed25519.py` ships signer + verifier, and the audit guide documents key distribution (T08, `e366c5c`) |
| 16 | Node.js unguardable shapes | **mitigated for ESM named imports; sync/handle openers accepted** | opt-in `registerEsmInterceptors` loader + `--import interlock-guard/esm-hook` preload close named/namespace imports and move `esm.named-import` to `covered`; the synchronous and handle-returning shapes stay in `installInterceptors().uncovered` (T13, `9d163a7`) |
| 17 | Node.js depends on a sidecar | **open (by design)** | `deny` default; `degraded`/`allow` are documented weakenings |

---

## T01 — Correct the MCP trust-label gap text

**Status:** done (2026-10-25, `db633bb`)

- **Rewrite the bullet in `docs/security-model.md`**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — the bullet now says trust facts live on
    `SensorEvent.labels`, reserved `__*__` keys are stripped at every
    model-facing boundary, and only trusted code can set a label.
- **Fix the stale caveat in `docs/guides/mcp.md`**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — the "trusted as given" caveat is gone; the guide keeps
    the hand-built-event caveat and states the stripping rule.

## T02 — Correct the shell-parsing gap and the add-only claim

**Status:** done (2026-10-25, `db633bb` + `192b6a8`)

- **Update the gap bullet**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — ANSI-C decoding, base64 payloads and a fetched script
    run later are now described as covered; other encodings and run-time
    assembled paths remain the documented evasions.
- **Decide and document the add-only invariant**
  - status: done — documented, not changed
  - last worked on: 2026-10-25
  - remaining: none — the security model and the guard's docstring say a
    complete parse may clear a raw match for a pure print (`echo rm -rf /`);
    the union is explicitly not add-only.
- **Sweep duplicate stale claims**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `coding-agents.md`, `detectors.md`, `shell/parser.py`
    and `command_intent_guard.py` carry the corrected text.

## T03 — Correct the sandbox timeout and scratch-removal text

**Status:** done (2026-10-25)

- **Qualify the `setsid()` sentence**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — both the guide and the security model note bwrap's
    PID namespace + `--die-with-parent`, the live escape under
    `sandbox-exec`/`soft`, and (after T10) the Windows `taskkill /T` tree walk
    with its reparenting caveat.
- **Fix the scratch-removal contradiction**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `python-api.md` now says the scratch is removed on every
    exit path *except* when an escaped descendant still holds it at timeout.

## T04 — Reconcile the false-positive measurement story

**Status:** done (2026-10-25, `9461a8d` + this pass)

- **Update the gap bullet**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — the bullet carries measured numbers and the real
    residual (other policies unmeasured, corpus is one developer's traffic).
- **Fix README/ROADMAP self-contradiction**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — README no longer lists the corpus/number as future
    work, ROADMAP R5 records the shipped default-pack measurement, and the
    conformance count (774 cases, seven categories) matches the files.

## T05 — Update the approvals gap to include the review queue

**Status:** done (2026-10-25, `db633bb`)

- **Rewrite the bullet**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — the in-process approver limit stays, and both the
    security model and `approvals.md` now point at the durable review queue
    and the opt-in console as the out-of-process route.

## T06 — Close shell evasion: encoded payloads and staged downloads

**Status:** done (2026-10-25, `192b6a8`) — both evasions closed, not accepted

- **Decode base64 payloads before intent analysis**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — the intent path decodes a base64 payload piped into a
    shell (bounded size), so `echo cm0gLXJmIC8= | base64 -d | sh` carries
    `fs.delete.recursive`. Other encodings (gzip, rotation, encryption) stay
    documented evasions.
- **Track a fetched script that is executed later**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `_fetch_write_exec` follows a fetcher's `-o` path to a
    later invocation that runs the same literal path, within one command
    string. The parser stays stateless per string; cross-*event* provenance is
    now a separate boundary mechanism (R9, `interlock.flow`), not parser
    state.

## T07 — Publish a false-positive number and gate it

**Status:** done (2026-10-25)

- **Commit a benign agent-traffic corpus**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `benchmarks/fp/benign.jsonl`, 70 events across file,
    git, build/test, search, fetch and MCP tools, call and result phases.
- **Publish per-detector FP + latency**
  - status: done (2026-10-25, T17) — per rule and per detector
  - last worked on: 2026-10-25
  - remaining: none for the default pack — `scripts/fp_baseline.py --per-rule`
    measures all 20 rules alone (0 FP each) and `--per-detector` measures all
    six mounted detectors with their rules together (0 FP each);
    `measure_each_rule` / `measure_each_detector` are exported from
    `interlock.mesh.harness`. Tables are in `benchmarks/fp/README.md`.
    *Other* policies still have no published number; the harness measures them
    on demand.
- **Add a CI regression gate**
  - status: done (2026-10-25, widened in T17)
  - last worked on: 2026-10-25
  - remaining: none — `tests/test_fp_baseline.py` asserts zero false positives
    on the main and held-out corpora, zero induced blocks, and no stress case
    over 150 ms, so the existing pytest CI job enforces all four. The latency
    bounds are widened there to keep a slow runner from flaking.
- **Held-out split and the DoS half**
  - status: done (2026-10-25, T17)
  - last worked on: 2026-10-25
  - remaining: none — `benign-heldout.jsonl` (20 events, written after the
    rules) checks generalisation; `poisons.jsonl` + `induced_blocking()` and
    `stress_events()` + `stress()` cover induced blocking and pathological
    cost. The stress run found a real 100x amplification, fixed in T17.

## T08 — Bundle a public-key receipt signer

**Status:** done (2026-10-25, `e366c5c`)

- **Wire Ed25519 into the receipt sink**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `interlock/receipt_ed25519.py` ships
    `ed25519_signer`, `ed25519_verifier`, `generate_seed` and `public_key`;
    `FileSink("...", signer=ed25519_signer, key=seed)` signs and
    `verify_file(..., verifier=...)` checks with the public key alone. HMAC
    stays the default.
- **Document the key distribution model**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `docs/guides/audit-log.md` shows the operator holding
    the seed and the auditor holding only the public key, plus what a wrong
    key proves.

## T09 — Give the review queue integrity and an owner

**Status:** done (2026-10-25) — option (a) implemented

- **Decide the threat model first**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — chose (a), an HMAC key the database does not contain.
    Directory is `0o700`, file `0o600`, and the coding-agent policy blocks
    writes to `~/.interlock` (`interlock/policy/packs.py:103-115`); that is
    access narrowing, and the signature now adds integrity on top.
- **Sign every row**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `interlock/reviews.py` signs id, binding, status, action,
    phase, principal, requester, policy, reason, digest, preview, timestamps,
    decision fields and the approver list, with a 32-byte key at
    `reviews.key` (beside the DB, mode 0600, never inside it). Every mutation
    reseals; `claim`, `approve`, `reject`, `revoke` and `_review` verify first.
    `key=` / `key_path=` allow separating the key from shared storage. A
    pre-signing database is sealed on first open by the reviewer's process.
  - tests: `tests/test_review_integrity.py` — forged approval, redirected
    binding, swapped preview, forged approver, replaced key, explicit key.
- **Document the residual**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `docs/guides/reviews.md` "Integrity" + "Trust", the
    security-model bullet, the API table and `CHANGELOG.md`. Residual: whoever
    can read both the database and the key can still forge; whoever can delete
    either can deny service.

## T10 — Contain Windows sandbox descendants

**Status:** done (2026-10-25)

- **Kill the tree, not the child**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `_kill_process_group` uses `taskkill /T /F /PID` (a
    bounded, silent, failure-tolerant call) and then kills the direct child as
    a backstop. A process that reparents itself before the walk can still
    escape; that is stated in the security-model bullet.
  - tests: `tests/test_brace_windows_kill.py` runs the real win32 branch on any
    host with the platform and `subprocess.run` swapped: tree kill first,
    missing taskkill, hung taskkill, vanished process.

## T11 — Report `rlimit` from the OS backends

**Status:** done (2026-10-25)

- **Join the guarantee matrix**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — both backends append `rlimit` to `enforced` when
    `cpu_seconds` or `memory_mb` is set (`backends/bubblewrap.py`,
    `backends/sandbox_exec.py`), the token matrix's escape and control tests
    now run on all three backends, `TOKENS_BY_BACKEND` and the guarantee table
    in `interlock/brace/__init__.py` carry the rows, and
    `tests/test_brace_limits.py` asserts the token appears only with a
    ceiling. Verified on macOS: `sandbox-exec` dies with SIGXCPU; bubblewrap
    rows run on Linux CI.

## T12 — Python import-time hooks (ROADMAP R11)

**Status:** done (2026-10-25) — MCP attached at import; model SDKs confirmed to
have no class seam; compatibility contract + import monitor shipped

- **Ship the opt-in import hook**
  - status: done
  - last worked on: 2026-10-25
  - `interlock/attach.py`: `attach()` patches
    `mcp.client.session.ClientSession.call_tool` at the class, immediately if
    the SDK is already imported and through a `sys.meta_path` finder + wrapping
    loader if it is imported later. The class wrapper hands the *bound
    original* to `guard_mcp_session(original=...)` on the first call per
    session, which is what breaks the class-patch recursion; the
    `__interlock_guarded__` marker is the double-wrap guard on both paths.
  - `detach()` restores every patched method and removes the finder.
  - `uncovered()` lists every known surface with `attachable`, `available` and
    the explicit call that guards it — the Python counterpart of the Node
    client's report.
  - `tests/test_attach.py` (13 tests): already-imported and import-later
    paths, block before effect, allowed call reaches the server once, second
    attach wraps nothing twice, detach restores, sync sessions, a failing
    install does not break the import, and the same verdict from
    `guard_mcp_session(session)` and from the attached class.
  - The model SDKs stay adapter-guarded by design (they never execute tools —
    the application's dispatcher does); the import **monitor** and
    compatibility contract follow.
- **Compatibility contract**
  - status: done (2026-10-25)
  - last worked on: 2026-10-25
  - `Seam`/`MCP_SEAM`, `check_seam()`, `inspect_surfaces()` and
    `interlock attach --check` (exit 1 on an installed, attachable,
    incompatible seam). `attach()` raises `_Incompatible` internally and
    reports `incompatible seam: ...` in `missed`; nothing is patched.
  - Tests: `tests/test_attach_monitor.py` (contract accepts async, sync and
    `*args` shapes; names each break; refuses before patching); a real-SDK
    check runs under `importorskip("mcp.client.session")`.
- **Import monitor**
  - status: done (2026-10-25)
  - last worked on: 2026-10-25
  - `attach_monitor()` / `from interlock.attach import monitor` records
    provenance at attach (class object, wrapper, file SHA-256, distribution
    version) and reports `missing`, `replaced`, `unpatched`, `modified`,
    `removed`, `version`. `attach()` repairs replaced/unpatched classes and
    adds the findings to `AttachReport.drifts` (`repaired` true/false).
  - A second default `attach()` now reuses the existing attachment rather than
    replacing it, so provenance survives; a changed file is never re-hashed
    away by a second attach.
  - Tests: restore, replace, file modify, module removal, version change,
    monitor-then-guarded-call, inspection without attaching, CLI JSON.

## T13 — Node.js: report ESM named imports as uncovered

**Status:** done (2026-10-25, `9d163a7`)

- **Add the missing entry**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `installInterceptors().uncovered` carries
    `esm.named-import`, and `js/test/fs.test.ts` keeps the bypass executable
    as a fact.
- **Mitigate the hole with a loader**
  - status: done (2026-10-25)
  - last worked on: 2026-10-25
  - remaining: none — `registerEsmInterceptors` installs the patches and
    registers `js/src/esm-loader.ts`, whose synthetic builtin modules delegate
    guarded named exports to the patched functions at call time; the preload
    `node --import interlock-guard/esm-hook` does this from `INTERLOCK_SOCKET`.
    `esm.named-import` moves to `covered` in the returned report.
    `js/test/esm.test.ts` spawns real children against the sidecar for named,
    namespace and callback imports. Registration must precede the first link of
    the builtin (Node has no unregister); the synchronous and handle-returning
    shapes remain unclosable.

## T14 — Register the accepted limitations

**Status:** done (2026-10-25, `db633bb`)

- **Mark four gaps as accepted, not queued**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — six bullets in `docs/security-model.md` now carry an
    explicit **Accepted:** marker: SQL/masking semantics, hook
    cooperativeness, per-host egress without root, macOS read confinement and
    memory visibility, a platform that cannot express a limit, and Node's
    unguardable shapes.

## T15 — Memoize intent analysis per event (found during T07)

**Status:** done (2026-10-25)

- **Stop re-parsing one Bash command once per intent rule**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `interlock/shell/intents.py` exposes a
    `memoized_analysis()` context and `memoized_analyze(command, cwd)`;
    `PolicyEngine.evaluate` opens one memo around the rule loop and
    `DeclarativeEngine.evaluate` extends it over the shadow pass (a nested
    block reuses the outer table). Keyed on `(command, cwd)`, per thread/task,
    never survives the event. `tests/test_intent_memo.py` (8 tests) pins one
    parse for four intent rules, no cross-event or cross-directory reuse, a
    rewritten command analyzed under its own text, and the same answer as
    `analyze`.
  - measured: `Bash` p50 1.26 ms → 0.67 ms, corpus p50 1.0 → 0.6 ms, p95
    2.0 → 1.0 ms (`benchmarks/fp/README.md`). Not an order of magnitude: the
    remaining cost is the rules matching their selectors, not the parse.

## T16 — Overhead benchmark suite (ROADMAP R12)

**Status:** done (2026-10-25)

- **Measure the added cost, not a standalone throughput number**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `scripts/bench_overhead.py` runs the same benign corpus
    through an empty `PolicyEngine` (floor) and `builtin:coding-agent`
    (guarded), with one untimed warm-up then `--repeats` timed passes.
    Reports both percentiles, the difference, and a per-action breakdown;
    `--json` for tooling.
- **Write the methodology down**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `benchmarks/overhead/README.md` states input, procedure,
    sample count, timing call, percentile rule, hardware, and exclusions.
- **Add a regression gate**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — exit non-zero when guarded p95 or added p95 exceeds
    5 ms, or guarded/floor p50 exceeds 500x. The ratio is suppressed when the
    floor is under 5 µs, because that is timer resolution. Measured: guarded
    p50 243 µs / p95 392 µs / p99 445 µs vs a 2 µs floor; `Bash` 285 µs.
- **Fix what it found**
  - status: done (2026-10-25)
  - last worked on: 2026-10-25
  - remaining: none — the corpus median was 0.61 ms; sharing one parse per
    event (parser memo) and one cwd, plus cheap prefilters before path
    resolution, brought it to 0.24 ms. Tests: `tests/test_bench_overhead.py`
    (ordering, gate reasons, empty measurement, CLI JSON on the committed
    corpus).

## T17 — Complete R5: per-rule/per-detector FP, induced blocking, stress

**Status:** done (2026-10-25)

- **Per-rule and per-detector numbers**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `measure_each_rule` (all 20 rules alone) and
    `measure_each_detector` (all six mounted detectors with all their rules)
    in `interlock/mesh/harness.py`; `--per-rule` / `--per-detector` on
    `scripts/fp_baseline.py`; tables published in `benchmarks/fp/README.md`.
    Tests: `tests/test_harness_per_rule.py`.
- **Held-out benign corpus**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `benchmarks/fp/benign-heldout.jsonl` (20 events, written
    after the rules) measured at 0 false positives and asserted in
    `tests/test_fp_baseline.py` so a tuned-only result cannot pass.
- **Induced blocking (bait in non-execution fields)**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `induced_blocking()` appends each of 10 poison strings
    to `description`, `content`, `new_string`, `prompt`, `query`, `new_source`
    on every baseline-ALLOW call-phase event. Default pack: 0 of 560 changed.
    Result-phase events are excluded because result detectors read content by
    design. Tests: `tests/test_harness_robustness.py`.
- **Pathological-cost stress and the DoS half**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — six legal-but-hostile calls timed with a 50 ms p95 gate;
    found a real amplification (100 KB `Bash` 0.66 s) caused by ~7 parses and
    ~12k `os.getcwd()` calls per event. Fixes: parser memo (`memoized_parse`),
    event-scoped cwd, cached home components, a cheap `_could_name_own`
    prefilter, `lexists` skip for nonexistent bare names, `MAX_INPUT` 64 KB →
    16 KB, new `MAX_ARGS` 4,096. Worst case now 27.9 ms. A reverted candidate
    is recorded: skipping all bare relative words would miss symlinks into
    `~/.ssh`, so the skip is `lexists`-based only.
- **Keep the parser bound fail-closed**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — past either cap `.partial` is set and
    `unreadable-commands` escalates; `tests/test_regex_linearity.py` now
    permits ESCALATE (never BLOCK) for a destructive command past the cap, and
    `tests/test_parse_memo.py` pins the caps and memo lifetime.

## T18 — R9 flow-typed policy (source → sink)

**Status:** done (2026-10-25)

- **Provenance on the event**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `SensorEvent.origins` maps argument paths to
    `tool:<canonical action>` / `principal:<id>` labels. `FlowTracker` records
    the text a guarded tool returned, bounded to 512 fragments, 16 characters
    minimum, 64 KiB per call, and scoped by span so two runs cannot taint each
    other. `record_origin()` covers an integration that knows a source.
- **Declarative source→sink condition**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `{"flow": {"source": ..., "sink": ...}}` in
    `interlock/policy/declarative.py`; both selectors are validated at load
    (a malformed one is quarantined), globs and nested paths are supported,
    and `attributed_to` names the tainted argument. `PolicyEngine.evaluate` is
    unchanged: a flow rule is a rule.
- **First consumer detector**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `network_egress_guard(block_origins=...)` denies an
    egress payload carrying matching provenance even to an allowlisted host.
- **Equivalence proof**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `tests/test_flow.py` checks the general rule and an
    equivalent hand-written predicate agree on every case, plus the tracker
    bounds, span isolation, the end-to-end result→call round trip and the
    canary shape. `docs/security-model.md` records the honest limit:
    boundary-level matching, not language-level taint.

## T19 — Close the review-queue rollback replay

**Status:** done (2026-10-25)

- **Count every write outside the database**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `interlock/reviews.py` keeps `settings.seq`, bumped inside
    the same transaction as each state change (`lookup_or_file` when it files or
    expires, `approve`, `reject`/`revoke` via `_settle`, `claim`, and `get`/
    `list` only when an expiry changed a row). After the commit it writes
    `<key>.head` — JSON `{version, seq, mac}`, HMAC under the row key — atomically
    (temp file, fsync, `os.replace`, 0600).
- **Refuse backwards, heal forwards**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `_restore_head` refuses a database whose counter is below
    the mark ("behind its high-water mark") and rewrites the mark when it is
    behind the database, which is what a crash between commit and write leaves.
    A malformed or foreign-signed mark is refused at construction.
- **Surface it**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `head_path=` on `ReviewQueue`, `--key`/`--head` on
    `interlock reviews`; `docs/guides/reviews.md`, the security-model bullet and
    `CHANGELOG.md`.
  - tests: `tests/test_review_rollback.py` — database rollback refused, database
    plus key restored from the same backup refused when the mark is elsewhere,
    crash gap heals, foreign/malformed mark refused, reads do not advance the
    mark, each state change advances it once, expiry counts, relocated mark is
    0600, CLI flags.

## T20 — Anchor the receipt tail outside the log

**Status:** done (2026-10-25)

- **A command that records the head**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `interlock/cli/anchor.py` (registered as `interlock
    anchor`) verifies the chain, then writes `<log>.anchor` (or `--out FILE`):
    version, log path, receipt count, head, timestamp and an HMAC under the
    receipt key, atomically with mode 0600.
- **Refuse to move backwards**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — a re-anchor requires the log to still contain the
    anchored receipt at the same index, and to be no shorter than the anchored
    count; otherwise it exits 2. `--check` makes the same comparison without
    writing and accepts a grown log, reporting receipts since the anchor.
- **Surface it**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — the "Catch receipts cut from the end" section of
    `docs/guides/audit-log.md`, the security-model bullet, the README table and
    `CHANGELOG.md`.
  - tests: `tests/test_cli_anchor.py` — record then check, growth accepted,
    truncation refused (check and re-record), same-length rewrite refused,
    edited/unreadable anchor refused, wrong log refused, check without an
    anchor fails, a broken chain is never anchored, JSON output.

## T21 — R29: let the clients pin the scope document

**Status:** done (2026-10-25)

The wire could carry a signed scope document, but no client set the field, so a
remote client could not ask the daemon for a scoped decision it could name.

- **Python `RemoteEngine` presents the document**
  - status: done — `scope=` (the daemon's published `--scope-document` file) and
    `scope_key=`; verified at construction by `wire.read_scope_envelope`, sent on
    every request, `request_frame(..., scope=...)`.
- **Node.js `RemoteEngine` presents the document**
  - status: done — `scopeFile`/`scopeKey`/`scopeKeyFile`; `wire.readScopeEnvelope`
    mirrors Python, and `node:fs` is required lazily so the ESM-hook preload
    cannot cache the unpatched builtin.
- **Prove the overlay is actually sent**
  - status: done — a client pinning a different, well-signed envelope is refused
    with `scope_mismatch` (a client that sent nothing would have been decided).
- **Live smoke with the real client**
  - status: done — `tests/test_sidecar_scopes.py` starts a daemon with
    `--scope-document` + `--key-file` and compares `RemoteEngine` verdicts to an
    in-process oracle; `js/test/scope.test.ts` does the Node half.
- **Docs and roadmap**
  - status: done — sidecar reference "Pinning the scope document from a client",
    python-api options, js/README, scopes guide, ROADMAP R29 → `shipped`,
    CHANGELOG.
