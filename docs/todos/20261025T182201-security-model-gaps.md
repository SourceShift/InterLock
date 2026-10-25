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
| 4 | Review queue trusts its file | **closed for forgery** | rows HMAC-signed with a key beside the DB (T09, `1547afc`); rollback replay until `approval_ttl` remains |
| 5 | Shell parsing best-effort | **closed for the two named evasions** | ANSI-C quoting, a base64 payload piped to a shell, and a staged fetched script are decoded/followed (T06, `192b6a8`); other encodings remain; "not add-only" is now documented |
| 6 | SQL analysis + masking best-effort | **open (accepted)** | `interlock/sql/lexer.py`, no AST dep; `interlock/masking.py:35`; T14 marks it accepted |
| 7 | Coding-agent hooks cooperative | **open (accepted)** | `interlock/adapters/base.py:25-27` capability matrix; inherent to an in-agent adapter (T14) |
| 8 | No measured false-positive rate | **partial** | closed for the default pack by T07 (committed corpus, 0/70, CI gate); other policies still unmeasured |
| 9 | Per-host egress needs root | **open (accepted)** | no backend exists between bwrap all-or-none and root nftables (T14) |
| 10 | macOS can't confine reads / visibility / memory | **open (accepted)** | `sandbox_exec.py:109,122`; `limits.py:59-67`; Seatbelt cannot express these (T14) |
| 11 | `setsid()` descendant survives timeout kill | **partial** | bwrap `--unshare-pid` + `--die-with-parent`; Windows `taskkill /T /F` walks the tree (T10); a reparented process can still escape |
| 12 | Write confinement differs by backend | **open (accurate)** | `sandbox.py:155-191`; the scratch exception is now documented in `python-api.md` (T03) |
| 13 | CPU/memory reported only by `soft` | **closed** | every backend claims `rlimit` when a ceiling is set (T11); the token matrix carries an escape row for each |
| 14 | Truncated tail needs an outside record | **open** | `head=` exists (`sink.py:89-108`); no automatic anchor |
| 15 | Receipts prove integrity, not authorship | **closed** | `interlock/receipt_ed25519.py` ships signer + verifier, and the audit guide documents key distribution (T08, `e366c5c`) |
| 16 | Node.js unguardable shapes | **open (accepted, now visible)** | the shapes and `esm.named-import` are reported by `installInterceptors().uncovered` (T13, `9d163a7`) |
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
    string. Cross-*event* taint is still out of scope: the parser stays
    stateless per string, which is now stated in the security model.

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
have no class seam

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
  - Not shipped, and now recorded in `ROADMAP.md` R11: the model SDKs are
    adapter-guarded by design (they never execute tools — the application's
    dispatcher does), and the import **monitor** / compatibility contract are
    still open.

## T13 — Node.js: report ESM named imports as uncovered

**Status:** done (2026-10-25, `9d163a7`)

- **Add the missing entry**
  - status: done
  - last worked on: 2026-10-25
  - remaining: none — `installInterceptors().uncovered` carries
    `esm.named-import`, and `js/test/fs.test.ts` keeps the bypass executable
    as a fact. The hole itself is unclosable from JavaScript; the sidecar or
    an OS sandbox is the boundary, and the entry makes it visible.

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
